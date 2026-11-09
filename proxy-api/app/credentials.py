"""Credential seam for the gateway's OrcaRouter provider.

Two adapters implement :class:`CredentialSource` and both produce the same
:class:`OrcaCredential` -- a plain OrcaRouter API key that the inference path
(Bearer against ``https://api.orcarouter.ai/v1``) treats exactly like a pasted
one. Nothing downstream of this module knows how the key was obtained.

* :class:`StaticKeyCredentialSource` -- the operator pastes an ``sk-orca-`` key.
* :class:`PKCECredentialSource` -- OAuth 2.0 + PKCE (loopback redirect, Flow A)
  against the OrcaRouter consent screen; the exchange returns a durable API key.

Protocol facts encoded here (see the OrcaRouter PKCE integration guide):

* auth origin ``https://www.orcarouter.ai``, authorize path ``/auth``,
  exchange path ``/api/v1/auth/keys`` (NOT ``/v1/auth/keys``);
* inference origin ``https://api.orcarouter.ai/v1`` -- never derived from the
  auth origin;
* ``S256`` is always used; verifier + state are fresh per attempt from a CSPRNG
  and the verifier never leaves the process until the exchange;
* ``state`` is compared in constant time before the code is used;
* the response's granted ``scope`` is checked, not the requested one.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import secrets
import time
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Protocol

import httpx

DEFAULT_AUTH_BASE_URL = "https://www.orcarouter.ai"
DEFAULT_API_BASE_URL = "https://api.orcarouter.ai/v1"
AUTHORIZE_PATH = "/auth"
EXCHANGE_PATH = "/api/v1/auth/keys"
APP_NAME = "Occludra AI Security Gateway"
GRANTED_SCOPES = ("api", "connector")
OUT_OF_BAND = "oob"

# Bound how long the operator has to approve in the browser before the
# attempt is abandoned (auth codes themselves live 10 minutes).
AUTHORIZATION_TIMEOUT_SECONDS = 600
_EXCHANGE_TIMEOUT_SECONDS = 30.0
_MAX_RESPONSE_BYTES = 64 * 1024


class CredentialError(Exception):
    """Credential acquisition failed with a user-safe message."""


class PKCEProtocolError(CredentialError):
    """The authorization response or exchange violated the protocol."""


@dataclass(frozen=True)
class OrcaCredential:
    """The single credential shape both adapters produce."""

    api_key: str
    source: str  # "api_key" | "pkce"
    scope: str | None = None


@dataclass(frozen=True)
class PreparedAuthorization:
    """Authorize URL handed to the browser plus its pending PKCE state."""

    authorize_url: str
    callback_url: str
    state: str
    verifier: str
    expires_in_seconds: int = AUTHORIZATION_TIMEOUT_SECONDS


class CodeVerifierStore:
    """Process-local store of pending PKCE verifiers, keyed by state.

    The verifier is never written to disk, URLs, logs or error messages.
    Entries are single-use and expire with the authorization timeout.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._pending: dict[str, tuple[str, float]] = {}
        self._clock = clock

    def put(self, state: str, verifier: str, ttl: float = AUTHORIZATION_TIMEOUT_SECONDS) -> None:
        self._pending[state] = (verifier, self._clock() + ttl)

    def take(self, state: str) -> str | None:
        entry = self._pending.pop(state, None)
        if entry is None:
            return None
        verifier, expires_at = entry
        if self._clock() > expires_at:
            return None
        return verifier

    def discard(self, state: str) -> None:
        self._pending.pop(state, None)

    def __len__(self) -> int:
        return len(self._pending)


def b64url(raw: bytes) -> str:
    """Unpadded base64url as required by RFC 7636."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def code_challenge(verifier: str) -> str:
    """``base64url(sha256(verifier))`` -- the S256 challenge."""
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def new_verifier() -> str:
    return b64url(secrets.token_bytes(32))


def new_state() -> str:
    return b64url(secrets.token_bytes(16))


def resolve_origins(
    auth_base_url: str | None = None,
    api_base_url: str | None = None,
    shared_base_url: str | None = None,
) -> tuple[str, str]:
    """Resolve auth and inference origins from explicit overrides.

    Explicit ``auth``/``api`` values win; otherwise a shared self-hosted base
    supplies *both* origins (inference under ``/v1``). Neither origin is ever
    derived from the other by rewriting a hostname.
    """
    shared = (shared_base_url or "").rstrip("/")
    auth = (auth_base_url or (f"{shared}" if shared else DEFAULT_AUTH_BASE_URL)).rstrip("/")
    api = (api_base_url or (f"{shared}/v1" if shared else DEFAULT_API_BASE_URL)).rstrip("/")
    for origin in {urllib.parse.urlsplit(u).scheme + "://" + urllib.parse.urlsplit(u).netloc for u in (auth, api)}:
        _require_safe_origin(origin)
    return auth, api


def _require_safe_origin(origin: str) -> None:
    parts = urllib.parse.urlsplit(origin)
    if parts.scheme == "https":
        return
    if parts.scheme == "http" and parts.hostname:
        host = parts.hostname
        if host == "localhost" or _is_loopback_ip(host):
            return
        raise CredentialError("HTTP origins are only allowed for loopback (self-hosted dev).")
    raise CredentialError("OrcaRouter origins must be https URLs.")


def _is_loopback_ip(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


def is_valid_callback_url(url: str) -> bool:
    """Mirror the consent server's callback_url rules (fail early, locally)."""
    parts = urllib.parse.urlsplit(url)
    if parts.username or parts.password or parts.fragment:
        return False
    if parts.scheme == "https" and parts.hostname:
        return True
    if parts.scheme == "http" and parts.hostname:
        return parts.hostname == "localhost" or _is_loopback_ip(parts.hostname)
    return False


def build_authorize_url(auth_base_url: str, *, callback_url: str, state: str, challenge: str) -> str:
    query = urllib.parse.urlencode(
        {
            "callback_url": callback_url,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
            "app_name": APP_NAME,
            "scope": "api",
        }
    )
    return f"{auth_base_url.rstrip('/')}{AUTHORIZE_PATH}?{query}"


def _check_scope(granted: object) -> str:
    if not isinstance(granted, str) or granted not in GRANTED_SCOPES:
        raise PKCEProtocolError(
            "OrcaRouter granted a scope this gateway cannot use. Re-authorize and approve API access."
        )
    if granted != "api":
        raise PKCEProtocolError(
            f'OrcaRouter granted "{granted}" instead of "api"; this gateway needs API scope.'
        )
    return granted


def parse_exchange_response(status_code: int, payload: object) -> OrcaCredential:
    """Validate the exchange result; errors never echo response bodies."""
    if status_code in (401, 403):
        raise PKCEProtocolError(
            "The authorization code was rejected (unknown, expired, already used or verifier mismatch)."
        )
    if status_code == 429:
        raise CredentialError("Too many authorization requests for this account. Try again later.")
    if status_code >= 400:
        raise PKCEProtocolError(f"OrcaRouter exchange failed with HTTP {status_code}.")
    if not isinstance(payload, dict):
        raise PKCEProtocolError("OrcaRouter returned an unexpected exchange response.")
    key = payload.get("key")
    if not isinstance(key, str) or not key.startswith("sk-orca-"):
        raise PKCEProtocolError("OrcaRouter did not return an OrcaRouter API key.")
    scope = _check_scope(payload.get("scope"))
    return OrcaCredential(api_key=key, source="pkce", scope=scope)


def parse_callback_url(callback_url: str, expected_state: str) -> str:
    """Compare ``state`` (constant time) then return the one-time ``code``."""
    parts = urllib.parse.urlsplit(callback_url)
    query = urllib.parse.parse_qs(parts.query)
    state = (query.get("state") or [""])[0]
    if not expected_state or not hmac.compare_digest(state.encode(), expected_state.encode()):
        raise PKCEProtocolError("Login state mismatch; the authorization response was ignored.")
    error = (query.get("error") or [""])[0]
    if error:
        if error == "access_denied":
            raise CredentialError("Authorization was denied in the browser.")
        raise PKCEProtocolError(f"OrcaRouter authorization failed: {error}.")
    code = (query.get("code") or [""])[0]
    if not code:
        raise PKCEProtocolError("The authorization response did not contain a code.")
    return code


class CredentialSource(Protocol):
    """How a downstream provider obtains its OrcaRouter key."""

    source_id: str

    async def obtain(self, **kwargs) -> OrcaCredential: ...


class StaticKeyCredentialSource:
    """Adapter 1: an API key pasted by the operator."""

    source_id = "api_key"

    def __init__(self, api_key: str) -> None:
        self._api_key = (api_key or "").strip()

    async def obtain(self, **_: object) -> OrcaCredential:
        if not self._api_key.startswith("sk-orca-"):
            raise CredentialError("Expected an OrcaRouter API key starting with 'sk-orca-'.")
        return OrcaCredential(api_key=self._api_key, source=self.source_id)


class PKCECredentialSource:
    """Adapter 2: OAuth 2.0 + PKCE (Flow A loopback / code paste-back).

    ``prepare()`` builds the authorize URL and holds the verifier; ``obtain()``
    takes the callback URL, verifies ``state``, exchanges the code at
    ``<auth>/api/v1/auth/keys`` and returns the durable API key.
    """

    source_id = "pkce"

    def __init__(
        self,
        *,
        auth_base_url: str | None = None,
        api_base_url: str | None = None,
        shared_base_url: str | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        verifiers: CodeVerifierStore | None = None,
    ) -> None:
        self.auth_base_url, self.api_base_url = resolve_origins(auth_base_url, api_base_url, shared_base_url)
        self._transport = transport
        self.verifiers = verifiers or CodeVerifierStore()
        self._prepared: PreparedAuthorization | None = None

    def prepare(self, callback_url: str) -> PreparedAuthorization:
        # Flow B (out-of-band) uses the literal ``oob``: the consent screen shows
        # the code instead of redirecting anywhere.
        if callback_url != OUT_OF_BAND and not is_valid_callback_url(callback_url):
            raise CredentialError("callback_url must be https, or http on localhost/127.0.0.1/[::1].")
        verifier = new_verifier()
        state = new_state()
        self.verifiers.put(state, verifier)
        prepared = PreparedAuthorization(
            authorize_url=build_authorize_url(
                self.auth_base_url,
                callback_url=callback_url,
                state=state,
                challenge=code_challenge(verifier),
            ),
            callback_url=callback_url,
            state=state,
            verifier=verifier,
        )
        self._prepared = prepared
        return prepared

    async def obtain(self, *, callback_url: str | None = None, code: str | None = None) -> OrcaCredential:
        prepared = self._prepared
        if prepared is None:
            raise PKCEProtocolError("No PKCE authorization has been prepared.")
        if callback_url:
            code = parse_callback_url(callback_url, prepared.state)
        if not code:
            raise PKCEProtocolError("No authorization code to exchange.")
        # The verifier is consumed exactly once: a replayed code finds nothing.
        verifier = self.verifiers.take(prepared.state)
        if verifier is None:
            # A replayed code carries the same state; consume the pending entry
            # anyway so only the first attempt can ever reach the exchange.
            self.verifiers.discard(prepared.state)
        self._prepared = None
        if verifier is None:
            raise PKCEProtocolError("This login expired or was already completed. Start a new login.")
        status_code, payload = await self._exchange(code, verifier)
        return parse_exchange_response(status_code, payload)

    async def _exchange(self, code: str, verifier: str) -> tuple[int, object]:
        url = f"{self.auth_base_url}{EXCHANGE_PATH}"
        body = {"code": code, "code_verifier": verifier, "code_challenge_method": "S256"}
        try:
            async with httpx.AsyncClient(
                transport=self._transport,
                timeout=_EXCHANGE_TIMEOUT_SECONDS,
                follow_redirects=False,
            ) as client:
                response = await client.post(url, json=body)
        except httpx.TimeoutException as exc:
            raise CredentialError("OrcaRouter did not answer in time. Start a new login.") from exc
        except httpx.HTTPError as exc:
            raise CredentialError("Could not reach OrcaRouter to exchange the code.") from exc
        raw = response.content[:_MAX_RESPONSE_BYTES]
        try:
            payload = response.json() if raw else None
        except ValueError:
            payload = None
        return response.status_code, payload
