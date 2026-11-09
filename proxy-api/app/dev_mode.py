"""Development-server credential entry points for the gateway's own console.

A self-hosted gateway operator (an authenticated console session) can attach an
OrcaRouter credential in two ways, and both produce the same thing: an
``sk-orca-`` API key stored under ``providers.orcarouter.api_key`` in the
gateway config file (the same slot ``${ORCA_API_KEY}`` resolves to).

1. **API key** -- paste an existing key.
2. **Connect with OrcaRouter** -- OAuth 2.0 + PKCE (loopback redirect, Flow A),
   which mints a durable key belonging to the operator's OrcaRouter account.

The credential seam lives in :mod:`app.credentials`; this module only owns HTTP
plumbing, the login-state lifecycle (attempt generation, timeout, cancel) and
config-file persistence. The stored key is masked in every response and never
logged. The endpoints are opt-in via ``AISG_DEV_MODE=1``.
"""

from __future__ import annotations

import asyncio
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import structlog
import yaml
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from .auth import authenticate
from .credentials import CredentialError, PKCECredentialSource
from .log_utils import mask_key
from .providers import ProviderSpec, get_provider
from .tokens import CredentialStore

log = structlog.get_logger()
router = APIRouter(prefix="/v1/dev/orcarouter", tags=["dev"])

# OrcaRouter issued keys are durable API keys, not refreshable tokens: a key
# rejected with 401 must be re-acquired, never silently retried or refreshed.
_TOKEN_REJECTED_STATUS = 401

_SUCCESS_PAGE = (
    "<!doctype html><meta charset=utf-8><title>Connected</title>"
    "<p>OrcaRouter connected. You can close this tab and return to the terminal.</p>"
)
_ERROR_PAGE = (
    "<!doctype html><meta charset=utf-8><title>Not connected</title>"
    "<p>{message} You can close this tab.</p>"
)


def _is_dev_mode() -> bool:
    """Dev endpoints are opt-in via AISG_DEV_MODE=1."""
    return os.environ.get("AISG_DEV_MODE", "").lower() in {"1", "true", "yes"}


def _require_dev_auth(request: Request) -> dict:
    """Require a valid gateway API key for every dev-endpoint call."""
    raw_key = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    record = authenticate(raw_key)
    if record is None:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")
    return record


# ── Terminal key rejection ──────────────────────────────────────────────────


@dataclass
class _KeyState:
    """Generation-tracked view of the stored OrcaRouter key.

    ``generation`` increases on every successful credential replacement, so an
    in-flight request issued with an older generation can be told apart from
    the credential now stored.
    """

    key: str
    generation: int = 1
    needs_reauth: bool = False


class KeyStateTracker:
    """Marks *exactly* the key generation rejected by upstream as ``needs_reauth``.

    A request that started under generation N cannot mark generation N+1 dirty:
    a late 401 from a request issued with the old key must not poison a key the
    operator has just re-connected.
    """

    def __init__(self) -> None:
        self._states: dict[str, _KeyState] = {}
        self._last_generation = 0

    def current(self, key: str) -> _KeyState:
        state = self._states.get(key)
        if state is None:
            state = _KeyState(key=key)
            self._states[key] = state
        return state

    def snapshot(self, key: str) -> tuple[str, int]:
        """Generation token to capture when a request is issued."""
        return key, self.current(key).generation

    def mark_rejected(self, snapshot: tuple[str, int]) -> bool:
        """Terminal 401 handling: flag the rejected generation only."""
        key, generation = snapshot
        state = self.current(key)
        if state.generation != generation:
            log.info("orcarouter_stale_401_ignored", provider="orcarouter", key_id=mask_key(key))
            return False
        state.needs_reauth = True
        log.warning("orcarouter_key_needs_reauth", provider="orcarouter", key_id=mask_key(key))
        return True

    def replace(self, new_key: str) -> None:
        """A new key was stored: bump the global generation, clear the flag."""
        self._last_generation += 1
        state = self.current(new_key)
        state.generation = self._last_generation
        state.needs_reauth = False
        log.info("orcarouter_key_replaced", provider="orcarouter", key_id=mask_key(new_key), generation=state.generation)


key_state = KeyStateTracker()


# ── Login state (attempt generation, cancel, timeout) ───────────────────────


@dataclass
class LoginAttempt:
    """One PKCE login: its own credential adapter and verifier store."""

    attempt_id: str
    source: PKCECredentialSource
    authorize_url: str = ""
    prepared_callback_url: str = ""
    expires_in_seconds: int = 0
    task: asyncio.Task | None = field(default=None)
    cancelled: bool = False


class LoginState:
    """Single-flight PKCE login with monotonically increasing attempt ids."""

    def __init__(self) -> None:
        self._current: LoginAttempt | None = None
        self._counter = 0
        self.last_error: str | None = None

    def _next_id(self) -> str:
        self._counter += 1
        return f"login_{self._counter}_{secrets.token_hex(4)}"

    def begin(self, callback_url: str) -> LoginAttempt:
        if self._current is not None:
            raise CredentialError("An OrcaRouter login is already in progress. Cancel it first.")
        self.last_error = None
        source = PKCECredentialSource()
        prepared = source.prepare(callback_url)
        attempt = LoginAttempt(
            attempt_id=self._next_id(),
            source=source,
            authorize_url=prepared.authorize_url,
            prepared_callback_url=prepared.callback_url,
            expires_in_seconds=prepared.expires_in_seconds,
        )
        self._current = attempt
        return attempt

    def current_attempt(self) -> LoginAttempt | None:
        return self._current

    def is_current(self, attempt: LoginAttempt) -> bool:
        return self._current is attempt and not attempt.cancelled

    def state_matches(self, attempt: LoginAttempt | None, state: str) -> bool:
        """Constant-time comparison of the callback state for this attempt."""
        import hmac

        if attempt is None:
            return False
        expected = attempt.source._prepared.state if attempt.source._prepared else ""
        return bool(expected) and hmac.compare_digest(state.encode(), expected.encode())

    def finish(self, attempt: LoginAttempt, error: str | None = None) -> None:
        if self._current is attempt:
            self._current = None
            self.last_error = error

    def cancel(self) -> bool:
        """Release the login lock; a late success is then ignored."""
        attempt = self._current
        if attempt is None:
            return False
        attempt.cancelled = True
        self._current = None
        if attempt.task is not None and not attempt.task.done():
            attempt.task.cancel()
        log.info("orcarouter_login_cancelled")
        return True

    @property
    def busy(self) -> bool:
        return self._current is not None


login_state = LoginState()


# ── Config-file persistence (reuses the existing gateway.yaml secret slot) ──


def _config_file_path() -> Path:
    from .config import get_settings

    config_path = get_settings().config_path
    if not Path(config_path).exists():
        env_path = os.environ.get("AISG_CONFIG_PATH")
        if env_path:
            return Path(env_path)
    return Path(config_path)


def persist_orcarouter_key(api_key: str) -> None:
    """Write ``providers.orcarouter.api_key`` into the gateway config file.

    Only the OrcaRouter slot is rewritten; every other line is preserved. The
    key is written as a literal so ``${ORCA_API_KEY}`` env substitution cannot
    later override the operator's choice.
    """
    path = _config_file_path()
    text = path.read_text() if path.exists() else "providers:\n"
    document = yaml.safe_load(text) or {}
    providers = document.setdefault("providers", {})
    entry = providers.get("orcarouter")
    if not isinstance(entry, dict):
        entry = {}
        providers["orcarouter"] = entry
    entry["api_key"] = api_key

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(yaml.safe_dump(document, sort_keys=False))
    tmp.replace(path)

    # Drop the cached config so the next request re-reads the new key.
    from . import config as _config

    _config._gateway_config = None


def stored_orcarouter_key() -> str | None:
    """Return the configured OrcaRouter key, if any (never logged)."""
    from .config import get_provider_keys

    key = get_provider_keys().get("orcarouter")
    return key or None


def status_payload() -> dict[str, Any]:
    key = stored_orcarouter_key()
    payload: dict[str, Any] = {
        "provider": "orcarouter",
        "display_name": "OrcaRouter Cyber Inference",
        "auth_methods": ["api_key", "pkce"],
    "cli_commands": ["api-key", "login"],
    }
    if key:
        state = key_state.current(key)
        payload.update(
            configured=True,
            secret_masked=mask_key(key),
            generation=state.generation,
            needs_reauth=state.needs_reauth,
        )
    else:
        payload["configured"] = False
    attempt = login_state.current_attempt()
    payload["login"] = {
        "busy": login_state.busy,
        "attempt_id": attempt.attempt_id if attempt else None,
        "last_error": login_state.last_error,
    }
    return payload


def _require_orcarouter_provider() -> ProviderSpec:
    spec = get_provider("orcarouter")
    if spec is None:
        raise HTTPException(status_code=404, detail="OrcaRouter provider is not registered")
    return spec


def _persist(api_key: str) -> None:
    """Write OrcaRouter's own config slot without forcing other secrets to disk."""
    persist_orcarouter_key(api_key)


def _store_and_report(api_key: str) -> dict[str, Any]:
    """Persist a credential issued by either entry point and report it masked."""
    _persist(api_key)
    key_state.replace(api_key)
    log.info("orcarouter_key_stored", provider="orcarouter", key_id=mask_key(api_key), source_origin="gateway")
    return status_payload()


# ── Routes ─────────────────────────────────────────────────────────────────


class ApiKeyRequest(BaseModel):
    api_key: str


class ConnectRequest(BaseModel):
    callback_url: str


class CompleteRequest(BaseModel):
    attempt_id: str
    callback_url: str | None = None
    code: str | None = None


@router.get("/status")
async def status(request: Request):
    _require_dev_auth(request)
    return JSONResponse(status_payload(), headers={"Cache-Control": "no-store"})


@router.put("/credentials/api-key")
async def put_api_key(body: ApiKeyRequest, request: Request):
    """Entry point 1: store a pasted ``sk-orca-`` API key."""
    _require_dev_auth(request)
    _require_orcarouter_provider()
    key = body.api_key.strip()
    if not CredentialStore.classify(key).well_formed:
        raise HTTPException(status_code=400, detail="Expected an OrcaRouter API key starting with 'sk-orca-'")
    return JSONResponse(_store_and_report(key))


@router.post("/connect")
async def connect(body: ConnectRequest, request: Request):
    """Entry point 2, step 1: start PKCE and return the authorize URL."""
    _require_dev_auth(request)
    _require_orcarouter_provider()
    try:
        attempt = login_state.begin(body.callback_url)
    except CredentialError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return JSONResponse(
        {
            "attempt_id": attempt.attempt_id,
            "authorize_url": attempt.authorize_url,
            "callback_url": attempt.prepared_callback_url,
            "expires_in": attempt.expires_in_seconds,
            "code_challenge_method": "S256",
        },
        headers={"Cache-Control": "no-store"},
    )


@router.post("/connect/complete")
async def connect_complete(body: CompleteRequest, request: Request):
    """Entry point 2, step 2: compare state, exchange the code, store the key."""
    _require_dev_auth(request)
    _require_orcarouter_provider()
    attempt = login_state.current_attempt()
    if attempt is None or attempt.attempt_id != body.attempt_id:
        raise HTTPException(status_code=410, detail="This login attempt is no longer active. Start a new one.")
    try:
        credential = await attempt.source.obtain(callback_url=body.callback_url, code=body.code)
    except CredentialError as exc:
        login_state.finish(attempt, error=str(exc))
        log.warning("orcarouter_login_failed", reason=type(exc).__name__)
        raise HTTPException(status_code=400, detail=str(exc))
    if not login_state.is_current(attempt):
        # Cancelled (or superseded) while the exchange was in flight: do not
        # overwrite whatever the operator chose afterwards.
        return JSONResponse({"status": "cancelled", "attempt_id": attempt.attempt_id}, status_code=409)
    login_state.finish(attempt)
    return JSONResponse(_store_and_report(credential.api_key))


@router.post("/connect/cancel")
async def connect_cancel(request: Request):
    _require_dev_auth(request)
    cancelled = login_state.cancel()
    return JSONResponse({"cancelled": cancelled, "login": {"busy": login_state.busy}})


@router.delete("/credentials")
async def delete_credential(request: Request):
    """Clear the stored OrcaRouter key from the gateway config."""
    _require_dev_auth(request)
    _persist("")
    return JSONResponse({"configured": False})


@router.get("/callback")
async def callback(request: Request):
    """Flow A landing page: confirm the state and tell the operator to paste back.

    No exchange happens on GET, so link prefetchers or scanners cannot consume
    the one-time code; the operator echoes the full URL into step 2.
    """
    state = request.query_params.get("state", "")
    attempt = login_state.current_attempt()
    if not login_state.state_matches(attempt, state):
        return HTMLResponse(_ERROR_PAGE.format(message="Login state did not match."), status_code=400)
    if request.query_params.get("error"):
        login_state.cancel()
        return HTMLResponse(_ERROR_PAGE.format(message="Authorization was denied."), status_code=400)
    return HTMLResponse(_SUCCESS_PAGE)
