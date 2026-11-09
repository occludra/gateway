"""Tests for the OrcaRouter credential seam: API-key and PKCE adapters.

Every test uses fake keys/codes and a local fake auth server; no real
credential is ever minted.
"""

from __future__ import annotations

import asyncio
import hashlib
import json

import httpx
import pytest

from app.credentials import (
    AUTHORIZE_PATH,
    EXCHANGE_PATH,
    CredentialError,
    PKCECredentialSource,
    PKCEProtocolError,
    StaticKeyCredentialSource,
    b64url,
    build_authorize_url,
    code_challenge,
    is_valid_callback_url,
    new_verifier,
    parse_callback_url,
    parse_exchange_response,
    resolve_origins,
)
from app.tokens import CredentialStore

FAKE_KEY = "sk-orca-fake00000000000000000000000000"


class FakeAuthServer:
    """Local stand-in for the OrcaRouter auth origin (never www.orcarouter.ai)."""

    def __init__(self, status: int = 200, payload: object | None = None) -> None:
        self.status = status
        self.payload = payload if payload is not None else {"key": FAKE_KEY, "user_id": "1", "scope": "api"}
        self.requests: list[httpx.Request] = []
        server = self

        class _Transport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                server.requests.append(request)
                body = server.payload if isinstance(server.payload, bytes) else json.dumps(server.payload).encode()
                return httpx.Response(server.status, content=body, request=request)

        self.transport = _Transport()

    def source(self, **kwargs) -> PKCECredentialSource:
        return PKCECredentialSource(transport=self.transport, **kwargs)


def _callback(source: PKCECredentialSource, code: str = "fake-code-123") -> str:
    from urllib.parse import urlencode

    prepared = source._prepared
    assert prepared is not None
    return f"{prepared.callback_url}?{urlencode({'code': code, 'state': prepared.state})}"


def _run(coro):
    return asyncio.run(coro)


class TestOrigins:
    def test_defaults_are_separate_public_origins(self):
        auth, api = resolve_origins()
        assert auth == "https://www.orcarouter.ai"
        assert api == "https://api.orcarouter.ai/v1"

    def test_explicit_overrides_win_over_shared_base(self):
        auth, api = resolve_origins("https://auth.example.test", "https://relay.example.test/v1", "http://127.0.0.1:1")
        assert (auth, api) == ("https://auth.example.test", "https://relay.example.test/v1")

    def test_shared_self_hosted_base_supplies_both(self):
        auth, api = resolve_origins(shared_base_url="https://orca.internal")
        assert auth == "https://orca.internal" and api == "https://orca.internal/v1"

    def test_http_only_for_loopback(self):
        assert resolve_origins("http://localhost:8080", "http://127.0.0.1:9/v1")
        with pytest.raises(CredentialError):
            resolve_origins("http://orca.example.test")

    def test_exchange_path_is_not_v1_auth_keys(self):
        assert EXCHANGE_PATH == "/api/v1/auth/keys"
        assert AUTHORIZE_PATH == "/auth"


class TestPKCEPrimitives:
    def test_challenge_is_unpadded_base64url_sha256(self):
        verifier = new_verifier()
        expected = hashlib.sha256(verifier.encode()).digest()
        challenge = code_challenge(verifier)
        assert challenge == b64url(expected)
        assert "=" not in challenge and "+" not in challenge and "/" not in challenge

    def test_verifier_is_fresh_per_attempt(self):
        assert new_verifier() != new_verifier()

    def test_authorize_url_uses_auth_origin_and_s256(self):
        url = build_authorize_url(
            "https://www.orcarouter.ai", callback_url="http://127.0.0.1:5555/cb", state="s", challenge="c"
        )
        assert url.startswith("https://www.orcarouter.ai/auth?")
        assert "code_challenge_method=S256" in url
        assert "api.orcarouter.ai" not in url

    def test_callback_rules(self):
        assert is_valid_callback_url("http://127.0.0.1:5555/cb")
        assert is_valid_callback_url("http://localhost:1/cb")
        assert is_valid_callback_url("https://gateway.example.test/cb")
        assert not is_valid_callback_url("http://gateway.example.test/cb")
        assert not is_valid_callback_url("http://user:pw@127.0.0.1/cb")
        assert not is_valid_callback_url("http://127.0.0.1/cb#frag")


class TestPkceAdapter:
    def test_full_flow_persists_a_durable_key(self):
        server = FakeAuthServer()
        source = server.source()
        prepared = source.prepare("http://127.0.0.1:5555/cb")
        credential = _run(source.obtain(callback_url=_callback(source)))
        assert credential.api_key == FAKE_KEY
        assert credential.source == "pkce" and credential.scope == "api"

        request = server.requests[0]
        assert str(request.url) == "https://www.orcarouter.ai/api/v1/auth/keys"
        body = json.loads(request.content)
        assert body["code"] == "fake-code-123"
        assert body["code_challenge_method"] == "S256"
        assert code_challenge(body["code_verifier"]) == prepared.authorize_url.split("code_challenge=")[1].split("&")[0]

    def test_verifier_never_appears_in_authorize_url(self):
        source = FakeAuthServer().source()
        prepared = source.prepare("http://127.0.0.1:5555/cb")
        assert prepared.verifier not in prepared.authorize_url

    def test_state_mismatch_is_rejected_before_exchange(self):
        server = FakeAuthServer()
        source = server.source()
        source.prepare("http://127.0.0.1:5555/cb")
        bad = _callback(source).replace("state=", "state=tampered")
        with pytest.raises(PKCEProtocolError, match="state mismatch"):
            _run(source.obtain(callback_url=bad))
        assert server.requests == []

    def test_out_of_band_flow_pastes_code(self):
        server = FakeAuthServer()
        source = server.source()
        prepared = source.prepare("oob")
        assert "callback_url=oob" in prepared.authorize_url
        assert prepared.verifier not in prepared.authorize_url
        credential = _run(source.obtain(code="pasted-code"))
        assert credential.api_key == FAKE_KEY
        assert json.loads(server.requests[0].content)["code"] == "pasted-code"

    def test_code_reuse_is_rejected_locally(self):
        server = FakeAuthServer()
        source = server.source()
        source.prepare("http://127.0.0.1:5555/cb")
        callback = _callback(source)
        _run(source.obtain(callback_url=callback))
        with pytest.raises(PKCEProtocolError):
            _run(source.obtain(callback_url=callback))
        assert len(server.requests) == 1

    def test_expired_login_is_rejected(self):
        server = FakeAuthServer()
        source = server.source()
        prepared = source.prepare("http://127.0.0.1:5555/cb")
        source.verifiers.put(prepared.state, prepared.verifier, ttl=-1)
        with pytest.raises(PKCEProtocolError):
            _run(source.obtain(callback_url=_callback(source)))
        assert server.requests == []

    def test_denial_is_reported_not_exchanged(self):
        server = FakeAuthServer()
        source = server.source()
        prepared = source.prepare("http://127.0.0.1:5555/cb")
        denied = f"{prepared.callback_url}?error=access_denied&state={prepared.state}"
        with pytest.raises(CredentialError, match="denied"):
            _run(source.obtain(callback_url=denied))
        assert server.requests == []

    @pytest.mark.parametrize("status", [403, 401])
    def test_rejected_code_is_terminal(self, status):
        source = FakeAuthServer(status=status).source()
        source.prepare("http://127.0.0.1:5555/cb")
        with pytest.raises(PKCEProtocolError, match="rejected"):
            _run(source.obtain(callback_url=_callback(source)))

    def test_rate_limit_is_explained(self):
        source = FakeAuthServer(status=429, payload={"error": "slow_down"}).source()
        source.prepare("http://127.0.0.1:5555/cb")
        with pytest.raises(CredentialError, match="Too many"):
            _run(source.obtain(callback_url=_callback(source)))

    def test_network_failure_is_explained_without_leaking(self):
        class _Boom(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                raise httpx.ConnectError("boom", request=request)

        source = PKCECredentialSource(transport=_Boom())
        source.prepare("http://127.0.0.1:5555/cb")
        with pytest.raises(CredentialError) as info:
            _run(source.obtain(callback_url=_callback(source)))
        assert "verifier" not in str(info.value).lower()

    def test_scope_downgrade_is_reported(self):
        source = FakeAuthServer(payload={"key": FAKE_KEY, "scope": "connector"}).source()
        source.prepare("http://127.0.0.1:5555/cb")
        with pytest.raises(PKCEProtocolError, match="connector"):
            _run(source.obtain(callback_url=_callback(source)))

    def test_missing_scope_is_rejected(self):
        with pytest.raises(PKCEProtocolError):
            parse_exchange_response(200, {"key": FAKE_KEY})

    def test_exchange_response_without_key_is_rejected(self):
        with pytest.raises(PKCEProtocolError):
            parse_exchange_response(200, {"scope": "api", "error": "oops"})


class TestApiKeyAdapter:
    def test_static_key_yields_the_same_credential_shape(self):
        static = _run(StaticKeyCredentialSource(FAKE_KEY).obtain())
        source = FakeAuthServer().source()
        source.prepare("http://127.0.0.1:5555/cb")
        pkce = _run(source.obtain(callback_url=_callback(source)))
        assert type(static) is type(pkce)
        assert static.api_key == pkce.api_key
        assert {static.source, pkce.source} == {"api_key", "pkce"}

    def test_wrong_prefix_rejected(self):
        with pytest.raises(CredentialError):
            _run(StaticKeyCredentialSource("sk-something-else").obtain())


class TestCredentialStore:
    def test_well_formed_and_masked(self):
        info = CredentialStore.classify(FAKE_KEY)
        assert info.well_formed is True
        assert info.masked != FAKE_KEY
        assert info.masked.endswith(FAKE_KEY[-4:])
        assert CredentialStore.classify("not-a-key").well_formed is False
        assert CredentialStore.mask("") == ""
