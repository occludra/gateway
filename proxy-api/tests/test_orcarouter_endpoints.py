"""End-to-end tests for the OrcaRouter dev credential endpoints and proxy wiring.

A config file in a tmp dir is the gateway's real secret store; a local fake
auth origin stands in for www.orcarouter.ai. No real key is minted.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from urllib.parse import urlencode

import httpx
import pytest
import yaml
from starlette.testclient import TestClient

from app import config as config_mod
from app import dev_mode
from app import providers
from app.credentials import AUTHORIZATION_TIMEOUT_SECONDS

FAKE_KEY = "sk-orca-fake11111111111111111111111111"
NEW_KEY = "sk-orca-newkey222222222222222222222222"
NGINX_HEADER = "Bearer gateway-test-key"


class FakeAuth:
    def __init__(self, status: int = 200, payload: object | None = None) -> None:
        self.status = status
        self.payload = payload if payload is not None else {"key": FAKE_KEY, "user_id": "1", "scope": "api"}
        self.requests: list[httpx.Request] = []
        fake = self

        class _Transport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                fake.requests.append(request)
                body = fake.payload if isinstance(fake.payload, bytes) else json.dumps(fake.payload).encode()
                return httpx.Response(fake.status, content=body, request=request)

        self.transport = _Transport()


@pytest.fixture
def gateway(tmp_path, monkeypatch):
    config_path = tmp_path / "gateway.yaml"
    config_path.write_text(
        yaml.safe_dump(
            {
                "providers": {"groq": {"api_key": "${GROQ_API_KEY:-}"}, "orcarouter": {"api_key": ""}},
                "api_keys": [{"key": "gateway-test-key", "name": "console"}],
                "dlp": {"action": "redact"},
            }
        )
    )
    monkeypatch.setenv("AISG_DEV_MODE", "1")
    monkeypatch.setenv("AISG_CONFIG_PATH", str(config_path))
    monkeypatch.setattr(config_mod.get_settings(), "config_path", str(config_path))
    monkeypatch.setattr(config_mod, "_gateway_config", None)
    dev_mode.login_state.__init__()
    dev_mode.key_state.__init__()

    from app.main import _rate_buckets, app

    _rate_buckets.clear()
    with TestClient(app) as client:
        yield client, config_path, monkeypatch
    monkeypatch.setattr(config_mod, "_gateway_config", None)


def _headers():
    return {"Authorization": NGINX_HEADER}


def _key_on_disk(config_path: Path) -> str:
    return (yaml.safe_load(config_path.read_text())["providers"]["orcarouter"] or {}).get("api_key") or ""


def _start_login(client, monkeypatch, fake: FakeAuth) -> dict:
    original = dev_mode.PKCECredentialSource

    def _factory(*args, **kwargs) -> dev_mode.PKCECredentialSource:
        return original(transport=fake.transport)

    monkeypatch.setattr(dev_mode, "PKCECredentialSource", _factory)
    resp = client.post(
        "/v1/dev/orcarouter/connect",
        json={"callback_url": "http://127.0.0.1:5555/cb"},
        headers=_headers(),
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _callback_for(attempt_id: str, state: str, code: str = "fake-code") -> str:
    return f"http://127.0.0.1:5555/cb?{urlencode({'code': code, 'state': state})}"


def _state_of(attempt_id: str) -> str:
    attempt = dev_mode.login_state.current_attempt()
    assert attempt is not None and attempt.attempt_id == attempt_id
    return attempt.source._prepared.state


class TestDevAuthGates:
    def test_requires_gateway_key(self, gateway):
        client, _, _ = gateway
        assert client.get("/v1/dev/orcarouter/status").status_code == 403

    def test_status_lists_both_auth_methods(self, gateway):
        client, _, _ = gateway
        resp = client.get("/v1/dev/orcarouter/status", headers=_headers())
        data = resp.json()
        assert data["configured"] is False
        assert data["auth_methods"] == ["api_key", "pkce"]
        assert data["cli_commands"] == ["api-key", "login"]
        assert data["display_name"] == "OrcaRouter Cyber Inference"


class TestApiKeyEntry:
    def test_paste_key_stores_masked_config(self, gateway):
        client, config_path, _ = gateway
        resp = client.put("/v1/dev/orcarouter/credentials/api-key", json={"api_key": FAKE_KEY}, headers=_headers())
        assert resp.status_code == 200
        data = resp.json()
        assert data["configured"] is True
        assert data["secret_masked"] != FAKE_KEY
        assert FAKE_KEY not in resp.text
        assert _key_on_disk(config_path) == FAKE_KEY
        # other providers keep their env-substitution slots
        stored = yaml.safe_load(config_path.read_text())
        assert stored["providers"]["groq"]["api_key"] == "${GROQ_API_KEY:-}"

    def test_models_selector_filtered_server_side(self, gateway, monkeypatch):
        import httpx

        from app import providers

        client, _, _ = gateway
        client.put("/v1/dev/orcarouter/credentials/api-key", json={"api_key": FAKE_KEY}, headers=_headers())
        seen: list[httpx.Request] = []
        payload = {
            "data": [
                {"id": "openai/gpt-5.5", "supported_endpoint_types": ["openai"], "architecture": {"input_modalities": ["text"]}},
                {"id": "anthropic/claude-opus-4.8", "supported_endpoint_types": ["openai"], "architecture": {"input_modalities": ["text", "image"]}},
                {"id": "black-forest-labs/flux", "supported_endpoint_types": ["image-generation"]},
            ]
        }

        class _T(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                seen.append(request)
                return httpx.Response(200, content=json.dumps(payload).encode(), request=request)

        from app import orcarouter_catalog

        monkeypatch.setattr(orcarouter_catalog.ModelCatalog, "_transport", None, raising=False)
        catalog = orcarouter_catalog.ModelCatalog(transport=_T())
        monkeypatch.setattr("app.routers.proxy._orcarouter_catalog", catalog)

        text = client.post("/v1/models/orcarouter", json={"capability": "chat"}, headers=_headers()).json()
        assert [m["id"] for m in text["data"]] == ["anthropic/claude-opus-4.8", "openai/gpt-5.5"]
        assert text["catalog_source"] == "live" and text["degraded"] is False
        vision = client.post(
            "/v1/models/orcarouter", json={"capability": "chat", "required_modalities": ["text", "image"]}, headers=_headers()
        ).json()
        assert [m["id"] for m in vision["data"]] == ["anthropic/claude-opus-4.8"]
        assert FAKE_KEY not in json.dumps(text)
        assert seen[0].url.host == "api.orcarouter.ai"
        assert seen[0].headers["authorization"] == f"Bearer {FAKE_KEY}"

        # discovery outage: labelled degraded seed, never free text
        class _Down(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                return httpx.Response(503, content=b"{}", request=request)

        monkeypatch.setattr("app.routers.proxy._orcarouter_catalog", orcarouter_catalog.ModelCatalog(transport=_Down()))
        down = client.post("/v1/models/orcarouter", json={"capability": "chat", "refresh": True}, headers=_headers()).json()
        assert down["degraded"] is True and down["catalog_source"] == "seed"
        assert all(m["verified"] for m in down["data"])
        assert providers.ORCAROUTER_PROVIDER in providers.list_providers()

    def test_bad_key_shape_rejected(self, gateway):
        client, config_path, _ = gateway
        resp = client.put("/v1/dev/orcarouter/credentials/api-key", json={"api_key": "sk-nope"}, headers=_headers())
        assert resp.status_code == 400
        assert _key_on_disk(config_path) == ""

    def test_clear_key(self, gateway):
        client, config_path, _ = gateway
        client.put("/v1/dev/orcarouter/credentials/api-key", json={"api_key": FAKE_KEY}, headers=_headers())
        resp = client.delete("/v1/dev/orcarouter/credentials", headers=_headers())
        assert resp.json()["configured"] is False
        assert _key_on_disk(config_path) == ""


class TestPkceEntry:
    def test_full_login_authorize_exchange_persist(self, gateway):
        client, config_path, monkeypatch = gateway
        fake = FakeAuth()
        start = _start_login(client, monkeypatch, fake)
        assert start["code_challenge_method"] == "S256"
        assert start["authorize_url"].startswith("https://www.orcarouter.ai/auth?")
        assert start["expires_in"] == AUTHORIZATION_TIMEOUT_SECONDS

        state = _state_of(start["attempt_id"])
        done = client.post(
            "/v1/dev/orcarouter/connect/complete",
            json={"attempt_id": start["attempt_id"], "callback_url": _callback_for(start["attempt_id"], state)},
            headers=_headers(),
        )
        assert done.status_code == 200, done.text
        assert done.json()["secret_masked"] != FAKE_KEY
        assert _key_on_disk(config_path) == FAKE_KEY
        assert fake.requests[0].url.host == "www.orcarouter.ai"
        assert fake.requests[0].url.path == "/api/v1/auth/keys"
        # login lock released
        assert client.get("/v1/dev/orcarouter/status", headers=_headers()).json()["login"]["busy"] is False

    def test_second_login_while_busy_conflicts(self, gateway):
        client, _, monkeypatch = gateway
        fake = FakeAuth()
        _start_login(client, monkeypatch, fake)
        resp = client.post("/v1/dev/orcarouter/connect", json={"callback_url": "http://127.0.0.1:5555/cb"}, headers=_headers())
        assert resp.status_code == 409

    def test_state_mismatch_and_stale_attempt(self, gateway):
        client, config_path, monkeypatch = gateway
        fake = FakeAuth()
        start = _start_login(client, monkeypatch, fake)
        state = _state_of(start["attempt_id"])
        bad = client.post(
            "/v1/dev/orcarouter/connect/complete",
            json={"attempt_id": start["attempt_id"], "callback_url": _callback_for(start["attempt_id"], "wrong" + state)},
            headers=_headers(),
        )
        assert bad.status_code == 400
        stale = client.post(
            "/v1/dev/orcarouter/connect/complete",
            json={"attempt_id": "login_999_ffff", "callback_url": _callback_for(start["attempt_id"], state)},
            headers=_headers(),
        )
        assert stale.status_code == 410
        assert _key_on_disk(config_path) == ""
        assert fake.requests == []

    def test_cancel_releases_lock_and_late_success_is_dropped(self, gateway):
        client, config_path, monkeypatch = gateway
        fake = FakeAuth()
        start = _start_login(client, monkeypatch, fake)
        state = _state_of(start["attempt_id"])
        attempt = dev_mode.login_state.current_attempt()
        assert attempt is not None
        # Snapshot what step 2 would use, then cancel before it lands.
        source = attempt.source
        assert client.post("/v1/dev/orcarouter/connect/cancel", headers=_headers()).json()["cancelled"] is True
        late = asyncio.run(source.obtain(callback_url=_callback_for(start["attempt_id"], state)))
        assert late.api_key == FAKE_KEY  # the exchange itself is the adapter's job...
        assert dev_mode.login_state.busy is False  # ...but the cancelled attempt owns nothing
        resp = client.post(
            "/v1/dev/orcarouter/connect/complete",
            json={"attempt_id": start["attempt_id"], "callback_url": _callback_for(start["attempt_id"], state)},
            headers=_headers(),
        )
        assert resp.status_code == 410
        assert _key_on_disk(config_path) == ""
        # a second login can start immediately
        again = _start_login(client, monkeypatch, fake)
        assert again["attempt_id"] != start["attempt_id"]

    def test_callback_page_checks_state_without_exchanging(self, gateway):
        client, _, monkeypatch = gateway
        fake = FakeAuth()
        start = _start_login(client, monkeypatch, fake)
        state = _state_of(start["attempt_id"])
        ok = client.get(f"/v1/dev/orcarouter/callback?code=x&state={state}")
        assert ok.status_code == 200
        assert fake.requests == []
        bad = client.get("/v1/dev/orcarouter/callback?code=x&state=nope")
        assert bad.status_code == 400


class TestReauthAndGeneration:
    def test_401_marks_exact_generation_only(self, gateway):
        client, _, _ = gateway
        key_state = dev_mode.key_state
        snapshot = key_state.snapshot(FAKE_KEY)
        assert key_state.mark_rejected(snapshot) is True
        assert key_state.current(FAKE_KEY).needs_reauth is True
        # re-login replaces the key: new generation, flag cleared
        key_state.replace(NEW_KEY)
        assert key_state.current(NEW_KEY).needs_reauth is False
        # a late failure for the previous generation cannot poison the new key
        previous_generation = (NEW_KEY, snapshot[1] - 1)
        assert key_state.mark_rejected(previous_generation) is False
        assert key_state.current(NEW_KEY).needs_reauth is False

    def test_late_401_does_not_mark_new_generation(self, gateway):
        client, _, _ = gateway
        client.put("/v1/dev/orcarouter/credentials/api-key", json={"api_key": FAKE_KEY}, headers=_headers())
        old_generation = dev_mode.key_state.current(FAKE_KEY).generation
        old_snapshot = (NEW_KEY, old_generation)  # request issued before the re-login
        client.put("/v1/dev/orcarouter/credentials/api-key", json={"api_key": NEW_KEY}, headers=_headers())
        assert dev_mode.key_state.current(NEW_KEY).generation == old_generation + 1
        assert dev_mode.key_state.mark_rejected(old_snapshot) is False
        assert dev_mode.key_state.current(NEW_KEY).needs_reauth is False

    def test_revoked_key_short_circuits_without_upstream_call(self, gateway, monkeypatch):
        client, _, _ = gateway
        client.put("/v1/dev/orcarouter/credentials/api-key", json={"api_key": FAKE_KEY}, headers=_headers())
        dev_mode.key_state.mark_rejected(dev_mode.key_state.snapshot(FAKE_KEY))

        from app.dlp import ProcessResult

        monkeypatch.setattr("app.routers.proxy.dlp.process_messages", _async_return(ProcessResult()))
        called = []
        monkeypatch.setattr(
            "app.routers.proxy.providers.forward_chat_completion",
            _async_recorder(called),
        )
        resp = client.post(
            "/v1/chat/completions",
            json={"model": "orcarouter/auto", "messages": [{"role": "user", "content": "hi"}]},
            headers={**_headers(), "x-provider": "orcarouter"},
        )
        assert resp.status_code == 502
        assert "orcarouter_reauth_required" in resp.text
        assert called == []

    def test_reauth_hint_is_actionable(self, gateway):
        client, _, _ = gateway
        client.put("/v1/dev/orcarouter/credentials/api-key", json={"api_key": FAKE_KEY}, headers=_headers())
        dev_mode.key_state.mark_rejected(dev_mode.key_state.snapshot(FAKE_KEY))
        text = client.get("/v1/dev/orcarouter/status", headers=_headers()).json()
        assert text["needs_reauth"] is True
        assert text["generation"] == 1


class TestNoSecretLeaks:
    def test_key_absent_from_logs_and_errors(self, gateway, monkeypatch, caplog):
        client, _, _ = gateway
        caplog.set_level(logging.DEBUG)
        fake = FakeAuth(status=200)
        client.put("/v1/dev/orcarouter/credentials/api-key", json={"api_key": FAKE_KEY}, headers=_headers())
        start = _start_login(client, monkeypatch, fake)
        state = _state_of(start["attempt_id"])
        done = client.post(
            "/v1/dev/orcarouter/connect/complete",
            json={"attempt_id": start["attempt_id"], "callback_url": _callback_for(start["attempt_id"], state)},
            headers=_headers(),
        )
        assert FAKE_KEY not in done.text
        assert FAKE_KEY not in caplog.text
        assert "sk-orca-newkey" not in caplog.text


def _async_return(value):
    async def _inner(*args, **kwargs):
        return value

    return _inner


def _async_recorder(sink):
    async def _inner(*args, **kwargs):
        sink.append((args, kwargs))
        raise RuntimeError("should not be called")

    return _inner
