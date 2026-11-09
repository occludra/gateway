"""Tests for the live-check helper and the CLI on-ramps (both auth choices).

The live-marked test performs ONE real request through
``app.providers.forward_chat_completion`` -- the same path
``/v1/chat/completions`` uses -- with ``ORCAROUTER_API_KEY`` and is skipped
when the variable is absent. No key is ever printed.
"""

from __future__ import annotations

import asyncio
import json
import os

import httpx
import pytest

from app import providers
from app.credentials import resolve_origins
from app.orcarouter_catalog import ModelCatalog, filter_models

FAKE_KEY = "sk-orca-cli000000000000000000000000000"


class TestLiveCheck:
    @pytest.mark.asyncio
    async def test_live_request_through_gateway_forwarding_path(self):
        api_key = os.environ.get("ORCAROUTER_API_KEY")
        if not api_key:
            pytest.skip("ORCAROUTER_API_KEY not set")
        spec = providers.get_provider(providers.ORCAROUTER_PROVIDER)
        assert spec is not None and spec.base_url == "https://api.orcarouter.ai/v1"

        live_models = await ModelCatalog().fetch(api_key, force=True)
        chat = filter_models(live_models.models, capability="chat")
        assert live_models.source == "live", f"catalog degraded: {live_models.error}"
        assert chat, "live catalog exposed no chat models"
        assert all("orcarouter" in m["id"] or "/" in m["id"] for m in chat)

        # Every chat-selectable model goes through the provider path; one success
        # proves the wiring (the verification key is scoped to a subset).
        attempts: list[tuple[str, str]] = []
        reply = None
        chosen = ""
        for model in chat:
            try:
                reply = await providers.forward_chat_completion(
                    spec,
                    api_key,
                    {"model": model["id"], "messages": [{"role": "user", "content": "Reply with the single word: ready"}], "max_tokens": 32},
                )
                chosen = model["id"]
                break
            except Exception as exc:  # 403 = key not entitled to this model
                attempts.append((model["id"], type(exc).__name__))
        assert reply is not None, f"no live model accepted by this key: {attempts[:5]}"
        assert reply.choices and reply.choices[0].message.content
        assert chosen in {m["id"] for m in chat}
        # multimodal selector: only models that declare image input survive
        vision = filter_models(live_models.models, capability="chat", required_modalities=["text", "image"])
        assert all("image" in m["input_modalities"] for m in vision)
        print(f"LIVE model={chosen} catalog={len(chat)} vision={len(vision)}")
        print(f"LIVE reply={reply.choices[0].message.content[:80]!r}")


class _FakeTransport(httpx.AsyncBaseTransport):
    def __init__(self, payload: dict) -> None:
        self.payload = payload
        self.requests: list[httpx.Request] = []

    async def handle_async_request(self, request):
        self.requests.append(request)
        return httpx.Response(200, content=json.dumps(self.payload).encode(), request=request)


class TestSelectorsComeFromApi:
    def test_text_dropdown_only_from_api_and_vision_fail_closed(self):
        payload = {
            "data": [
                {"id": "openai/gpt-5.5", "supported_endpoint_types": ["openai"], "architecture": {"input_modalities": ["text"]}},
                {"id": "anthropic/claude-opus-4.8", "supported_endpoint_types": ["openai"], "architecture": {"input_modalities": ["text", "image"]}},
                {"id": "google/gemini-3.5-flash", "supported_endpoint_types": ["openai"], "architecture": {"input_modalities": ["text", "image"]}},
                {"id": "black-forest-labs/flux", "supported_endpoint_types": ["image-generation"]},
            ]
        }
        transport = _FakeTransport(payload)
        result = asyncio.run(ModelCatalog(transport=transport).fetch(FAKE_KEY))
        text = [m["id"] for m in filter_models(result.models, capability="chat")]
        assert text == ["anthropic/claude-opus-4.8", "google/gemini-3.5-flash", "openai/gpt-5.5"]
        with_image = [m["id"] for m in filter_models(result.models, capability="chat", required_modalities=["text", "image"])]
        assert with_image == ["anthropic/claude-opus-4.8", "google/gemini-3.5-flash"]
        assert "openai/gpt-5.5" not in with_image
        assert transport.requests[0].url.host == "api.orcarouter.ai"


@pytest.fixture(autouse=True)
def _isolated_gateway_state(tmp_path, monkeypatch):
    """No test here may touch a real gateway.yaml or an enabled dev-mode app."""
    from app import config as config_mod
    from app import dev_mode

    config_path = tmp_path / "gateway.yaml"
    config_path.write_text("providers:\n  orcarouter:\n    api_key: ''\n")
    monkeypatch.setenv("AISG_CONFIG_PATH", str(config_path))
    monkeypatch.setattr(config_mod.get_settings(), "config_path", str(config_path))
    monkeypatch.setattr(config_mod, "_gateway_config", None)
    dev_mode.login_state.__init__()
    dev_mode.key_state.__init__()
    yield
    monkeypatch.setattr(config_mod, "_gateway_config", None)


class TestCliOnramps:
    def test_cli_help_exposes_both_auth_commands(self):
        from app.orcarouter_cli import build_parser

        help_text = build_parser().format_help()
        assert "api-key" in help_text
        assert "Connect with OrcaRouter (OAuth 2.0 + PKCE)" in help_text
        assert build_parser().parse_args(["login", "--flow", "loopback"]).flow == "loopback"

    def test_api_key_command_uses_shared_credential_path(self, monkeypatch, tmp_path):
        from app import dev_mode, orcarouter_cli

        stored: list[str] = []
        monkeypatch.setattr(orcarouter_cli, "_store", stored.append)
        monkeypatch.setattr(orcarouter_cli, "_load_catalog", lambda key, cap: {"catalog_source": "seed", "models": []})
        monkeypatch.setattr(orcarouter_cli.getpass, "getpass", lambda prompt: FAKE_KEY)
        assert orcarouter_cli.main(["api-key"]) == 0
        assert stored == [FAKE_KEY]
        assert dev_mode is not None

    def test_login_command_reports_denial_and_stores_nothing(self, monkeypatch):
        from app import orcarouter_cli
        from app import credentials

        stored: list[str] = []
        monkeypatch.setattr(orcarouter_cli, "_store", stored.append)
        monkeypatch.setattr("builtins.input", lambda prompt="": "")
        # stop before any network call: the operator never pasted a code
        assert orcarouter_cli.main(["login", "--flow", "oob", "--no-browser"]) == 3
        assert stored == []
        assert credentials.OUT_OF_BAND == "oob"
