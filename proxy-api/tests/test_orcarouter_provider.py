"""Tests for the OrcaRouter named provider: registry, routing and catalog."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app import providers
from app.orcarouter_catalog import (
    ModelCatalog,
    cyber_models_from,
    filter_models,
    parse_catalog,
    seed_catalog,
)

CONFIG = Path(__file__).resolve().parents[2] / "config" / "providers.json"

CHAT_TEXT = {
    "id": "openai/gpt-5.5",
    "name": "GPT-5.5",
    "context_length": 400000,
    "supports_reasoning": True,
    "supported_endpoint_types": ["openai"],
    "architecture": {"input_modalities": ["text"]},
}
CHAT_VISION = {
    "id": "anthropic/claude-opus-4.8",
    "name": "Claude Opus 4.8",
    "context_length": 200000,
    "supported_endpoint_types": ["openai", "anthropic"],
    "architecture": {"input_modalities": ["text", "image"]},
}
EMBEDDING = {"id": "qwen/qwen3-embedding", "supported_endpoint_types": ["embedding"]}
IMAGE_GEN = {"id": "black-forest-labs/flux", "supported_endpoint_types": ["image-generation"]}
VIDEO = {"id": "google/veo", "supported_endpoint_types": ["openai-video"]}
RERANK = {"id": "jina/jina-reranker", "supported_endpoint_types": ["jina-rerank"]}
AUTO = {"id": "orcarouter/auto", "supported_endpoint_types": ["openai"], "architecture": {"input_modalities": ["text"]}}
CYBER = {"id": "orcacyber-ultra-1.0", "supported_endpoint_types": ["openai"], "architecture": {"input_modalities": ["text"]}}
NO_NAMESPACE = {"id": "bare-model", "supported_endpoint_types": ["openai"]}


class TestRegistry:
    def test_orcarouter_is_a_named_provider(self):
        spec = providers.get_provider("orcarouter")
        assert spec is not None
        assert spec.base_url == "https://api.orcarouter.ai/v1"
        assert spec.display_name == "OrcaRouter Cyber Inference"
        assert spec.default_model == "orcarouter/auto"
        assert providers.ORCAROUTER_PROVIDER in providers.list_providers()

    def test_existing_providers_keep_their_routing(self):
        for name in ("groq", "openai", "anthropic", "together", "gemini", "mistral", "deepinfra", "xai"):
            spec = providers.get_provider(name)
            assert spec is not None and spec.base_url is None
        assert providers.litellm_model_name(providers.get_provider("groq"), "m") == "groq/m"

    def test_config_keeps_brand_and_links(self):
        raw = json.loads(CONFIG.read_text())["providers"]["orcarouter"]
        assert raw["base_url"] == "https://api.orcarouter.ai/v1"
        assert raw["links"]["brand"] == "https://www.orcarouter.ai"
        assert raw["links"]["provider_page"] == "https://www.orcarouter.ai/cyber"
        assert raw["links"]["cyber_models"] == "https://www.orcarouter.ai/models?tier=cyber"
        assert raw["recommended_models"]["default"] == "orcarouter/auto"
        assert raw["recommended_models"]["general_fallback"] == "orcarouter/fusion"
        assert raw["seed_models"] == ["deepseek/deepseek-v4.1-flash"]
        assert raw["recommended_models"]["dedicated_cyber"] == ["orcacyber-ultra-1.0", "orcacyber-zero-1.5"]


class TestForwarding:
    @pytest.mark.asyncio
    async def test_non_stream_uses_orcarouter_base_url(self):
        spec = providers.get_provider("orcarouter")
        with patch("app.providers.litellm.acompletion", new_callable=AsyncMock) as completion:
            completion.return_value = "resp"
            await providers.forward_chat_completion(spec, "sk-orca-test000000", {"model": "orcarouter/auto", "messages": []})
        kwargs = completion.await_args.kwargs
        assert kwargs["api_base"] == "https://api.orcarouter.ai/v1"
        assert kwargs["api_key"] == "sk-orca-test000000"
        assert kwargs["model"] == "openai/orcarouter/auto"

    @pytest.mark.asyncio
    async def test_stream_uses_orcarouter_base_url(self):
        spec = providers.get_provider("orcarouter")
        with patch("app.providers.litellm.acompletion", new_callable=AsyncMock) as completion:
            completion.return_value = "stream"
            await providers.forward_chat_completion_stream(
                spec, "sk-orca-test000000", {"model": "orcarouter/auto", "messages": []}
            )
        kwargs = completion.await_args.kwargs
        assert kwargs["api_base"] == "https://api.orcarouter.ai/v1"
        assert kwargs["stream"] is True
        assert kwargs["stream_options"] == {"include_usage": True}

    @pytest.mark.asyncio
    async def test_reasoning_model_gets_effort_but_not_for_other_providers(self):
        orca = providers.get_provider("orcarouter")
        groq = providers.get_provider("groq")
        with patch("app.providers.litellm.acompletion", new_callable=AsyncMock) as completion:
            await providers.forward_chat_completion(orca, "k", {"model": "openai/gpt-5.5", "messages": []})
            await providers.forward_chat_completion(groq, "k", {"model": "llama-3", "messages": []})
        assert completion.await_args_list[0].kwargs["reasoning_effort"] == "medium"
        assert "reasoning_effort" not in completion.await_args_list[1].kwargs

    @pytest.mark.asyncio
    async def test_explicit_base_override_still_wins(self):
        spec = providers.get_provider("orcarouter")
        with patch("app.providers.litellm.acompletion", new_callable=AsyncMock) as completion:
            await providers.forward_chat_completion(
                spec, "k", {"model": "orcarouter/auto", "messages": []}, base_url_override="http://127.0.0.1:9/v1"
            )
        assert completion.await_args.kwargs["api_base"] == "http://127.0.0.1:9/v1"


class TestCatalogParsing:
    def test_parse_keeps_namespace_and_filters_non_chat(self):
        models = parse_catalog({"data": [CHAT_TEXT, CHAT_VISION, EMBEDDING, IMAGE_GEN, VIDEO, RERANK, NO_NAMESPACE, "junk"]})
        ids = [m["id"] for m in models]
        assert ids == ["anthropic/claude-opus-4.8", "bare-model", "openai/gpt-5.5"]
        gpt = next(m for m in models if m["id"] == "openai/gpt-5.5")
        assert gpt["context_length"] == 400000
        assert gpt["supports_reasoning"] is True

    def test_chat_catalog_drops_non_chat_endpoints(self):
        models = parse_catalog({"data": [CHAT_TEXT, EMBEDDING, IMAGE_GEN, VIDEO, RERANK]})
        assert [m["id"] for m in models] == ["openai/gpt-5.5"]

    def test_parse_is_bounded(self):
        payload = {"data": [{"id": f"vendor/m{i}", "supported_endpoint_types": ["openai"]} for i in range(5000)]}
        assert len(parse_catalog(payload)) == providers.CATALOG_MAX_ITEMS

    def test_parse_rejects_non_list_payload(self):
        assert parse_catalog({"data": "nope"}) == []
        assert parse_catalog([]) == []

    def test_text_filter_excludes_multimodal_only_endpoints(self):
        models = parse_catalog({"data": [CHAT_TEXT, EMBEDDING, IMAGE_GEN, VIDEO, RERANK]})
        assert [m["id"] for m in filter_models(models, capability="chat")] == ["openai/gpt-5.5"]

    def test_image_attachment_filter_is_fail_closed(self):
        models = parse_catalog({"data": [CHAT_TEXT, CHAT_VISION]})
        with_image = filter_models(models, capability="chat", required_modalities=["text", "image"])
        assert [m["id"] for m in with_image] == ["anthropic/claude-opus-4.8"]
        assert all("image" in m["input_modalities"] for m in with_image)

    def test_capability_filters_use_endpoint_types(self):
        models = parse_catalog({"data": [CHAT_TEXT, EMBEDDING, IMAGE_GEN, VIDEO, RERANK]}, chat_only=False)
        assert [m["id"] for m in filter_models(models, capability="embedding")] == ["qwen/qwen3-embedding"]
        assert filter_models(models, capability="image") == []
        assert filter_models(models, capability="video") == []

    def test_cyber_tier_only_from_live_catalog(self):
        models = parse_catalog({"data": [AUTO, CYBER]}, chat_only=False)
        assert [m["id"] for m in cyber_models_from(models)] == ["orcacyber-ultra-1.0"]
        assert cyber_models_from(seed_catalog()) == []


class _FakeTransport:
    def __init__(self, status: int, body: object) -> None:
        self.status = status
        self.body = body
        self.requests: list = []

    def build(self):
        import httpx

        transport = self

        class _Handler(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                transport.requests.append(request)
                raw = json.dumps(transport.body).encode() if not isinstance(transport.body, bytes) else transport.body
                return httpx.Response(transport.status, content=raw, request=request)

        return _Handler()


class TestDiscovery:
    @pytest.mark.asyncio
    async def test_live_catalog_is_authoritative_and_authenticated(self):
        transport = _FakeTransport(200, {"data": [CHAT_TEXT, CHAT_VISION]})
        catalog = ModelCatalog(transport=transport.build())
        result = await catalog.fetch("sk-orca-test000000")
        assert result.source == "live" and result.degraded is False
        assert [m["id"] for m in result.models] == ["anthropic/claude-opus-4.8", "openai/gpt-5.5"]
        request = transport.requests[0]
        assert str(request.url) == "https://api.orcarouter.ai/v1/models"
        assert request.headers["authorization"] == "Bearer sk-orca-test000000"

    @pytest.mark.asyncio
    async def test_failure_falls_back_to_labelled_seed(self):
        transport = _FakeTransport(503, {"error": "down"})
        result = await ModelCatalog(transport=transport.build()).fetch("sk-orca-test000000")
        assert result.source == "seed" and result.degraded is True
        assert [m["id"] for m in result.models] == ["orcarouter/auto", "deepseek/deepseek-v4.1-flash"]
        assert all(m["verified"] for m in result.models)

    @pytest.mark.asyncio
    async def test_auth_error_falls_back_to_seed_with_reason(self):
        transport = _FakeTransport(401, {})
        result = await ModelCatalog(transport=transport.build()).fetch("sk-orca-test000000")
        assert result.source == "seed" and result.error == "auth_error:401"

    @pytest.mark.asyncio
    async def test_cached_live_is_reused_then_last_known_good(self):
        clock = [0.0]
        transport = _FakeTransport(200, {"data": [CHAT_TEXT]})
        catalog = ModelCatalog(transport=transport.build(), clock=lambda: clock[0], ttl_seconds=60)
        first = await catalog.fetch("k")
        second = await catalog.fetch("k")
        assert first is second and len(transport.requests) == 1
        clock[0] = 120.0
        transport.status = 500
        third = await catalog.fetch("k")
        assert third.source == "last_known_good" and third.degraded is True
        assert [m["id"] for m in third.models] == ["openai/gpt-5.5"]

    @pytest.mark.asyncio
    async def test_oversized_or_empty_catalog_falls_back(self):
        assert (await ModelCatalog(transport=_FakeTransport(200, {"data": []}).build()).fetch("k")).source == "seed"
        blob = b'{"data": [' + b" " * (providers.CATALOG_MAX_BYTES + 10) + b"]}"
        assert (await ModelCatalog(transport=_FakeTransport(200, blob).build()).fetch("k")).source == "seed"
