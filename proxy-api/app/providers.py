"""Provider registry and upstream forwarding via LiteLLM.

Provider metadata is loaded from config/providers.json.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import litellm
import structlog

from .config import get_settings

litellm.drop_params = True
litellm.set_verbose = False

log = structlog.get_logger()

# Chat-completion parameters forwarded to upstream providers.
_KNOWN_COMPLETION_PARAMS = {
    "messages", "temperature", "top_p", "max_tokens", "max_completion_tokens",
    "stop", "stream", "stream_options", "n",
    "presence_penalty", "frequency_penalty",
    "logit_bias", "logprobs", "top_logprobs",
    "user", "seed",
    "tools", "tool_choice", "functions", "function_call",
    "parallel_tool_calls",
    "response_format",
    "reasoning_effort",
    "thinking",
    "top_k",
    "extra_headers",
    "service_tier",
}


def _load_providers_json() -> dict[str, Any]:
    """Load provider metadata from config/providers.json."""
    env = os.environ.get("PROVIDERS_CONFIG_PATH")
    candidates = []
    if env:
        candidates.append(Path(env))
    candidates.append(Path("/app/config/providers.json"))
    candidates.append(Path(__file__).resolve().parent.parent / "config" / "providers.json")

    for p in candidates:
        if p.exists():
            with open(p) as f:
                return json.load(f)
    return {"providers": {}}


_PROVIDERS_DATA = _load_providers_json()


PROVIDER_PREFIX: dict[str, str] = {
    k: v["litellm_prefix"] for k, v in _PROVIDERS_DATA.get("providers", {}).items()
}


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """Immutable descriptor for an LLM provider.

    ``base_url`` is set for named providers that speak the OpenAI wire format
    at a fixed endpoint (OrcaRouter); LiteLLM is pointed there explicitly so the
    provider keeps its own identity instead of being aliased to a generic
    ``openai``/``custom`` endpoint.
    """

    name: str
    litellm_prefix: str
    base_url: str | None = None
    default_model: str | None = None
    display_name: str | None = None

    @property
    def is_orcarouter(self) -> bool:
        return self.name == "orcarouter"


def _spec_from_entry(name: str, entry: dict[str, Any]) -> ProviderSpec:
    return ProviderSpec(
        name=name,
        litellm_prefix=entry["litellm_prefix"],
        base_url=entry.get("base_url"),
        default_model=entry.get("default_model"),
        display_name=entry.get("display_name"),
    )


PROVIDERS: dict[str, ProviderSpec] = {
    name: _spec_from_entry(name, entry)
    for name, entry in _PROVIDERS_DATA.get("providers", {}).items()
}

ORCAROUTER_PROVIDER = "orcarouter"

# Small, operator-verified cold-start seed for OrcaRouter. Live GET /v1/models
# is authoritative; this is only used (labelled ``degraded``) when discovery
# fails, so every entry must be one this provider path has actually called
# (verify/verification date in the comment below each entry).
ORCAROUTER_SEED_MODELS: list[dict[str, Any]] = [
    {
        "id": "orcarouter/auto",
        "name": "OrcaRouter Auto (default)",
        "context_length": 200_000,
        "input_modalities": ["text"],
        "supports_reasoning": True,
        "verified": True,
    },
    # verified 2026-11-09: real completion through forward_chat_completion()
    {
        "id": "deepseek/deepseek-v4.1-flash",
        "name": "DeepSeek V4.1 Flash (general fallback)",
        "context_length": 128_000,
        "input_modalities": ["text"],
        "supports_reasoning": False,
        "verified": True,
    },
]

# Dedicated cyber tier -- recommended for security teams doing authorized work.
# A model is offered only when the live catalog advertises that id; these
# entries add tier + label metadata on top of the live record.
ORCAROUTER_CYBER_MODELS: dict[str, dict[str, Any]] = {
    "orcacyber-ultra-1.0": {"name": "OrcaCyber Ultra", "tier": "cyber"},
    "orcacyber-zero-1.5": {"name": "OrcaCyber Zero", "tier": "cyber"},
}

# Bounds so a catalog response cannot consume unbounded memory or advertise
# routes this gateway cannot speak.
CATALOG_MAX_BYTES = 2 * 1024 * 1024
CATALOG_MAX_ITEMS = 2_000
CATALOG_TIMEOUT_SECONDS = 10.0
_SUPPORTED_ENDPOINT_TYPES = {"openai", "openai-response", "anthropic", "gemini"}
_NON_TEXT_ENDPOINT_TYPES = {"image-generation", "openai-video", "jina-rerank", "embedding", "embeddings"}


def get_provider(name: str) -> ProviderSpec | None:
    """Look up a ProviderSpec by case-insensitive provider name."""
    return PROVIDERS.get(name.lower())


def list_providers() -> list[str]:
    """Return a sorted list of all configured provider names."""
    return sorted(PROVIDERS.keys())


def litellm_model_name(provider: ProviderSpec, model: str) -> str:
    """Build the 'prefix/model' string that LiteLLM expects."""
    return f"{provider.litellm_prefix}/{model}"


def _signals_reasoning(model: str) -> bool:
    """Heuristic used only when the catalog gives no explicit reasoning flag."""
    lowered = model.lower()
    return any(token in lowered for token in ("gpt-5", "o1", "o3", "o4", "reasoning", "thinking"))


def _tune_request(provider: ProviderSpec, raw_model: str, params: dict[str, Any]) -> dict[str, Any]:
    """Provider-specific request tweaks, shared by the stream and non-stream paths.

    Other providers pass through untouched. OrcaRouter exposes reasoning models
    behind the OpenAI schema, so unless the caller chose an effort level the
    relay is asked for a medium reasoning summary instead of silently dropping it.
    """
    params = dict(params)
    if provider.is_orcarouter:
        model = raw_model.split("/", 1)[-1]
        if _signals_reasoning(model) and params.get("reasoning_effort") is None:
            params["reasoning_effort"] = "medium"
    return params


def _completion_kwargs(
    provider: ProviderSpec,
    api_key: str,
    raw_model: str,
    body: dict[str, Any],
    base_url_override: str | None,
) -> dict[str, Any]:
    params = _tune_request(provider, raw_model, {k: v for k, v in body.items() if k in _KNOWN_COMPLETION_PARAMS})
    kwargs: dict[str, Any] = {
        "model": litellm_model_name(provider, raw_model),
        "timeout": get_settings().upstream_timeout_seconds,
        "api_key": api_key,
        **params,
    }
    effective_base = base_url_override or provider.base_url
    if effective_base:
        kwargs["api_base"] = effective_base.rstrip("/")
    return kwargs


async def forward_chat_completion(
    provider: ProviderSpec,
    api_key: str,
    body: dict[str, Any],
    *,
    base_url_override: str | None = None,
) -> litellm.ModelResponse:
    """Call the upstream LLM via LiteLLM's async completion."""
    raw_model = body.pop("model", "")
    log.info("upstream_forward", provider=provider.name, litellm_model=litellm_model_name(provider, raw_model))
    return await litellm.acompletion(**_completion_kwargs(provider, api_key, raw_model, body, base_url_override))


async def forward_chat_completion_stream(
    provider: ProviderSpec,
    api_key: str,
    body: dict[str, Any],
    *,
    base_url_override: str | None = None,
):
    """Call the upstream LLM via LiteLLM with streaming enabled.

    Returns an async generator that yields ``ModelResponseStream`` chunks.
    """
    raw_model = body.pop("model", "")
    log.info("upstream_forward_stream", provider=provider.name, litellm_model=litellm_model_name(provider, raw_model))

    body["stream"] = True
    if body.get("stream_options") is None:
        body["stream_options"] = {"include_usage": True}

    return await litellm.acompletion(**_completion_kwargs(provider, api_key, raw_model, body, base_url_override))
