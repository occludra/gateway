"""Live OrcaRouter model catalog with bounded parsing and capability filtering.

The single source of truth for model IDs is ``GET {api_base}/models`` (default
``https://api.orcarouter.ai/v1/models``). When discovery succeeds its result is
authoritative; on failure a small verified seed is returned and labelled
``degraded`` so callers never fall back to free-text model entry.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx
import structlog

from . import providers

log = structlog.get_logger()

DEFAULT_CATALOG_URL = "https://api.orcarouter.ai/v1/models"
_SUPPORTED_ENDPOINT_TYPES = {"openai", "openai-response", "anthropic", "gemini"}
_NON_TEXT_ENDPOINT_TYPES = {"image-generation", "openai-video", "jina-rerank", "embedding", "embeddings"}
_MODALITY_TYPES = {
    "text": "text",
    "image": "image_url",
    "audio": "input_audio",
    "video": "video_url",
}


@dataclass(frozen=True)
class CatalogResult:
    """Outcome of a catalog lookup: models plus provenance."""

    models: list[dict[str, Any]]
    source: str  # "live" | "seed" | "last_known_good"
    degraded: bool
    error: str | None = None


@dataclass
class CatalogCache:
    live: CatalogResult | None = None
    expires_at: float = 0.0


def _endpoint_types(entry: dict[str, Any]) -> set[str]:
    raw = entry.get("supported_endpoint_types") or entry.get("supported_endpoint")
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {str(x) for x in raw}
    return set()


def _input_modalities(entry: dict[str, Any]) -> list[str]:
    architecture = entry.get("architecture") if isinstance(entry.get("architecture"), dict) else {}
    raw = architecture.get("input_modalities") or entry.get("input_modalities") or []
    if isinstance(raw, str):
        raw = [raw]
    if not isinstance(raw, list):
        return []
    return sorted({str(m).lower() for m in raw})


def is_text_chat_model(entry: dict[str, Any]) -> bool:
    """Chat models only: supported endpoint, and no image/video/rerank-only type."""
    types = _endpoint_types(entry)
    if types & _NON_TEXT_ENDPOINT_TYPES:
        return False
    if not types:
        return True  # catalog gave no endpoint metadata; keep it chat-selectable
    return bool(types & _SUPPORTED_ENDPOINT_TYPES)


def supports_modality(entry: dict[str, Any], modality: str) -> bool:
    """Fail closed: a model must *declare* the non-text modality to be offered."""
    if modality == "text":
        return True
    return modality in _input_modalities(entry)


def entry_to_model(entry: dict[str, Any]) -> dict[str, Any] | None:
    model_id = entry.get("id")
    if not isinstance(model_id, str) or not model_id or " " in model_id:
        return None  # drop malformed records but keep vendor/model ids verbatim
    context = entry.get("context_length") or entry.get("context_window")
    model: dict[str, Any] = {
        "id": model_id,
        "name": entry.get("name") if isinstance(entry.get("name"), str) else model_id,
        "input_modalities": _input_modalities(entry) or ["text"],
        "verified": False,
    }
    if isinstance(context, int) and context > 0:
        model["context_length"] = context
    if "supports_reasoning" in entry:
        model["supports_reasoning"] = bool(entry["supports_reasoning"])
    if entry.get("supported_endpoint_types"):
        model["supported_endpoint_types"] = sorted(_endpoint_types(entry))
    return model


def parse_catalog(payload: object, *, chat_only: bool = True) -> list[dict[str, Any]]:
    """Bounded, shape-checked parse of a ``GET /models`` response.

    ``chat_only`` (the default) drops non-text endpoints such as embeddings,
    image generation, video and rerank before the chat filter ever sees them.
    """
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if not isinstance(data, list):
        return []
    models: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in data[: providers.CATALOG_MAX_ITEMS]:
        if not isinstance(entry, dict):
            continue
        if chat_only and not is_text_chat_model(entry):
            continue
        model = entry_to_model(entry)
        if model is None or model["id"] in seen:
            continue
        seen.add(model["id"])
        models.append(model)
    models.sort(key=lambda m: m["id"])
    return models


def seed_catalog() -> list[dict[str, Any]]:
    """Verified cold-start seed (orcarouter/auto + fusion only)."""
    return [dict(m) for m in providers.ORCAROUTER_SEED_MODELS]


def cyber_models_from(catalog: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Restrict a catalog to OrcaCyber tier models it actually advertises."""
    wanted = providers.ORCAROUTER_CYBER_MODELS
    cyber: list[dict[str, Any]] = []
    for model in catalog:
        meta = wanted.get(model["id"])
        if meta is None:
            continue
        cyber.append({**model, **meta})
    return cyber


class ModelCatalog:
    """Fetch + cache OrcaRouter catalogs with a labelled degraded fallback."""

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
        ttl_seconds: float = 300.0,
        catalog_url: str | None = None,
    ) -> None:
        self._transport = transport
        self._clock = clock
        self._ttl = ttl_seconds
        self._url = catalog_url or DEFAULT_CATALOG_URL
        self._cache = CatalogCache()

    @property
    def url(self) -> str:
        return self._url

    async def fetch(self, api_key: str, *, force: bool = False) -> CatalogResult:
        now = self._clock()
        if not force and self._cache.live is not None and now < self._cache.expires_at:
            return self._cache.live
        try:
            models = await self._fetch_live(api_key)
        except Exception as exc:  # network, timeout, auth error, bad payload
            reason = getattr(exc, "status_code", None)
            error = f"auth_error:{reason}" if reason in (401, 403) else type(exc).__name__.lower()
            log.warning("orcarouter_catalog_unavailable", error=error)
            if self._cache.live is not None:
                return CatalogResult(models=self._cache.live.models, source="last_known_good", degraded=True, error=error)
            return CatalogResult(models=seed_catalog(), source="seed", degraded=True, error=error)
        result = CatalogResult(models=models, source="live", degraded=False)
        self._cache.live = result
        self._cache.expires_at = now + self._ttl
        return result

    async def _fetch_live(self, api_key: str) -> list[dict[str, Any]]:
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        async with httpx.AsyncClient(
            transport=self._transport,
            timeout=providers.CATALOG_TIMEOUT_SECONDS,
            follow_redirects=False,
        ) as client:
            async with client.stream("GET", self._url, headers=headers) as response:
                if response.status_code != 200:
                    raise _CatalogHTTPError(response.status_code)
                raw = await response.aread()
        if len(raw) > providers.CATALOG_MAX_BYTES:
            raise ValueError("catalog_too_large")
        import json

        models = parse_catalog(json.loads(raw))
        if not models:
            raise ValueError("catalog_empty")
        return models


class _CatalogHTTPError(Exception):
    def __init__(self, status_code: int) -> None:
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code


def filter_models(
    models: list[dict[str, Any]],
    *,
    capability: str = "chat",
    required_modalities: list[str] | None = None,
) -> list[dict[str, Any]]:
    """Capability filter actually bound to every model selector."""
    if capability != "chat":
        return [
            m
            for m in models
            if capability in (m.get("supported_endpoint_types") or [])
            or (capability == "embedding" and "embeddings" in (m.get("supported_endpoint_types") or []))
        ]
    modality_filter = {m for m in (required_modalities or []) if m != "text"}
    return [
        m
        for m in models
        if all(supports_modality(m, modality) for modality in modality_filter)
    ]


async def default_catalog(api_key: str) -> CatalogResult:
    return await ModelCatalog().fetch(api_key)
