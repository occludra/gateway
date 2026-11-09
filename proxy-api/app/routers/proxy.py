"""POST /v1/chat/completions — the core proxy handler.

Request lifecycle:
1. Authenticate via gateway.yaml API keys
2. Resolve provider + model from headers or defaults
3. Resolve provider API key from gateway.yaml
4. DLP: scan text messages via Presidio, block or redact per policy
5. Forward to upstream provider via LiteLLM
6. Return response with gateway metadata headers
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import litellm
import structlog
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, Field

from .. import dlp, providers
from ..auth import authenticate
from ..orcarouter_catalog import ModelCatalog, filter_models
from ..tokens import ORCA_KEY_PREFIX
from ..dev_mode import key_state
from ..config import get_settings, get_provider_keys, get_dlp_policy
from ..log_utils import mask_key
from ..models import (
    ChatCompletionRequest,
    DLPBlockResponse,
    DLPViolation,
    Usage,
)

log = structlog.get_logger()
router = APIRouter(prefix="/v1", tags=["proxy"])


def _generate_request_id() -> str:
    """Generate a unique opaque request ID (req_ + 16 hex chars)."""
    return f"req_{uuid.uuid4().hex[:16]}"


class ModelListRequest(BaseModel):
    """Model discovery request for the OrcaRouter provider (server-side key)."""

    capability: str = "chat"
    required_modalities: list[str] = Field(default_factory=list)
    refresh: bool = False


# One catalog cache serves every console session: a successful live discovery
# is authoritative, and a failure keeps the bounded seed / last-known-good.
_orcarouter_catalog = ModelCatalog()


@router.post("/models/orcarouter")
async def list_orcarouter_models(body: ModelListRequest, request: Request):
    """Return the capability-filtered OrcaRouter model list for selectors.

    The provider key is read server-side from gateway.yaml; only non-secret
    model metadata is returned, so no browser ever holds the API key.
    """
    raw_key = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if authenticate(raw_key) is None:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")
    if providers.get_provider(providers.ORCAROUTER_PROVIDER) is None:
        raise HTTPException(status_code=404, detail="OrcaRouter provider is not registered")

    key = get_provider_keys().get(providers.ORCAROUTER_PROVIDER) or ""
    result = await _orcarouter_catalog.fetch(key, force=body.refresh)
    models = filter_models(result.models, capability=body.capability, required_modalities=body.required_modalities)
    return JSONResponse(
        {
            "provider": providers.ORCAROUTER_PROVIDER,
            "display_name": "OrcaRouter Cyber Inference",
            "object": "list",
            "data": models,
            "catalog_source": result.source,
            "degraded": result.degraded,
            "error": result.error,
            "model_count": len(models),
        },
        headers={"Cache-Control": "no-store"},
    )


@router.post("/chat/completions")
async def chat_completions(
    body: ChatCompletionRequest,
    request: Request,
):
    """Core proxy handler: authenticate, DLP-scan, and forward to upstream LLM."""
    request_id = _generate_request_id()
    start = time.monotonic()
    settings = get_settings()

    client_ip = getattr(request.state, "client_ip", "unknown")
    rlog = log.bind(request_id=request_id, client_ip=client_ip)

    # ── 0. Validate request ──────────────────────────────────────────────────
    if not body.messages:
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "message": "messages array must not be empty."})

    last_msg = body.messages[-1]
    last_content = last_msg.content
    if isinstance(last_content, str):
        last_empty = last_content.strip() == ""
    elif isinstance(last_content, list):
        last_empty = len(last_content) == 0
    else:
        last_empty = last_content is None

    if last_empty:
        raise HTTPException(status_code=400, detail={"error": "invalid_request", "message": "Last message content cannot be empty."})

    # ── 1. Auth ──────────────────────────────────────────────────────────────
    raw_key = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()

    key_record = authenticate(raw_key)
    if key_record is None:
        raise HTTPException(status_code=403, detail="Invalid or missing API key")

    api_key_id = mask_key(raw_key) if raw_key else "open-mode"
    rlog = rlog.bind(auth=key_record.get("name", "unknown"))

    # ── 2. Provider resolution ───────────────────────────────────────────────
    model_name = request.headers.get("x-model") or body.model or settings.default_model
    provider_name = request.headers.get("x-provider") or settings.default_provider
    body.model = model_name

    provider_spec = providers.get_provider(provider_name)
    if not provider_spec:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported provider: '{provider_name}'. Available: {', '.join(providers.list_providers())}",
        )

    # ── 3. Resolve provider API key from config.yaml ─────────────────────────
    provider_keys = get_provider_keys()
    api_key = provider_keys.get(provider_name)
    if not api_key:
        raise HTTPException(
            status_code=402,
            detail={
                "error": "no_credentials",
                "message": f"No API key configured for provider '{provider_name}'. "
                f"Add it to gateway.yaml under providers.{provider_name}.api_key",
            },
        )

    if provider_spec.is_orcarouter and api_key.startswith(ORCA_KEY_PREFIX):
        # Durable key rejected upstream: re-acquisition time, never silent retry.
        if key_state.current(api_key).needs_reauth:
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "orcarouter_reauth_required",
                    "message": "The OrcaRouter key was revoked or rejected. Run: python -m app.orcarouter_cli login",
                },
            )

    rlog.info("provider_resolved", provider=provider_name, model=model_name)

    # ── 4. DLP policy enforcement ────────────────────────────────────────────
    dlp_config = get_dlp_policy()
    pii_action = dlp_config.get("action", "redact").lower()
    score_threshold = dlp_config.get("confidence_threshold", 0.4)
    entities = dlp_config.get("entities") or None

    pii_detected = False
    violations_list: list[dict[str, Any]] = []
    dlp_latency_ms = 0
    redacted_user_prompt: str | None = None

    http_client = request.state.http_client

    should_anonymize = pii_action == "redact"

    dlp_start = time.monotonic()
    try:
        dlp_result = await dlp.process_messages(
            http_client,
            body.messages,
            entities=entities,
            score_threshold=score_threshold,
            anonymize=should_anonymize,
        )
    except dlp.PresidioError:
        rlog.error("presidio_unavailable", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail={
                "error": "security_processing_error",
                "message": "PII safety scan is temporarily unavailable. "
                "Request blocked to protect your data. Please retry shortly.",
            },
        )

    dlp_latency_ms = int((time.monotonic() - dlp_start) * 1000)
    rlog.info("dlp_scan_complete", dlp_latency_ms=dlp_latency_ms)

    # Text violations
    raw_violations = dlp_result.violations
    if raw_violations:
        pii_detected = True
        violations_list = [v.model_dump() for v in raw_violations]

        has_injection = any(v.entity_type == "PROMPT_INJECTION" for v in raw_violations)
        effective_action = "block" if has_injection else pii_action

        if effective_action == "block":
            block_msg = (
                "Request blocked: prompt injection / jailbreak attempt detected"
                if has_injection
                else "Request blocked: PII detected in prompt"
            )
            return JSONResponse(
                status_code=400,
                content=DLPBlockResponse(
                    request_id=request_id,
                    message=block_msg,
                    violations=[
                        DLPViolation(entity_type=v.entity_type, start=v.start, end=v.end, score=v.score)
                        for v in raw_violations
                    ],
                ).model_dump(),
                headers={"x-request-id": request_id},
            )

        if pii_action == "redact" and dlp_result.redacted_messages:
            rlog.info("dlp_redacting", violations=len(raw_violations))
            body.messages = dlp_result.redacted_messages
            for rm in reversed(body.messages):
                if rm.role == "user" and isinstance(rm.content, str):
                    redacted_user_prompt = rm.content
                    break

    # ── 5. Forward to upstream via LiteLLM ───────────────────────────────────
    upstream_body = body.model_dump(exclude_none=True)
    upstream_start = time.monotonic()

    # ── 5a. Streaming path ────────────────────────────────────────────────
    if body.stream:
        try:
            stream_response = await providers.forward_chat_completion_stream(
                provider_spec, api_key, dict(upstream_body),
            )
        except litellm.exceptions.Timeout:
            rlog.error("upstream_timeout", provider=provider_name, exc_info=True)
            raise HTTPException(status_code=504, detail="The AI provider took too long to respond. Please try again.")
        except litellm.exceptions.AuthenticationError:
            rlog.error("upstream_auth_error", provider=provider_name, exc_info=True)
            raise HTTPException(status_code=502, detail="Your API key was rejected by the provider. Check gateway.yaml.")
        except litellm.exceptions.BadRequestError as exc:
            rlog.error("upstream_bad_request", provider=provider_name, detail=str(exc)[:300])
            raise HTTPException(status_code=400, detail={"error": "upstream_bad_request", "message": str(exc)[:500]})
        except Exception:
            rlog.exception("upstream_unexpected_error")
            raise HTTPException(status_code=502, detail={"error": "upstream_error", "message": f"Could not complete request to '{provider_name}'. Please retry."})

        async def _sse_generator():
            try:
                async for chunk in stream_response:
                    chunk_dict = chunk.model_dump() if hasattr(chunk, "model_dump") else dict(chunk)
                    chunk_dict["model"] = model_name
                    yield f"data: {json.dumps(chunk_dict)}\n\n"
                yield "data: [DONE]\n\n"
            except Exception:
                rlog.exception("stream_chunk_error", provider=provider_name)
                yield f"data: {json.dumps({'error': {'message': 'Stream interrupted', 'type': 'server_error'}})}\n\n"
                yield "data: [DONE]\n\n"
            finally:
                _now = time.monotonic()
                rlog.info(
                    "stream_completed",
                    status_code=200,
                    provider=provider_name,
                    model=model_name,
                    latency_ms=int((_now - start) * 1000),
                    dlp_latency_ms=dlp_latency_ms,
                    pii_detected=pii_detected,
                    is_streaming=True,
                )

        return StreamingResponse(
            _sse_generator(),
            media_type="text/event-stream",
            headers={
                "x-request-id": request_id,
                "x-aisg-latency": str(int((time.monotonic() - start) * 1000)),
                "x-dlp-latency": str(dlp_latency_ms),
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    # ── 5b. Non-streaming path ────────────────────────────────────────────
    try:
        response: litellm.ModelResponse = await providers.forward_chat_completion(
            provider_spec, api_key, upstream_body,
        )
    except litellm.exceptions.Timeout:
        rlog.error("upstream_timeout", provider=provider_name, exc_info=True)
        raise HTTPException(status_code=504, detail="The AI provider took too long to respond. Please try again.")
    except litellm.exceptions.AuthenticationError:
        rlog.error("upstream_auth_error", provider=provider_name, exc_info=True)
        raise HTTPException(status_code=502, detail="Your API key was rejected by the provider. Check gateway.yaml.")
    except litellm.exceptions.BadRequestError as exc:
        rlog.error("upstream_bad_request", provider=provider_name, detail=str(exc)[:300])
        raise HTTPException(status_code=400, detail={"error": "upstream_bad_request", "message": str(exc)[:500]})
    except litellm.exceptions.RateLimitError:
        rlog.error("upstream_rate_limit", provider=provider_name)
        raise HTTPException(
            status_code=429,
            detail={"error": "rate_limit", "message": f"Provider '{provider_name}' rate-limited this request. Retry shortly."},
        )
    except Exception as exc:
        rlog.exception("upstream_unexpected_error")
        raise HTTPException(
            status_code=502,
            detail={"error": "upstream_error", "message": f"Could not complete request to '{provider_name}'. Please retry."},
        )

    upstream_latency_ms = int((time.monotonic() - upstream_start) * 1000)
    elapsed_ms = int((time.monotonic() - start) * 1000)

    usage_info = response.usage
    usage = Usage(
        prompt_tokens=usage_info.prompt_tokens or 0,
        completion_tokens=usage_info.completion_tokens or 0,
        total_tokens=usage_info.total_tokens or 0,
    )

    hub_latency_ms = max(elapsed_ms - upstream_latency_ms, 0)

    rlog.info(
        "request_completed",
        status_code=200,
        provider=provider_name,
        model=model_name,
        tokens=usage.total_tokens,
        latency_ms=elapsed_ms,
        hub_latency_ms=hub_latency_ms,
        dlp_latency_ms=dlp_latency_ms,
        pii_detected=pii_detected,
        api_key_id=api_key_id,
    )

    # ── 6. Response ──────────────────────────────────────────────────────────
    data = response.model_dump()
    data["model"] = model_name
    data["x_request_id"] = request_id

    aisg_meta: dict[str, Any] = {
        "provider_selected": provider_name,
        "latency_ms": hub_latency_ms,
        "dlp_latency_ms": dlp_latency_ms,
        "pii_detected": pii_detected,
        "upstream_latency_ms": upstream_latency_ms,
    }
    if violations_list:
        aisg_meta["dlp_action"] = "redact" if redacted_user_prompt else "detect"
        aisg_meta["violations_count"] = len(violations_list)
        aisg_meta["entity_types_detected"] = sorted({v["entity_type"] for v in violations_list})
    data["aisg_metadata"] = aisg_meta

    resp_headers = {
        "x-request-id": request_id,
        "x-aisg-latency": str(hub_latency_ms),
        "x-dlp-latency": str(dlp_latency_ms),
    }
    return JSONResponse(content=data, headers=resp_headers)
