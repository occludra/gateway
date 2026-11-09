"""AISG Gateway — self-hosted AI security proxy.

Core features:
- PII detection & redaction via Presidio
- Prompt injection blocking
- Multi-provider LLM routing via LiteLLM
- API key auth via config.yaml
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from contextlib import asynccontextmanager

import httpx
import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

from .config import get_settings
from .log_utils import log_scrubber, mask_key

settings = get_settings()
_log_level = getattr(logging, settings.log_level.upper(), logging.INFO)

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        log_scrubber,
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(_log_level),
    logger_factory=structlog.PrintLoggerFactory(),
)

_log = structlog.get_logger()
_http_client: httpx.AsyncClient | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage the shared httpx client lifecycle (startup/shutdown)."""
    global _http_client
    _log.info("startup_begin", log_level=settings.log_level)
    _http_client = httpx.AsyncClient(timeout=10.0)
    _log.info("startup_http_client_ready")
    yield
    await _http_client.aclose()


app = FastAPI(
    title="AISG — AI Security Gateway",
    description="Self-hosted AI security proxy with PII detection, prompt injection blocking, and multi-provider routing.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """Return a generic 500 JSON response for uncaught exceptions."""
    _log.error("unhandled_exception", error=str(exc)[:500], exc_info=exc, path=str(request.url.path))
    return JSONResponse(
        status_code=500,
        content={"error": "internal_server_error", "message": "An unexpected error occurred. Please retry."},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Return a 422 JSON response with sanitized Pydantic validation details."""
    _log.warn("validation_error", errors=str(exc.errors())[:500], path=str(request.url.path))
    safe_details = [{"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")} for e in exc.errors()]
    return JSONResponse(
        status_code=422,
        content={"error": "validation_error", "message": "Invalid request format.", "details": safe_details},
    )


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins.split(","),
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["x-request-id", "x-aisg-latency", "x-dlp-latency"],
)


class PayloadGuardMiddleware(BaseHTTPMiddleware):
    """Reject requests whose Content-Length exceeds the configured max body size."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        content_length = request.headers.get("content-length")
        max_bytes = settings.max_body_bytes
        if content_length:
            try:
                cl = int(content_length)
            except ValueError:
                return JSONResponse(status_code=400, content={"error": "invalid_content_length"})
            if cl > max_bytes:
                return JSONResponse(
                    status_code=413,
                    content={"error": "payload_too_large", "message": f"Request body exceeds {max_bytes // (1024 * 1024)}MB limit."},
                )
        return await call_next(request)


app.add_middleware(PayloadGuardMiddleware)


class _TokenBucket:
    """In-memory token-bucket rate limiter."""

    __slots__ = ("capacity", "tokens", "refill_rate", "last_refill")

    def __init__(self, capacity: int, refill_rate: float):
        self.capacity = capacity
        self.tokens = float(capacity)
        self.refill_rate = refill_rate
        self.last_refill = time.monotonic()

    def consume(self) -> bool:
        """Refill tokens based on elapsed time and attempt to consume one."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False


_rate_buckets: dict[str, _TokenBucket] = defaultdict(
    lambda: _TokenBucket(capacity=settings.rate_limit_rps, refill_rate=settings.rate_limit_rps)
)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Per-API-key token-bucket rate limiter for /v1/ endpoints."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if not request.url.path.startswith("/v1/"):
            return await call_next(request)
        auth = request.headers.get("authorization", "")
        key = auth.removeprefix("Bearer ").strip()[:32] or "anonymous"
        bucket = _rate_buckets[key]
        if not bucket.consume():
            return JSONResponse(
                status_code=429,
                content={"error": "rate_limit_exceeded", "message": f"Too many requests. Limit: {settings.rate_limit_rps}/sec."},
                headers={"Retry-After": "1"},
            )
        return await call_next(request)


app.add_middleware(RateLimitMiddleware)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Attach the shared httpx client and resolved client IP to request.state."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        request.state.http_client = _http_client
        xff = request.headers.get("x-forwarded-for", "")
        request.state.client_ip = xff.split(",")[0].strip() if xff else (
            request.client.host if request.client else "unknown"
        )
        return await call_next(request)


app.add_middleware(RequestContextMiddleware)

from . import dev_mode  # noqa: E402
from .routers import health, proxy  # noqa: E402

app.include_router(health.router)
app.include_router(proxy.router)
# Operator-only credential entry points (API key + Connect with OrcaRouter).
# Mounted by default because the route handlers themselves run on the gateway's
# own Bearer-key auth; set AISG_DEV_MODE=false to unmount them entirely.
app.include_router(dev_mode.router)
