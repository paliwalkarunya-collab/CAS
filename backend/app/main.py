"""
CAS-SE FastAPI Application

This is the main application factory. CAS-SE exposes REST API endpoints
consumed by the organization's own application layer. It does NOT replace
the organization's application -- it is a governance middleware.

Security invariants enforced here:
  - All secrets remain server-side; none appear in responses or logs.
  - CORS origins configured through environment variables.
  - Request size limits enforced at middleware level.
  - All sensitive routes require JWT + OPA evaluation.
"""

from __future__ import annotations

import logging
import time
from collections.abc import AsyncGenerator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import access, audit, auth, envelopes, health, keys, ml_jobs, policies, search
from app.core.config import get_settings

logger = logging.getLogger("cas_se")

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Application startup and shutdown lifecycle."""
    logger.info("CAS-SE middleware starting up -- environment: %s", settings.environment)
    # Future: initialise DB connection pool, OPA warmup, adapter health checks
    yield
    logger.info("CAS-SE middleware shutting down")


def create_app() -> FastAPI:
    app = FastAPI(
        title="CAS-SE API",
        version=settings.app_version,
        description=(
            "Context-Aware, Searchable, Split-Key Data Envelope -- "
            "Privacy-preserving data-governance middleware for sensitive ML datasets."
        ),
        openapi_url="/openapi.json" if settings.environment != "production" else None,
        docs_url="/docs" if settings.environment != "production" else None,
        redoc_url="/redoc" if settings.environment != "production" else None,
        lifespan=lifespan,
    )

    # Adapter instances are initialized lazily on their first use and then
    # retained on app.state. This keeps import-time side effects out of client
    # applications and test tooling, while still preventing any fallback to an
    # unconfigured development adapter.
    app.state.cas_storage_adapter = None
    app.state.cas_key_service = None
    app.state.cas_identity_adapter = None

    # ------------------------------------------------------------------
    # Rate Limiting
    # ------------------------------------------------------------------
    from slowapi import _rate_limit_exceeded_handler
    from slowapi.errors import RateLimitExceeded

    from app.core.rate_limit import limiter

    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # CORS
    # ------------------------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
    )

    # ------------------------------------------------------------------
    # Request size limit middleware
    # ------------------------------------------------------------------
    @app.middleware("http")
    async def limit_upload_size(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method in ("POST", "PUT", "PATCH"):
            content_length = request.headers.get("content-length")
            if content_length is not None:
                try:
                    request_size = int(content_length)
                except ValueError:
                    return JSONResponse(
                        status_code=400, content={"detail": "Invalid Content-Length"}
                    )
                if request_size > settings.max_upload_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Request body too large"},
                    )
            elif request.headers.get("transfer-encoding", "").lower() == "chunked":
                body = await request.body()
                if len(body) > settings.max_upload_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": "Request body too large"},
                    )
        return await call_next(request)

    # ------------------------------------------------------------------
    # Request timing (logged, not returned in response)
    # ------------------------------------------------------------------
    @app.middleware("http")
    async def log_request_duration(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        start = time.monotonic()
        response: Response = await call_next(request)
        duration_ms = (time.monotonic() - start) * 1000
        logger.debug(
            "CAS-SE %s %s -> %d (%.1fms)",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
        )
        return response

    # ------------------------------------------------------------------
    # Routers
    # ------------------------------------------------------------------
    app.include_router(health.router, tags=["Health"])
    app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
    app.include_router(envelopes.router, prefix="/envelopes", tags=["Envelopes"])
    app.include_router(search.router, prefix="/search", tags=["Protected Search"])
    app.include_router(access.router, prefix="/access-request", tags=["Access Control"])
    app.include_router(ml_jobs.router, prefix="/ml-jobs", tags=["ML Jobs"])
    app.include_router(audit.router, prefix="/audit", tags=["Audit"])
    app.include_router(audit.anomalies_router, prefix="/anomalies", tags=["Anomalies"])
    app.include_router(policies.router, prefix="/policies", tags=["Policies"])
    app.include_router(keys.router, prefix="/keys", tags=["Key Management"])

    return app


app = create_app()
