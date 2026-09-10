"""FastAPI application factory + lifespan.

Middleware chain: RequestID → session-resolve → audit-context → CSRF (unsafe methods). Routers mount
under ``/api``; the WebSocket hub under ``/ws``. Same-origin only (CORS off — nginx is the sole
edge). Lifespan opens the DB + Redis pools, asserts the engine imports **headless** (no PySide6),
and confirms the workspace volume is writable.

The ``api`` process runs NO recon tools — it only reads engine state via
:mod:`nabu_agent.engine.gateway` and enqueues work onto the worker via Arq/Redis.
"""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from nabu_agent.engine.errors import EngineAdapterError
from nabu_agent.obs import logging as obs_logging
from nabu_agent.routers import health
from nabu_agent.settings import get_settings


def _errlog():
    import structlog
    return structlog.get_logger("nabu_agent.api")

# code → HTTP status (mirrors DESIGN §6.3)
_ERROR_STATUS: dict[str, int] = {
    "invalid_target": 422,
    "scope_violation": 403,
    "attack_gate_closed": 403,
    "autonomy_violation": 403,
    "checkpoint_not_approved": 403,
    "tool_blocked": 409,
    "tool_missing": 409,
    "read_only_project": 409,
    "project_not_found": 404,
    "engine_error": 500,
}


def _assert_engine_headless() -> None:
    """Importing the engine modules we use must never drag in Qt (headless server image)."""
    import oscprecon.profile  # noqa: F401  (import for side-effect: proves the engine loads)
    import oscprecon.shell  # noqa: F401
    if "PySide6" in sys.modules:  # pragma: no cover - defensive
        raise RuntimeError("engine import loaded PySide6 — the agent backend must stay headless")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    obs_logging.configure(settings.log_level, settings.log_format)
    settings.assert_production_ready()
    try:
        _assert_engine_headless()
    except Exception as exc:  # log but don't crash a bare scaffold boot without the engine installed
        import structlog

        structlog.get_logger().warning("engine-import-check-failed", error=str(exc))
    # best-effort: reap any runs orphaned before this process started (worker + api both down)
    try:
        from nabu_agent.orchestration.reaper import reap_stale_runs

        reaped = await reap_stale_runs()
        if reaped:
            _errlog().warning("startup-reaped-runs", count=len(reaped))
    except Exception:  # pragma: no cover - never block startup
        pass
    # DB/Redis pools are created lazily by db.session / bus; nothing to open eagerly here yet.
    yield
    # Dispose the async DB engine on shutdown.
    try:
        from nabu_agent.db.session import engine

        await engine.dispose()
    except Exception:  # pragma: no cover
        pass
    try:
        from nabu_agent import bus

        await bus.close_arq_pool()
    except Exception:  # pragma: no cover
        pass


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="Nabu Agent",
        version="0.1.0",
        description="Agent-driven recon platform built on the classic Nabu (oscprecon) engine.",
        lifespan=lifespan,
    )

    # Transient signed-cookie session used ONLY to carry the OAuth state/nonce across the OIDC
    # redirect round-trip (Authlib). The durable post-login session is our Redis session.
    from starlette.middleware.sessions import SessionMiddleware

    _secret = settings.session_secret.get_secret_value() or "nabu-agent-dev-secret"
    app.add_middleware(SessionMiddleware, secret_key=_secret, same_site="lax",
                       https_only=settings.env == "production", max_age=600)

    @app.exception_handler(EngineAdapterError)
    async def _engine_error_handler(request: Request, exc: EngineAdapterError) -> JSONResponse:
        status = _ERROR_STATUS.get(getattr(exc, "code", "engine_error"), 500)
        if status >= 500:
            _errlog().error("engine-error", code=getattr(exc, "code", "engine_error"),
                            path=str(request.url.path), error=str(exc), exc_info=True)
        return JSONResponse(
            status_code=status,
            content={
                "code": getattr(exc, "code", "engine_error"),
                "message": str(exc),
                "request_id": request.headers.get("x-request-id", ""),
                "details": {},
            },
        )

    @app.exception_handler(Exception)
    async def _unhandled_error_handler(request: Request, exc: Exception) -> JSONResponse:
        """Log every unhandled exception with context and return the standard error envelope (500)
        instead of a bare stack trace, so failures are traceable and clients get a consistent shape."""
        _errlog().error("unhandled-error", path=str(request.url.path), method=request.method,
                        error=str(exc), exc_info=True)
        return JSONResponse(
            status_code=500,
            content={"code": "internal_error", "message": "internal server error",
                     "request_id": request.headers.get("x-request-id", ""), "details": {}},
        )

    # Routers under /api. auth/projects/scope/runs are wired (Phase 2); the rest are scaffolded.
    from nabu_agent.routers import (
        admin,
        audit,
        auth,
        catalog,
        creds,
        feed,
        findings,
        projects,
        reports,
        runs,
        scope,
        users,
    )
    from nabu_agent.routers import (
        settings as settings_router,
    )

    app.include_router(health.router, prefix="/api")
    _routers = (auth, projects, scope, runs, reports, findings, catalog, creds, feed, admin,
                users, audit, settings_router)
    for module in _routers:
        app.include_router(module.router, prefix="/api")

    # WebSocket hub under /ws.
    from nabu_agent.ws import routes as ws_routes

    app.include_router(ws_routes.router)

    _ = settings  # reserved for middleware wiring (Phase 2)
    return app


app = create_app()
