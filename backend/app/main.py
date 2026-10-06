"""FreeRADIUS Web Management Panel - FastAPI application."""
from __future__ import annotations

import logging
import logging.handlers
import os
import sys
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .api import active_directory as ad_router
from .api import admins as admins_router
from .api import alerts as alerts_router
from .api import auth as auth_router
from .api import clients as clients_router
from .api import groups as groups_router
from .api import deps
from .api import logs as logs_router
from .api import panel as panel_router
from .api import users as users_router
from .core.config import get_settings
from .core.db import init_db
from .services.auth import AuthError
from .services.backups import BackupError
from .services.config_tx import ConfigValidationError, PermissionDeniedError
from .freeradius.runner import CommandFailed, CommandNotAllowed

logging.basicConfig(
    level=os.environ.get("FRW_LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("freeradius-web")

settings = get_settings()

STATIC_DIR = Path(os.environ.get("FRW_STATIC_DIR", "/opt/freeradius-web/static"))


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        init_db()
        logger.info("started in %s mode", settings.environment)
    except Exception:
        logger.exception("database initialisation failed")
        raise
    yield
    logger.info("shutting down")


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
    description=(
        "Management API for a local FreeRADIUS 3.x installation. "
        "All configuration changes are backed up, validated with "
        "`freeradius -XC` and rolled back automatically on failure."
    ),
    docs_url="/api/docs" if settings.enable_docs else None,
    redoc_url="/api/redoc" if settings.enable_docs else None,
    openapi_url="/api/openapi.json" if settings.enable_docs else None,
    lifespan=lifespan,
)

# The SPA is served from the same origin as the API, so CORS is not needed in
# production. This is only for local development with the Vite dev server.
if settings.debug:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault(
        "Permissions-Policy", "camera=(), microphone=(), geolocation=()"
    )
    if settings.is_production:
        response.headers.setdefault(
            "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
        )
    return response


# Domain error translation - never leak a stack trace.
for exc_type in (
    AuthError,
    ConfigValidationError,
    PermissionDeniedError,
    CommandNotAllowed,
    CommandFailed,
    BackupError,
    ValueError,
):
    app.add_exception_handler(exc_type, deps.api_error_handler)


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    return await deps.api_error_handler(request, exc)


@app.get("/health", tags=["system"])
async def health() -> dict:
    """Unauthenticated liveness probe used by systemd and nginx."""
    return {"status": "ok"}


@app.get("/api/health", tags=["system"])
async def api_health() -> dict:
    from .core.db import get_engine
    from sqlalchemy import text

    db_ok = True
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception:
        logger.exception("database health check failed")
        db_ok = False

    return {"status": "ok", "database": db_ok, "version": app.version}


# -- API routers -------------------------------------------------------
app.include_router(auth_router.router)
app.include_router(admins_router.router)
app.include_router(alerts_router.router)
app.include_router(users_router.router)
app.include_router(clients_router.router)
app.include_router(groups_router.router)
app.include_router(ad_router.router)
app.include_router(logs_router.router)
app.include_router(panel_router.router)


# -- static frontend ---------------------------------------------------
if STATIC_DIR.exists():
    assets = STATIC_DIR / "assets"
    if assets.exists():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/", include_in_schema=False)
    async def index() -> FileResponse:
        return FileResponse(STATIC_DIR / "index.html")

    @app.get("/{path:path}", include_in_schema=False)
    async def spa_fallback(path: str) -> FileResponse:
        """Serve SPA routes; API paths are never shadowed."""
        if path.startswith("api/"):
            return JSONResponse({"error": "Not found"}, status_code=status.HTTP_404_NOT_FOUND)

        # Resolve before checking, so an encoded or backslashed traversal
        # ("%2e%2e", "..\\") cannot escape the bundle directory. Comparing the
        # *resolved* path against the resolved root is what matters: string
        # prefix checks are defeated by both encodings and by a sibling
        # directory sharing a name prefix.
        try:
            candidate = (STATIC_DIR / path).resolve(strict=True)
        except (OSError, RuntimeError):
            return FileResponse(STATIC_DIR / "index.html")

        if candidate.is_file() and candidate.is_relative_to(STATIC_DIR.resolve()):
            return FileResponse(candidate)
        return FileResponse(STATIC_DIR / "index.html")

else:  # pragma: no cover - dev convenience

    @app.get("/", include_in_schema=False)
    async def missing_ui() -> JSONResponse:
        return JSONResponse(
            {
                "app": settings.app_name,
                "status": "running",
                "message": (
                    "Frontend bundle not found. Build it with "
                    "`npm ci && npm run build` and set FRW_STATIC_DIR."
                ),
                "docs": "/api/docs" if settings.enable_docs else "disabled",
            },
            status_code=status.HTTP_200_OK,
        )