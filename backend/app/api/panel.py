"""Dashboard, accounting, radius test, service, backups and audit endpoints."""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..models.db import AuditLog, Administrator, as_utc
from .deps import require_role
from ..schemas.api import OkResponse, RadiusTestRequest, RadiusTestResult, ValidationOut
from ..services import accounting, audit, dashboard, radius_test, service
from ..services.auth import client_ip, current_admin
from ..services.backups import BackupStore
from ..services.config_tx import ConfigTransaction

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["panel"])


def _client_entry(name: str):
    """Look up one client in the live clients.conf.

    Returns ``None`` when the file cannot be read or the client is absent, so
    the caller can turn that into a 404 instead of a 500.
    """
    from ..freeradius import paths
    from ..freeradius.clients_parser import parse_clients

    try:
        doc = parse_clients(Path(paths.CLIENTS_FILE).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("could not read clients.conf for radius test: %s", exc)
        return None
    return doc.unique_find(name)


# -- dashboard ---------------------------------------------------------
@router.get("/dashboard")
async def get_dashboard(admin: Administrator = Depends(current_admin)) -> dict:
    return await dashboard.build_dashboard()


@router.get("/dashboard/ping")
async def ping() -> dict:
    return {"ok": True}


# -- accounting --------------------------------------------------------
@router.get("/accounting")
def get_accounting(
    limit: int = Query(default=100, ge=1, le=1000),
    admin: Administrator = Depends(current_admin),
) -> dict:
    return accounting.list_sessions(limit=limit)


# -- radius test -------------------------------------------------------
@router.post("/radius/test", response_model=RadiusTestResult)
async def run_radius_test(
    payload: RadiusTestRequest,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    secret = payload.secret
    if not secret:
        # Resolve the shared secret from a configured client so the browser
        # never has to carry one. The value is used here and never returned.
        if not payload.client:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="provide a client name or a secret",
            )
        entry = _client_entry(payload.client)
        if entry is None:
            raise HTTPException(
                status.HTTP_404_NOT_FOUND,
                detail=f"no RADIUS client named {payload.client!r}",
            )
        if not entry.has_secret:
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail=f"client {payload.client!r} has no secret set",
            )
        secret = entry.directive("secret").value

    return await radius_test.run_test(
        username=payload.username,
        password=payload.password,
        server=payload.server,
        secret=secret,
        port=payload.port,
        timeout=payload.timeout,
        administrator=admin.username,
        source_ip=client_ip(request),
        db=db,
    )


# -- service -----------------------------------------------------------
@router.get("/service")
async def get_service(admin: Administrator = Depends(current_admin)) -> dict:
    status_data = await service.get_status()
    info = service.server_info()
    return {"service": status_data, "server": info}


@router.get("/service/validate", response_model=ValidationOut)
async def validate_config(admin: Administrator = Depends(current_admin)) -> dict:
    validation = await service.validate()
    return {**validation.as_dict(), "summary": validation.summary}


@router.post("/service/restart", response_model=OkResponse)
async def restart_service(
    request: Request,
    admin: Administrator = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    result = await service.restart(
        administrator=admin.username, source_ip=client_ip(request), db=db
    )
    return OkResponse(ok=True, message="FreeRADIUS restarted", detail=result)


@router.post("/service/reload", response_model=OkResponse)
async def reload_service(
    request: Request,
    admin: Administrator = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    result = await service.reload(
        administrator=admin.username, source_ip=client_ip(request), db=db
    )
    return OkResponse(ok=True, message="FreeRADIUS reloaded", detail=result)


@router.get("/service/log")
async def service_log(admin: Administrator = Depends(current_admin)) -> dict:
    lines = await service.recent_log(lines=200)
    return {"lines": lines}


# -- backups -----------------------------------------------------------
@router.get("/backups")
def list_backups(
    limit: int = Query(default=50, ge=1, le=500),
    admin: Administrator = Depends(current_admin),
) -> dict:
    store = BackupStore()
    metas = store.list(limit=limit)
    return {
        "backups": [
            {**m.as_dict(), "changed_files": list(m.files.keys())} for m in metas
        ],
        "count": len(metas),
    }


@router.get("/backups/{backup_id}")
def get_backup(backup_id: str, admin: Administrator = Depends(current_admin)) -> dict:
    store = BackupStore()
    meta = store.get(backup_id)
    diffs = store.diff(meta)
    return {
        "backup": meta.as_dict(),
        "diff": diffs,
        "changed": any(d["changed"] for d in diffs),
    }


@router.post("/backups/{backup_id}/rollback", response_model=OkResponse)
async def rollback_backup(
    backup_id: str,
    request: Request,
    admin: Administrator = Depends(require_role("admin")),
    db: Session = Depends(get_db),
) -> dict:
    tx = ConfigTransaction()
    meta, validation = await tx.rollback(
        backup_id, administrator=admin.username, source_ip=client_ip(request)
    )
    audit.record(
        db,
        audit.CONFIG_ROLLBACK,
        admin.username,
        object_type="backup",
        object_id=backup_id,
        source_ip=client_ip(request),
        detail={"files": list(meta.files.keys())},
    )
    return OkResponse(
        ok=True,
        message=f"Restored backup {backup_id}",
        detail={"validation": validation.as_dict()},
    )


# -- audit -------------------------------------------------------------
@router.get("/audit")
def list_audit(
    limit: int = Query(default=100, ge=1, le=1000),
    action: str | None = Query(default=None, max_length=64),
    administrator: str | None = Query(default=None, max_length=64),
    success: bool | None = Query(default=None),
    db: Session = Depends(get_db),
    admin: Administrator = Depends(current_admin),
) -> dict:
    stmt = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if administrator:
        stmt = stmt.where(AuditLog.administrator == administrator)
    if success is not None:
        stmt = stmt.where(AuditLog.success == success)

    rows = db.execute(stmt).scalars().all()
    return {"entries": [audit.to_dict(r) for r in rows], "count": len(rows)}


# -- settings ----------------------------------------------------------
@router.get("/settings")
def get_settings_info(admin: Administrator = Depends(current_admin)) -> dict:
    from ..core.config import get_settings
    from ..freeradius import paths

    s = get_settings()
    return {
        "environment": s.environment,
        "docs_enabled": s.enable_docs,
        "session_timeout_seconds": s.session_ttl_seconds,
        "idle_timeout_seconds": s.session_idle_timeout_seconds,
        "cookie_secure": s.cookie_secure,
        "database": s.database_url.split("://", 1)[0],
        "raddb_dir": str(paths.RADDB_DIR),
        "managed_files": paths.describe_managed_files(),
        "backup_dir": str(paths.BACKUP_DIR),
        "log_dir": str(paths.LOG_DIR),
        "audit_logging": True,
    }