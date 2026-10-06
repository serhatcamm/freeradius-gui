"""Administrator management endpoints.

Admin-only, because these endpoints change who can administer the panel. Every
mutation records an audit entry and invalidates affected sessions when it has
to take effect immediately.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..models.db import Administrator, Session as SessionModel, as_utc
from ..schemas.api import (
    AdministratorCreate,
    AdministratorList,
    AdministratorPasswordReset,
    AdministratorRecord,
    AdministratorUpdate,
    OkResponse,
)
from ..services import admins as admins_service
from ..services import audit
from ..services.auth import client_ip, current_admin
from ..api.deps import require_role

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/administrators", tags=["administrators"])


def _iso(value) -> str | None:
    return as_utc(value).isoformat() if value else None


def _record(db: Session, admin: Administrator, is_self: bool) -> AdministratorRecord:
    session_count = db.execute(
        select(func.count())
        .select_from(SessionModel)
        .where(SessionModel.administrator_id == admin.id)
    ).scalar_one()

    return AdministratorRecord(
        username=admin.username,
        full_name=admin.full_name,
        role=admin.role,
        is_active=bool(admin.is_active),
        created_at=_iso(admin.created_at),
        last_login_at=_iso(admin.last_login_at),
        last_login_ip=admin.last_login_ip,
        failed_attempts=admin.failed_attempts or 0,
        locked_until=_iso(admin.locked_until),
        session_count=session_count,
        is_self=is_self,
    )


def _find(db: Session, username: str) -> Administrator:
    admin = db.execute(
        select(Administrator).where(Administrator.username == username)
    ).scalar_one_or_none()
    if admin is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No such administrator: {username}")
    return admin


@router.get("", response_model=AdministratorList)
def list_administrators(
    db: Session = Depends(get_db),
    actor: Administrator = Depends(require_role("admin")),
) -> AdministratorList:
    rows = admins_service.list_administrators(db)
    records = [_record(db, row, is_self=row.id == actor.id) for row in rows]
    active_admin_count = sum(1 for r in records if r.is_active and r.role == "admin")
    return AdministratorList(
        administrators=records, count=len(records), active_admin_count=active_admin_count
    )


@router.post("", response_model=AdministratorRecord, status_code=status.HTTP_201_CREATED)
def create_administrator(
    payload: AdministratorCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: Administrator = Depends(require_role("admin")),
) -> AdministratorRecord:
    try:
        admin = admins_service.create_administrator(
            db,
            actor,
            payload.username,
            payload.password,
            payload.role,
            payload.full_name,
            client_ip(request),
        )
    except admins_service.AdminError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _record(db, admin, is_self=False)


@router.patch("/{username}", response_model=AdministratorRecord)
def update_administrator(
    username: str,
    payload: AdministratorUpdate,
    request: Request,
    db: Session = Depends(get_db),
    actor: Administrator = Depends(require_role("admin")),
) -> AdministratorRecord:
    target = _find(db, username)
    try:
        admin = admins_service.update_administrator(
            db,
            actor,
            target,
            role=payload.role,
            full_name=payload.full_name,
            is_active=payload.is_active,
            source_ip=client_ip(request),
        )
    except admins_service.AdminError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return _record(db, admin, is_self=admin.id == actor.id)


@router.post("/{username}/password", response_model=OkResponse)
def reset_password(
    username: str,
    payload: AdministratorPasswordReset,
    request: Request,
    db: Session = Depends(get_db),
    actor: Administrator = Depends(require_role("admin")),
) -> OkResponse:
    target = _find(db, username)
    try:
        admins_service.reset_administrator_password(
            db, actor, target, payload.new_password, client_ip(request)
        )
    except admins_service.AdminError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    return OkResponse(
        ok=True,
        message=f"Password reset for {target.username}. Active sessions were signed out.",
    )


@router.post("/{username}/unlock", response_model=OkResponse)
def unlock(
    username: str,
    request: Request,
    db: Session = Depends(get_db),
    actor: Administrator = Depends(require_role("admin")),
) -> OkResponse:
    target = _find(db, username)
    admins_service.unlock_administrator(db, actor, target, client_ip(request))
    return OkResponse(ok=True, message=f"{target.username} unlocked")


@router.delete("/{username}", response_model=OkResponse)
def deactivate_administrator(
    username: str,
    request: Request,
    db: Session = Depends(get_db),
    actor: Administrator = Depends(require_role("admin")),
) -> OkResponse:
    """Deactivate rather than delete.

    Audit history references the username, so the row is kept and only the
    login path is closed. Deleting would also orphan that history.
    """
    target = _find(db, username)
    try:
        admins_service.update_administrator(
            db, actor, target, role=None, full_name=None, is_active=False,
            source_ip=client_ip(request),
        )
    except admins_service.AdminError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
    audit.record(
        db, audit.ADMIN_DEACTIVATED, actor.username, source_ip=client_ip(request),
        object_type="administrator", object_id=target.username, detail={"via": "delete"},
    )
    return OkResponse(ok=True, message=f"{target.username} deactivated")