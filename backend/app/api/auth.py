"""Authentication endpoints."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.orm import Session

from ..core.config import get_settings
from ..core.db import get_db
from ..models.db import Administrator, Session as SessionModel, as_utc
from ..schemas.api import (
    AdministratorOut,
    ChangePasswordRequest,
    LoginRequest,
    LoginResponse,
    OkResponse,
)
from ..security.passwords import PasswordPolicyError, hash_password, verify_password
from ..services import audit
from ..services.auth import (
    AuthError,
    authenticate,
    client_ip,
    create_session,
    current_admin,
    destroy_session,
    require_session,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])


def _admin_out(admin: Administrator) -> AdministratorOut:
    return AdministratorOut(
        username=admin.username,
        full_name=admin.full_name,
        role=admin.role,
        last_login_at=as_utc(admin.last_login_at).isoformat() if admin.last_login_at else None,
    )


@router.post("/login", response_model=LoginResponse)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> LoginResponse:
    settings = get_settings()
    ip = client_ip(request)

    admin = authenticate(db, payload.username, payload.password, settings, ip)
    _, csrf = create_session(db, admin, response, request)

    return LoginResponse(
        administrator=_admin_out(admin),
        csrf_token=csrf,
        session_expires_in=settings.session_ttl_seconds,
    )


@router.post("/logout", response_model=OkResponse)
def logout(
    request: Request,
    response: Response,
    session: SessionModel = Depends(require_session),
    db: Session = Depends(get_db),
) -> OkResponse:
    audit.record(
        db,
        audit.LOGOUT,
        session.administrator.username,
        source_ip=client_ip(request),
    )
    destroy_session(db, request, response)
    return OkResponse(ok=True, message="Signed out")


@router.get("/me", response_model=AdministratorOut)
def me(admin: Administrator = Depends(current_admin)) -> AdministratorOut:
    return _admin_out(admin)


@router.post("/change-password", response_model=OkResponse)
def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    admin: Administrator = Depends(current_admin),
    db: Session = Depends(get_db),
) -> OkResponse:
    if not verify_password(admin.password_hash, payload.current_password):
        audit.record(
            db, audit.LOGIN_FAILURE, admin.username, source_ip=client_ip(request),
            success=False, detail={"reason": "password change with wrong current password"},
        )
        raise AuthError("Current password is incorrect")

    try:
        admin.password_hash = hash_password(payload.new_password)
    except PasswordPolicyError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    db.commit()
    audit.record(
        db, "ADMIN_PASSWORD_CHANGED", admin.username,
        source_ip=client_ip(request), detail={"self_service": True},
    )
    return OkResponse(ok=True, message="Password updated")