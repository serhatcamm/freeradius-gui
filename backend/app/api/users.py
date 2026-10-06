"""RADIUS user management endpoints."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..models.db import Administrator
from .deps import require_role
from ..schemas.api import UserCreate, UserOut, UserUpdate
from ..services.auth import client_ip, current_admin
from ..services.users import UserService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/users", tags=["users"])

service = UserService()


@router.get("", response_model=list[UserOut])
def list_users(admin: Administrator = Depends(current_admin)) -> list[dict]:
    return service.list_users()


@router.get("/{username}", response_model=UserOut)
def get_user(username: str, admin: Administrator = Depends(current_admin)) -> dict:
    user = service.get_user(username)
    if user is None:
        from fastapi import HTTPException, status

        raise HTTPException(status.HTTP_404_NOT_FOUND, f"User {username!r} not found")
    return user


@router.post("", response_model=UserOut, status_code=201)
async def create_user(
    payload: UserCreate,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    return await service.create_user(
        username=payload.username,
        password=payload.password,
        cisco_privilege=payload.cisco_privilege,
        enabled=payload.enabled,
        administrator=admin.username,
        source_ip=client_ip(request),
        db=db,
    )


@router.patch("/{username}", response_model=UserOut)
async def update_user(
    username: str,
    payload: UserUpdate,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    return await service.update_user(
        username,
        password=payload.password,
        cisco_privilege=payload.cisco_privilege,
        clear_cisco=payload.clear_cisco,
        administrator=admin.username,
        source_ip=client_ip(request),
        db=db,
    )


@router.post("/{username}/enable", response_model=UserOut)
async def enable_user(
    username: str,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    return await service.set_enabled(
        username, True, administrator=admin.username,
        source_ip=client_ip(request), db=db,
    )


@router.post("/{username}/disable", response_model=UserOut)
async def disable_user(
    username: str,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    return await service.set_enabled(
        username, False, administrator=admin.username,
        source_ip=client_ip(request), db=db,
    )


@router.post("/{username}/password", response_model=UserOut)
async def change_user_password(
    username: str,
    payload: dict,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    password = payload.get("password")
    if not password:
        from fastapi import HTTPException, status

        raise HTTPException(status.HTTP_400_BAD_REQUEST, "password is required")
    return await service.change_password(
        username, password, administrator=admin.username,
        source_ip=client_ip(request), db=db,
    )


@router.delete("/{username}")
async def delete_user(
    username: str,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    removed = await service.delete_user(
        username, administrator=admin.username,
        source_ip=client_ip(request), db=db,
    )
    return {"ok": True, "username": username, "entries_removed": removed}