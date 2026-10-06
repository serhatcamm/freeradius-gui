"""RADIUS client (NAS) endpoints."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..models.db import Administrator
from .deps import require_role
from ..schemas.api import ClientCreate, ClientOut, ClientUpdate, SecretResponse
from ..services.auth import client_ip, current_admin
from ..services.clients import ClientService

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/clients", tags=["clients"])

service = ClientService()


@router.get("", response_model=list[ClientOut])
def list_clients(admin: Administrator = Depends(current_admin)) -> list[dict]:
    return service.list_clients()


@router.get("/{name}", response_model=ClientOut)
def get_client(name: str, admin: Administrator = Depends(current_admin)) -> dict:
    client = service.get_client(name)
    if client is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Client {name!r} not found")
    return client


@router.post("", response_model=ClientOut, status_code=201)
async def create_client(
    payload: ClientCreate,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    return await service.create_client(
        name=payload.name,
        address=payload.address,
        secret=payload.secret,
        nas_type=payload.nas_type,
        description=payload.description,
        ip_version=payload.ip_version,
        require_message_authenticator=payload.require_message_authenticator,
        administrator=admin.username,
        source_ip=client_ip(request),
        db=db,
    )


@router.patch("/{name}", response_model=ClientOut)
async def update_client(
    name: str,
    payload: ClientUpdate,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    return await service.update_client(
        name,
        address=payload.address,
        nas_type=payload.nas_type,
        description=payload.description,
        ip_version=payload.ip_version,
        require_message_authenticator=payload.require_message_authenticator,
        administrator=admin.username,
        source_ip=client_ip(request),
        db=db,
    )


@router.post("/{name}/reset-secret", response_model=SecretResponse)
async def reset_secret(
    name: str,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> SecretResponse:
    secret = await service.reset_secret(
        name, administrator=admin.username, source_ip=client_ip(request), db=db
    )
    return SecretResponse(name=name, secret=secret)


@router.post("/{name}/enable", response_model=ClientOut)
async def enable_client(
    name: str,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    return await service.set_enabled(
        name, True, administrator=admin.username,
        source_ip=client_ip(request), db=db,
    )


@router.post("/{name}/disable", response_model=ClientOut)
async def disable_client(
    name: str,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    return await service.set_enabled(
        name, False, administrator=admin.username,
        source_ip=client_ip(request), db=db,
    )


@router.delete("/{name}")
async def delete_client(
    name: str,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    removed = await service.delete_client(
        name, administrator=admin.username, source_ip=client_ip(request), db=db
    )
    return {"ok": True, "name": name, "entries_removed": removed}