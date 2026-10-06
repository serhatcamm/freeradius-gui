"""RADIUS group endpoints.

Reading is open to any authenticated account; writing needs the operator role,
matching the clients endpoints.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..models.db import Administrator
from .deps import require_role
from ..schemas.api import GroupCreate, GroupOut, GroupUpdate
from ..services.auth import client_ip, current_admin
from ..services.groups import GroupService, groupfile_status

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/groups", tags=["groups"])

service = GroupService()


@router.get("", response_model=list[GroupOut])
def list_groups(admin: Administrator = Depends(current_admin)) -> list[dict]:
    return service.list_groups()


@router.get("/status", response_model=dict)
def groups_status(admin: Administrator = Depends(current_admin)) -> dict:
    """Whether FreeRADIUS will actually read the groups file.

    Separate from the list so the UI can show the warning without having to
    infer it from an empty list.
    """
    status_info = groupfile_status()
    # Membership drives the "Members" column, so include it here rather than
    # making the UI issue one request per row.
    status_info["groups"] = service.list_groups(with_members=True)
    return status_info


@router.get("/{name}", response_model=GroupOut)
def get_group(name: str, admin: Administrator = Depends(current_admin)) -> dict:
    group = service.get_group(name)
    if group is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Group {name!r} not found")
    group["members"] = service.members(name)
    return group


@router.post("", response_model=GroupOut, status_code=201)
async def create_group(
    payload: GroupCreate,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    return await service.create_group(
        name=payload.name,
        attributes=payload.attributes,
        administrator=admin.username,
        source_ip=client_ip(request),
        db=db,
    )


@router.patch("/{name}", response_model=GroupOut)
async def update_group(
    name: str,
    payload: GroupUpdate,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    return await service.update_group(
        name,
        attributes=payload.attributes,
        administrator=admin.username,
        source_ip=client_ip(request),
        db=db,
    )


@router.delete("/{name}")
async def delete_group(
    name: str,
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    removed = await service.delete_group(
        name, administrator=admin.username, source_ip=client_ip(request), db=db
    )
    return {"ok": True, "name": name, "entries_removed": removed}