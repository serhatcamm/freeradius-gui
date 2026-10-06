"""Administrator lifecycle.

Two invariants make a web panel unrecoverable if broken, so they are enforced
here rather than in the API layer:

  - an administrator may not remove their own privileges or disable their own
    account, which would lock the panel out with no local fallback;
  - the last active administrator may not be deactivated or demoted.

Local administrators stay usable when Active Directory is unreachable, so
break-glass access never depends on the directory.
"""
from __future__ import annotations

import re
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models.db import Administrator, Session as SessionModel, utcnow
from ..security.passwords import PasswordPolicyError, hash_password
from . import audit

#: Roles an administrator may hold. Mirrors deps.ROLE_RANK.
ROLES = ("viewer", "operator", "admin")

_USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")


class AdminError(ValueError):
    """Refused administrator change, surfaced to the client as HTTP 400."""


def list_administrators(db: Session) -> list[Administrator]:
    return list(
        db.execute(select(Administrator).order_by(Administrator.username)).scalars()
    )


def _other_active_admins(db: Session, admin: Administrator) -> int:
    """Count *active administrators holding the admin role* other than ``admin``.

    Role matters: a viewer cannot keep the panel reachable, so counting every
    active account would let the last real admin be demoted.
    """
    return db.execute(
        select(func.count())
        .select_from(Administrator)
        .where(
            Administrator.is_active.is_(True),
            Administrator.role == "admin",
            Administrator.id != admin.id,
        )
    ).scalar_one()


def create_administrator(
    db: Session,
    actor: Administrator,
    username: str,
    password: str,
    role: str,
    full_name: str | None,
    source_ip: str | None,
) -> Administrator:
    username = (username or "").strip()
    if not _USERNAME_RE.match(username):
        raise AdminError(
            "Username must be 2-64 characters, start alphanumeric, and use only "
            "letters, digits, dot, underscore or hyphen."
        )
    if role not in ROLES:
        raise AdminError(f"Role must be one of: {', '.join(ROLES)}.")

    existing = db.execute(
        select(Administrator).where(Administrator.username == username)
    ).scalar_one_or_none()
    if existing is not None:
        raise AdminError(f"Administrator {username} already exists.")

    # Hash first: a rejected password must not leave a half-created row.
    try:
        password_hash = hash_password(password)
    except PasswordPolicyError as exc:
        raise AdminError(str(exc)) from exc

    admin = Administrator(
        username=username,
        password_hash=password_hash,
        full_name=(full_name or None),
        role=role,
        is_active=True,
    )
    db.add(admin)
    db.commit()
    db.refresh(admin)

    audit.record(
        db, audit.ADMIN_CREATED, actor.username, source_ip=source_ip,
        object_type="administrator", object_id=username, detail={"role": role},
    )
    return admin


def update_administrator(
    db: Session,
    actor: Administrator,
    target: Administrator,
    *,
    role: str | None,
    full_name: str | None,
    is_active: bool | None,
    source_ip: str | None,
) -> Administrator:
    if role is not None and role not in ROLES:
        raise AdminError(f"Role must be one of: {', '.join(ROLES)}.")

    is_self = target.id == actor.id
    demoting_self = is_self and role is not None and role != target.role
    disabling_self = is_self and is_active is False

    if demoting_self:
        raise AdminError("You cannot change your own role.")
    if disabling_self:
        raise AdminError("You cannot disable your own account.")

    # Losing the last usable admin would strand the panel. For a change made by
    # another administrator the actor's own account satisfies this, so today the
    # branch only fires for callers that reach the service without being an
    # active admin (break-glass or delegated paths). It stays as the invariant
    # that makes those paths safe rather than trusting them.
    losing_admin = target.is_active and (
        is_active is False or (role is not None and role != "admin")
    )
    if losing_admin and _other_active_admins(db, target) == 0:
        raise AdminError(
            "This is the last active administrator with admin rights. Create another "
            "administrator first."
        )

    before = {"role": target.role, "full_name": target.full_name, "is_active": target.is_active}

    if role is not None:
        target.role = role
    if full_name is not None:
        target.full_name = full_name or None
    if is_active is not None:
        target.is_active = is_active
        if is_active:
            target.locked_until = None
            target.failed_attempts = 0

    db.commit()
    db.refresh(target)

    if is_active is not None and is_active != before["is_active"]:
        action = audit.ADMIN_ACTIVATED if is_active else audit.ADMIN_DEACTIVATED
        audit.record(
            db, action, actor.username, source_ip=source_ip,
            object_type="administrator", object_id=target.username,
            success=True, detail={"self": is_self},
        )

    # Deactivating must take effect immediately, not at session expiry.
    if is_active is False:
        _drop_sessions(db, target)

    audit.record(
        db, audit.ADMIN_UPDATED, actor.username, source_ip=source_ip,
        object_type="administrator", object_id=target.username,
        detail={"before": before, "after": {"role": target.role, "is_active": target.is_active}},
    )
    return target


def reset_administrator_password(
    db: Session,
    actor: Administrator,
    target: Administrator,
    new_password: str,
    source_ip: str | None,
) -> None:
    if target.id == actor.id:
        raise AdminError(
            "Use the self-service password change to update your own password."
        )

    try:
        target.password_hash = hash_password(new_password)
    except PasswordPolicyError as exc:
        raise AdminError(str(exc)) from exc

    target.failed_attempts = 0
    target.locked_until = None
    db.commit()

    # Force re-authentication everywhere so the old password cannot survive.
    _drop_sessions(db, target)

    audit.record(
        db, audit.ADMIN_PASSWORD_RESET, actor.username, source_ip=source_ip,
        object_type="administrator", object_id=target.username,
    )


def unlock_administrator(
    db: Session,
    actor: Administrator,
    target: Administrator,
    source_ip: str | None,
) -> None:
    target.failed_attempts = 0
    target.locked_until = None
    db.commit()
    audit.record(
        db, audit.ADMIN_UPDATED, actor.username, source_ip=source_ip,
        object_type="administrator", object_id=target.username,
        detail={"unlocked": True},
    )


def _drop_sessions(db: Session, admin: Administrator) -> None:
    rows = db.execute(
        select(SessionModel).where(SessionModel.administrator_id == admin.id)
    ).scalars()
    for row in rows:
        db.delete(row)
    db.commit()


def is_locked(admin: Administrator) -> bool:
    """True while an explicit lockout window is still in the future."""
    return admin.locked_until is not None and admin.locked_until > utcnow()