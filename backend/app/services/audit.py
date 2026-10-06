"""Audit logging.

Every administrative action is recorded. The service strips anything that
looks like a secret before writing, so a caller cannot accidentally leak a
password or shared secret into the audit trail.
"""
from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from ..models.db import AuditLog, as_utc, utcnow

logger = logging.getLogger(__name__)

# Canonical action names.
LOGIN_SUCCESS = "LOGIN_SUCCESS"
LOGIN_FAILURE = "LOGIN_FAILURE"
LOGOUT = "LOGOUT"
USER_CREATED = "USER_CREATED"
USER_UPDATED = "USER_UPDATED"
USER_DELETED = "USER_DELETED"
USER_PASSWORD_CHANGED = "USER_PASSWORD_CHANGED"
USER_ENABLED = "USER_ENABLED"
USER_DISABLED = "USER_DISABLED"
CLIENT_CREATED = "CLIENT_CREATED"
CLIENT_UPDATED = "CLIENT_UPDATED"
CLIENT_DELETED = "CLIENT_DELETED"
CLIENT_ENABLED = "CLIENT_ENABLED"
CLIENT_DISABLED = "CLIENT_DISABLED"
CLIENT_SECRET_RESET = "CLIENT_SECRET_RESET"
GROUP_CREATED = "GROUP_CREATED"
GROUP_UPDATED = "GROUP_UPDATED"
GROUP_DELETED = "GROUP_DELETED"
CONFIG_ROLLBACK = "CONFIG_ROLLBACK"
CONFIG_VALIDATED = "CONFIG_VALIDATED"
CONFIG_VALIDATION_FAILED = "CONFIG_VALIDATION_FAILED"
FREERADIUS_RESTARTED = "FREERADIUS_RESTARTED"
FREERADIUS_RELOADED = "FREERADIUS_RELOADED"
RADIUS_TEST = "RADIUS_TEST"
BACKUP_RESTORED = "BACKUP_RESTORED"
ADMIN_CREATED = "ADMIN_CREATED"
ADMIN_UPDATED = "ADMIN_UPDATED"
ADMIN_PASSWORD_RESET = "ADMIN_PASSWORD_RESET"
ADMIN_DEACTIVATED = "ADMIN_DEACTIVATED"
ADMIN_ACTIVATED = "ADMIN_ACTIVATED"

#: Keys whose values must never be persisted.
_SECRET_KEYS = re.compile(
    r"(pass(word)?|secret|shared_?secret|token|key_hash|password_hash|credential)",
    re.IGNORECASE,
)


def redact(value: Any) -> Any:
    """Recursively replace secret-looking values with ``'***'``."""
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            out[k] = "***" if _SECRET_KEYS.search(str(k)) else redact(v)
        return out
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, datetime):
        return as_utc(value).isoformat()
    return value


def record(
    db: Session | None,
    action: str,
    administrator: str,
    *,
    object_type: str | None = None,
    object_id: str | None = None,
    source_ip: str | None = None,
    success: bool = True,
    detail: dict[str, Any] | None = None,
) -> AuditLog | None:
    """Append an audit entry. Commits immediately - the trail must survive.

    ``db`` may be ``None`` (CLI and test callers). The log line is still
    emitted so the action is never silently untraceable, but no row is
    written.
    """
    safe_detail = json.dumps(redact(detail), default=str) if detail else None
    logger.info(
        "audit %s by %s from %s success=%s detail=%s",
        action,
        administrator,
        source_ip,
        success,
        safe_detail,
    )
    if db is None:
        return None
    entry = AuditLog(
        timestamp=utcnow(),
        administrator=(administrator or "unknown")[:64],
        action=action[:64],
        object_type=(object_type or None),
        object_id=(str(object_id)[:128] if object_id is not None else None),
        source_ip=(source_ip or None),
        success=success,
        detail=safe_detail,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def to_dict(entry: AuditLog) -> dict:
    return {
        "id": entry.id,
        "timestamp": as_utc(entry.timestamp).isoformat(),
        "administrator": entry.administrator,
        "action": entry.action,
        "object_type": entry.object_type,
        "object_id": entry.object_id,
        "source_ip": entry.source_ip,
        "success": entry.success,
        "detail": entry.detail,
    }