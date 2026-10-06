"""RADIUS user management, backed by the ``users`` file parser."""
from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path

from ..freeradius import paths
from ..freeradius.users_parser import (
    PASSWORD_ATTRIBUTES,
    UserEntry,
    parse_users,
)
from .config_tx import ConfigError, ConfigTransaction
from .audit import (
    USER_CREATED,
    USER_DELETED,
    USER_DISABLED,
    USER_ENABLED,
    USER_PASSWORD_CHANGED,
    USER_UPDATED,
    record,
)

logger = logging.getLogger(__name__)

#: FreeRADIUS allows up to 253 characters; we restrict to a safe subset.
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,62}$")

#: Privilege levels offered by the UI for Cisco devices.
CISCO_PRIVILEGES = (1, 5, 15)

#: Characters that would break the file grammar or invite injection.
_FORBIDDEN_IN_USERNAME = set(' \t\r\n"\'\\;,=:{}$()[]#*/')


class UserValidationError(ValueError):
    pass


def validate_username(username: str) -> str:
    if not username or not username.strip():
        raise UserValidationError("Username is required")
    username = username.strip()
    if username == "DEFAULT":
        raise UserValidationError("'DEFAULT' is a reserved entry and cannot be managed")
    if _FORBIDDEN_IN_USERNAME & set(username):
        raise UserValidationError("Username contains characters that are not permitted")
    if not USERNAME_RE.match(username):
        raise UserValidationError(
            "Username must start with a letter or digit and contain only "
            "letters, digits, dot, underscore, @ or hyphen (max 63 chars)"
        )
    return username


def validate_privilege(level: int | None) -> int | None:
    if level is None:
        return None
    if level not in CISCO_PRIVILEGES:
        raise UserValidationError(
            f"Cisco privilege level must be one of {', '.join(map(str, CISCO_PRIVILEGES))}"
        )
    return level


class UserService:
    def __init__(self, tx: ConfigTransaction | None = None) -> None:
        self.tx = tx or ConfigTransaction()

    @property
    def path(self) -> Path:
        return paths.USERS_FILE

    # -- reading ---------------------------------------------------------
    def _read(self) -> str:
        path = self.path
        if not path.exists():
            return ""
        return path.read_text("utf-8", "replace")

    def list_users(self) -> list[dict]:
        doc = parse_users(self._read())
        seen: dict[str, dict] = {}
        duplicates: dict[str, int] = {}
        for entry in doc.users:
            duplicates[entry.username] = duplicates.get(entry.username, 0) + 1
            if entry.username not in seen:
                seen[entry.username] = _to_dict(entry)
        for name, count in duplicates.items():
            if count > 1:
                seen[name]["duplicate_entries"] = count
        return sorted(seen.values(), key=lambda u: u["username"].lower())

    def get_user(self, username: str) -> dict | None:
        for item in self.list_users():
            if item["username"] == username:
                return item
        return None

    # -- writing ---------------------------------------------------------
    async def create_user(
        self,
        *,
        username: str,
        password: str,
        cisco_privilege: int | None = None,
        administrator: str,
        source_ip: str | None = None,
        enabled: bool = True,
        db=None,
    ) -> dict:
        username = validate_username(username)
        privilege = validate_privilege(cisco_privilege)
        if not password:
            raise UserValidationError("Password is required")

        doc = parse_users(self._read())
        if doc.unique_find(username) is not None:
            raise UserValidationError(f"User {username!r} already exists")

        entry = UserEntry(username=username)
        entry.set_password(password)
        if privilege is not None:
            entry.set_cisco_privilege(privilege)
        entry.enabled = enabled
        doc.upsert(entry)

        await self.tx.apply(
            label="users",
            path=self.path,
            new_content=doc.render(),
            operation=USER_CREATED,
            administrator=administrator,
            source_ip=source_ip,
            notes=f"created user {username}",
        )
        record(
            db,
            USER_CREATED,
            administrator,
            object_type="user",
            object_id=username,
            source_ip=source_ip,
            detail={"cisco_privilege": privilege, "enabled": enabled},
        )
        return self.get_user(username) or {}

    async def update_user(
        self,
        username: str,
        *,
        password: str | None = None,
        cisco_privilege: int | None = None,
        clear_cisco: bool = False,
        administrator: str,
        source_ip: str | None = None,
        db=None,
    ) -> dict:
        privilege = validate_privilege(cisco_privilege)
        doc = parse_users(self._read())
        matches = [e for e in doc.users if e.username == username]
        if not matches:
            raise UserValidationError(f"User {username!r} not found")

        changed: dict[str, object] = {}
        if password:
            changed["password"] = "changed"
        if clear_cisco:
            changed["cisco_privilege"] = None
        elif privilege is not None:
            changed["cisco_privilege"] = privilege

        if not changed:
            raise UserValidationError("No changes requested")

        # Apply to *every* duplicate entry. FreeRADIUS matches the first
        # usable entry, so editing only one copy of a duplicated user would
        # silently leave the old password (or old privilege) in effect.
        for entry in matches:
            if password:
                entry.set_password(password)
            if clear_cisco:
                entry.clear_cisco()
            elif privilege is not None:
                entry.set_cisco_privilege(privilege)

        changed["entries_changed"] = len(matches)
        if len(matches) > 1:
            changed["duplicate_entries"] = len(matches)

        await self.tx.apply(
            label="users",
            path=self.path,
            new_content=doc.render(),
            operation=USER_UPDATED,
            administrator=administrator,
            source_ip=source_ip,
            notes=f"updated user {username}",
        )
        record(
            db,
            USER_UPDATED,
            administrator,
            object_type="user",
            object_id=username,
            source_ip=source_ip,
            detail=changed,
        )
        return self.get_user(username) or {}

    async def set_enabled(
        self, username: str, enabled: bool, *, administrator: str, source_ip: str | None = None, db=None
    ) -> dict:
        doc = parse_users(self._read())
        matches = [e for e in doc.users if e.username == username]
        if not matches:
            raise UserValidationError(f"User {username!r} not found")

        # Every duplicate entry must be toggled, otherwise the enabled one wins.
        for entry in matches:
            entry.enabled = enabled
            entry.dirty = True
        rendered = doc.render()

        action = USER_ENABLED if enabled else USER_DISABLED
        await self.tx.apply(
            label="users",
            path=self.path,
            new_content=rendered,
            operation=action,
            administrator=administrator,
            source_ip=source_ip,
            notes=f"{'enabled' if enabled else 'disabled'} user {username}",
        )
        record(
            db,
            action,
            administrator,
            object_type="user",
            object_id=username,
            source_ip=source_ip,
            detail={"entries_changed": len(matches)},
        )
        return self.get_user(username) or {}

    async def change_password(
        self, username: str, password: str, *, administrator: str, source_ip: str | None = None, db=None
    ) -> dict:
        if not password:
            raise UserValidationError("Password is required")
        doc = parse_users(self._read())
        matches = [e for e in doc.users if e.username == username]
        if not matches:
            raise UserValidationError(f"User {username!r} not found")
        for entry in matches:
            entry.set_password(password)
        await self.tx.apply(
            label="users",
            path=self.path,
            new_content=doc.render(),
            operation=USER_PASSWORD_CHANGED,
            administrator=administrator,
            source_ip=source_ip,
            notes=f"password changed for {username}",
        )
        record(
            db,
            USER_PASSWORD_CHANGED,
            administrator,
            object_type="user",
            object_id=username,
            source_ip=source_ip,
        )
        return self.get_user(username) or {}

    async def delete_user(
        self, username: str, *, administrator: str, source_ip: str | None = None, db=None
    ) -> int:
        doc = parse_users(self._read())
        removed = doc.delete(username)
        if not removed:
            raise UserValidationError(f"User {username!r} not found")

        await self.tx.apply(
            label="users",
            path=self.path,
            new_content=doc.render(),
            operation=USER_DELETED,
            administrator=administrator,
            source_ip=source_ip,
            notes=f"deleted user {username}",
        )
        record(
            db,
            USER_DELETED,
            administrator,
            object_type="user",
            object_id=username,
            source_ip=source_ip,
            detail={"entries_removed": removed},
        )
        return removed

def _to_dict(entry: UserEntry) -> dict:
    """Serialise for the API. Never includes the stored password."""
    return {
        "username": entry.username,
        "auth_method": entry.auth_method,
        "enabled": entry.enabled,
        "status": "active" if entry.enabled else "disabled",
        "cisco_privilege": entry.cisco_privilege,
        "cisco_avpairs": entry.cisco_avpairs,
        "has_password": entry.has_password,
        "rejects": entry.rejects,
        "line_number": entry.line_number,
        "conditions": [c.render() for c in entry.conditions],
    }