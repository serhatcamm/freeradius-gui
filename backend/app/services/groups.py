"""RADIUS group management, backed by the ``groups`` parser.

A group is a named bundle of attributes that users join via ``Group = name``
in ``authorize``. FreeRADIUS only consults the file when the ``files`` module
has an active ``groupfile`` directive, so :func:`groupfile_status` reports that
state and the UI surfaces it - otherwise edits here would appear to work while
having no effect on authentication.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..freeradius import paths
from ..freeradius.groups_parser import (
    DEFAULT_GROUP,
    MAX_NAME_LENGTH,
    GroupEntry,
    load_groups,
    parse_groups,
)
from ..freeradius.users_parser import Assignment
from .audit import (
    GROUP_CREATED,
    GROUP_DELETED,
    GROUP_UPDATED,
    record,
)
from .config_tx import ConfigTransaction

logger = logging.getLogger(__name__)

#: Same shape the users/clients validators accept, so group names can be used
#: as the right-hand side of "Group = <name>" without further escaping.
GROUP_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")

#: Attribute keys the panel will write into a group. An open-ended key set
#: would let a group redefine Auth-Type, Filename or similar and change how
#: authentication is processed rather than merely what it returns.
SAFE_ATTRIBUTE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,62}$")

#: Keys that must never be set from a group definition.
FORBIDDEN_KEYS = {
    "auth-type",
    "filename",
    "usersfile",
    "acctusersfile",
    "preproxy_usersfile",
    "groupfile",
    "cleartext-password",
    "ltmpassword",
    "ntpassword",
}


class GroupValidationError(ValueError):
    pass


def validate_group_name(name: str) -> str:
    if not name or not name.strip():
        raise GroupValidationError("Group name is required")
    name = name.strip()
    if name == DEFAULT_GROUP:
        raise GroupValidationError(
            "DEFAULT is managed implicitly and cannot be edited from here"
        )
    if len(name) > MAX_NAME_LENGTH:
        raise GroupValidationError(f"Group name must be at most {MAX_NAME_LENGTH} characters")
    if not GROUP_NAME_RE.match(name):
        raise GroupValidationError(
            "Group name must start with a letter or digit and contain only "
            "letters, digits, dot, underscore or hyphen"
        )
    return name


def validate_attribute_key(key: str) -> str:
    """Reject anything that could change control flow, not just data."""
    if not key or not key.strip():
        raise GroupValidationError("Attribute name is required")
    key = key.strip()
    if not SAFE_ATTRIBUTE_RE.match(key):
        raise GroupValidationError(
            f"{key!r} is not a valid attribute name (letters, digits, hyphen)"
        )
    if key.lower() in FORBIDDEN_KEYS:
        raise GroupValidationError(
            f"{key!r} cannot be set on a group; it changes how authentication "
            f"is processed rather than what it returns"
        )
    return key


def validate_attribute_value(value: str) -> str:
    """Group values are written into one comma-separated line.

    Comma, quote, backslash and newline would all corrupt the file grammar, so
    they are rejected outright instead of being escaped - an escaped value
    would be reinterpreted by FreeRADIUS differently than the panel displays.
    """
    if value is None:
        return ""
    if len(value) > 253:
        raise GroupValidationError("Attribute value must be at most 253 characters")
    bad = [ch for ch in value if ch in ',\n\r"\\']
    if bad:
        raise GroupValidationError(
            "Attribute value must not contain comma, quote, backslash or newline"
        )
    if value.strip() == "":
        raise GroupValidationError("Attribute value must not be empty")
    return value


def groupfile_status() -> dict:
    """Report whether FreeRADIUS will actually read the groups file.

    Returns ``enabled`` plus the module file inspected, so the UI can explain
    *why* groups are inert instead of just failing to apply them.
    """
    module = paths.MODS_AVAILABLE / "files"
    detail: dict[str, object] = {
        "enabled": False,
        "module_file": str(module),
        "groups_file": str(paths.GROUPS_FILE),
        "groups_file_exists": paths.GROUPS_FILE.exists(),
        "directive": None,
    }
    try:
        text = module.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        detail["error"] = str(exc)
        return detail

    # Only a directive inside the files { ... } section counts.
    inside = False
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"^files\s*\{", stripped):
            inside = True
            continue
        if inside and stripped.startswith("}"):
            break
        if inside and re.match(r"^groupfile\s*=", stripped):
            detail["enabled"] = True
            detail["directive"] = stripped
            break
    return detail


class GroupService:
    def __init__(self, tx: ConfigTransaction | None = None) -> None:
        self.tx = tx or ConfigTransaction()

    @property
    def path(self) -> Path:
        return paths.GROUPS_FILE

    def _read(self) -> str:
        path = self.path
        return path.read_text("utf-8", "replace") if path.exists() else ""

    # -- reading ---------------------------------------------------------
    def list_groups(self, with_members: bool = False) -> list[dict]:
        """List groups.

        ``with_members`` re-reads the users file per group, so the dashboard
        can show counts cheaply while a detail view can show names. Off by
        default because membership is a cross-file lookup and N+1 file reads
        are not free.
        """
        doc = parse_groups(self._read())
        out = sorted(
            (entry.to_dict() for entry in doc.groups),
            key=lambda g: (not g["is_default"], str(g["name"]).lower()),
        )
        if with_members:
            for group in out:
                group["members"] = self.members(group["name"])
        return out

    def get_group(self, name: str) -> dict | None:
        for item in self.list_groups():
            if item["name"] == name:
                return item
        return None

    def members(self, name: str) -> list[str]:
        """Users whose authorize entry sets ``Group = <name>``.

        Read from the users file rather than stored, because the groups file
        holds no back-reference and duplicating membership would let the two
        disagree.

        The ``Group`` assignment can land in any of the parser's attribute
        lists depending on how the entry is written (the users parser sorts
        continuation assignments into attributes/conditions/reply), so all
        three are scanned rather than assuming one.
        """
        from ..freeradius.users_parser import parse_users

        try:
            text = paths.USERS_FILE.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        found: list[str] = []
        for entry in parse_users(text).entries:
            for group in (*entry.attributes, *entry.conditions, *entry.reply):
                if group.key == "Group" and group.unquoted_value == name:
                    found.append(entry.username)
                    break
        return sorted(found)

    # -- writing ---------------------------------------------------------
    def _build_entry(self, name: str, attributes: list) -> GroupEntry:
        """Turn request attributes into a group entry.

        Accepts either pydantic models (from the API) or plain dicts (from
        tests and the CLI) so the service does not depend on the transport
        layer's types.
        """
        built: list[Assignment] = []
        reply_indices: set[int] = set()
        for item in attributes:
            if isinstance(item, dict):
                raw_key = item.get("key", "")
                raw_value = item.get("value", "")
                is_reply = bool(item.get("reply", False))
            else:
                raw_key = getattr(item, "key", "")
                raw_value = getattr(item, "value", "")
                is_reply = bool(getattr(item, "reply", False))

            key = validate_attribute_key(str(raw_key))
            value = validate_attribute_value(str(raw_value))
            if is_reply:
                reply_indices.add(len(built))
            built.append(Assignment(key=key, op="=", value=f'"{value}"', quoted=True))
        return GroupEntry(name=name, attributes=built, reply_indices=reply_indices)

    async def create_group(
        self,
        *,
        name: str,
        attributes: list[dict],
        administrator: str,
        source_ip: str | None = None,
        db=None,
    ) -> dict:
        name = validate_group_name(name)
        doc = parse_groups(self._read())
        if doc.unique_find(name) is not None:
            raise GroupValidationError(f"Group {name!r} already exists")

        entry = self._build_entry(name, attributes)
        doc.upsert(entry)
        await self.tx.apply(
            label="groups",
            path=self.path,
            new_content=doc.render(),
            operation=GROUP_CREATED,
            administrator=administrator,
            source_ip=source_ip,
            notes=f"created group {name}",
        )
        record(
            db,
            GROUP_CREATED,
            administrator,
            object_type="group",
            object_id=name,
            source_ip=source_ip,
            detail={"attributes": len(entry.attributes)},
        )
        return self.get_group(name) or {}

    async def update_group(
        self,
        name: str,
        *,
        attributes: list[dict],
        administrator: str,
        source_ip: str | None = None,
        db=None,
    ) -> dict:
        doc = parse_groups(self._read())
        existing = doc.unique_find(name)
        if existing is None:
            raise GroupValidationError(f"Group {name!r} not found")
        if name == DEFAULT_GROUP:
            raise GroupValidationError("DEFAULT is managed implicitly")

        entry = self._build_entry(name, attributes)
        doc.upsert(entry)
        await self.tx.apply(
            label="groups",
            path=self.path,
            new_content=doc.render(),
            operation=GROUP_UPDATED,
            administrator=administrator,
            source_ip=source_ip,
            notes=f"updated group {name}",
        )
        record(
            db,
            GROUP_UPDATED,
            administrator,
            object_type="group",
            object_id=name,
            source_ip=source_ip,
            detail={"attributes": len(entry.attributes)},
        )
        return self.get_group(name) or {}

    async def delete_group(
        self, name: str, *, administrator: str, source_ip: str | None = None, db=None
    ) -> int:
        if name == DEFAULT_GROUP:
            raise GroupValidationError("DEFAULT is managed implicitly")
        doc = parse_groups(self._read())
        removed = doc.delete(name)
        if not removed:
            raise GroupValidationError(f"Group {name!r} not found")

        await self.tx.apply(
            label="groups",
            path=self.path,
            new_content=doc.render(),
            operation=GROUP_DELETED,
            administrator=administrator,
            source_ip=source_ip,
            notes=f"deleted group {name}",
        )
        record(
            db,
            GROUP_DELETED,
            administrator,
            object_type="group",
            object_id=name,
            source_ip=source_ip,
            detail={"orphaned_members": self.members(name)},
        )
        return removed


def load_document(path: Path | None = None):
    return load_groups(path or paths.GROUPS_FILE)