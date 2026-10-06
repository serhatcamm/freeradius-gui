"""RADIUS client (NAS) management, backed by the ``clients.conf`` parser."""
from __future__ import annotations

import ipaddress
import logging
import re
from pathlib import Path

from ..freeradius import paths
from ..freeradius.clients_parser import ClientEntry, parse_clients
from ..security.passwords import generate_secret
from .audit import (
    CLIENT_CREATED,
    CLIENT_DELETED,
    CLIENT_DISABLED,
    CLIENT_ENABLED,
    CLIENT_SECRET_RESET,
    CLIENT_UPDATED,
    record,
)
from .config_tx import ConfigTransaction

logger = logging.getLogger(__name__)

CLIENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
DESCRIPTION_RE = re.compile(r"^[^#\r\n]{0,200}$")

VALID_NAS_TYPES = {
    "other",
    "cisco",
    "livingston",
    "max40xx",
    "multitech",
    "pathras",
    "patton",
    "portslave",
    "tc",
    "usrhiper",
}


class ClientValidationError(ValueError):
    pass


def validate_client_name(name: str) -> str:
    if not name or not name.strip():
        raise ClientValidationError("Client name is required")
    name = name.strip()
    if not CLIENT_NAME_RE.match(name):
        raise ClientValidationError(
            "Client name must start with a letter or digit and contain only "
            "letters, digits, dot, underscore or hyphen (max 64 chars)"
        )
    return name


def validate_address(address: str, ip_version: int = 4) -> str:
    """Validate a single host or a CIDR network using ``ipaddress``.

    A network with host bits set (``192.0.2.5/24``) is rejected rather
    than silently widened to ``192.0.2.0/24`` - quietly granting a whole
    subnet is never what the operator meant.
    """
    if not address or not address.strip():
        raise ClientValidationError("IP address is required")
    address = address.strip()

    try:
        net = ipaddress.ip_network(address, strict=True)
    except ValueError as exc:
        if "/" in address:
            # Distinguish "host bits set" from a malformed prefix.
            try:
                widened = ipaddress.ip_network(address, strict=False)
            except ValueError:
                raise ClientValidationError(f"Invalid IP address or network: {exc}") from exc
            raise ClientValidationError(
                f"{address} has host bits set. Use the network address "
                f"{widened.network_address}/{widened.prefixlen}"
            ) from exc
        raise ClientValidationError(f"Invalid IP address: {exc}") from exc

    if ip_version == 4 and net.version != 4:
        raise ClientValidationError("An IPv4 address or network is required")
    if ip_version == 6 and net.version != 6:
        raise ClientValidationError("An IPv6 address or network is required")

    # A single-host prefix (/32, /128) is normalised to the bare address.
    if net.num_addresses == 1:
        return str(net.network_address)
    return str(net)


def validate_nas_type(value: str | None) -> str:
    if not value:
        return "other"
    v = value.strip().lower()
    if v not in VALID_NAS_TYPES:
        raise ClientValidationError(
            f"nas_type must be one of: {', '.join(sorted(VALID_NAS_TYPES))}"
        )
    return v


def validate_description(value: str | None) -> str:
    if not value:
        return ""
    if not DESCRIPTION_RE.match(value):
        raise ClientValidationError(
            "Description must not contain '#' or newlines (max 200 chars)"
        )
    return value.strip()


def validate_secret(value: str) -> str:
    """Reject secrets that would break the grammar or leak via whitespace."""
    if not value or not value.strip():
        raise ClientValidationError("Shared secret is required")
    if len(value) < 16:
        raise ClientValidationError("Shared secret must be at least 16 characters")
    if len(value) > 128:
        raise ClientValidationError("Shared secret must be at most 128 characters")
    if any(ch in value for ch in '\r\n"#,;'):
        raise ClientValidationError("Shared secret contains characters that are not permitted")
    return value


class ClientService:
    def __init__(self, tx: ConfigTransaction | None = None) -> None:
        self.tx = tx or ConfigTransaction()

    @property
    def path(self) -> Path:
        return paths.CLIENTS_FILE

    def _read(self) -> str:
        path = self.path
        return path.read_text("utf-8", "replace") if path.exists() else ""

    # -- reading ---------------------------------------------------------
    def list_clients(self) -> list[dict]:
        doc = parse_clients(self._read())
        out = []
        for entry in doc.clients:
            out.append(_to_dict(entry))
        return sorted(out, key=lambda c: c["name"].lower())

    def get_client(self, name: str) -> dict | None:
        for item in self.list_clients():
            if item["name"] == name:
                return item
        return None

    # -- writing ---------------------------------------------------------
    async def create_client(
        self,
        *,
        name: str,
        address: str,
        secret: str | None = None,
        nas_type: str = "other",
        description: str = "",
        ip_version: int = 4,
        require_message_authenticator: bool = True,
        administrator: str,
        source_ip: str | None = None,
        db=None,
    ) -> dict:
        name = validate_client_name(name)
        address = validate_address(address, ip_version)
        nas_type = validate_nas_type(nas_type)
        description = validate_description(description)

        # Generate a strong secret unless one was supplied.
        generated = False
        if secret:
            secret = validate_secret(secret)
        else:
            secret = generate_secret()
            generated = True

        doc = parse_clients(self._read())
        if doc.unique_find(name) is not None:
            raise ClientValidationError(f"Client {name!r} already exists")

        self._check_overlap(doc, name, address, ip_version)

        entry = ClientEntry(name=name)
        key = "ipv6addr" if ip_version == 6 else "ipaddr"
        entry.set_directive(key, address)
        entry.set_secret(secret)
        entry.set_directive("nas_type", nas_type)
        if description:
            entry.set_directive("description", description)
        if require_message_authenticator:
            # Protects against the BlastRADIUS attack (CVE-2024-3596).
            entry.set_directive("require_message_authenticator", "true")
        entry.enabled = True
        entry.managed = True
        doc.upsert(entry)

        await self.tx.apply(
            label="clients",
            path=self.path,
            new_content=doc.render(),
            operation=CLIENT_CREATED,
            administrator=administrator,
            source_ip=source_ip,
            notes=f"created client {name}",
        )
        record(
            db,
            CLIENT_CREATED,
            administrator,
            object_type="client",
            object_id=name,
            source_ip=source_ip,
            detail={
                "address": address,
                "nas_type": nas_type,
                "secret_generated": generated,
            },
        )
        result = self.get_client(name) or {}
        # The plaintext secret is returned exactly once, at creation time.
        result["generated_secret"] = secret if generated else None
        return result

    async def update_client(
        self,
        name: str,
        *,
        address: str | None = None,
        nas_type: str | None = None,
        description: str | None = None,
        ip_version: int = 4,
        require_message_authenticator: bool | None = None,
        administrator: str,
        source_ip: str | None = None,
        db=None,
    ) -> dict:
        doc = parse_clients(self._read())
        entry = doc.unique_find(name)
        if entry is None:
            raise ClientValidationError(f"Client {name!r} not found")

        changed: dict[str, object] = {}
        if address:
            address = validate_address(address, ip_version)
            self._check_overlap(doc, name, address, ip_version, skip=name)
            entry.set_directive("ipv6addr" if ip_version == 6 else "ipaddr", address)
            changed["address"] = address
        if nas_type is not None:
            entry.set_directive("nas_type", validate_nas_type(nas_type))
            changed["nas_type"] = nas_type
        if description is not None:
            entry.set_directive("description", validate_description(description))
            changed["description"] = description
        if require_message_authenticator is not None:
            entry.set_directive(
                "require_message_authenticator",
                "true" if require_message_authenticator else "false",
            )
            changed["require_message_authenticator"] = require_message_authenticator

        if not changed:
            raise ClientValidationError("No changes requested")

        doc.upsert(entry)
        await self.tx.apply(
            label="clients",
            path=self.path,
            new_content=doc.render(),
            operation=CLIENT_UPDATED,
            administrator=administrator,
            source_ip=source_ip,
            notes=f"updated client {name}",
        )
        record(
            db,
            CLIENT_UPDATED,
            administrator,
            object_type="client",
            object_id=name,
            source_ip=source_ip,
            detail=changed,
        )
        return self.get_client(name) or {}

    async def reset_secret(
        self, name: str, *, administrator: str, source_ip: str | None = None, db=None
    ) -> str:
        doc = parse_clients(self._read())
        entry = doc.unique_find(name)
        if entry is None:
            raise ClientValidationError(f"Client {name!r} not found")

        secret = generate_secret()
        entry.set_secret(secret)
        doc.upsert(entry)
        await self.tx.apply(
            label="clients",
            path=self.path,
            new_content=doc.render(),
            operation=CLIENT_SECRET_RESET,
            administrator=administrator,
            source_ip=source_ip,
            notes=f"secret reset for {name}",
        )
        record(
            db,
            CLIENT_SECRET_RESET,
            administrator,
            object_type="client",
            object_id=name,
            source_ip=source_ip,
            detail={"secret_rotated": True},
        )
        return secret

    async def set_enabled(
        self, name: str, enabled: bool, *, administrator: str, source_ip: str | None = None, db=None
    ) -> dict:
        doc = parse_clients(self._read())
        entry = doc.unique_find(name)
        if entry is None:
            raise ClientValidationError(f"Client {name!r} not found")

        entry.enabled = enabled
        entry.dirty = True
        action = CLIENT_ENABLED if enabled else CLIENT_DISABLED
        await self.tx.apply(
            label="clients",
            path=self.path,
            new_content=doc.render(),
            operation=action,
            administrator=administrator,
            source_ip=source_ip,
            notes=f"{'enabled' if enabled else 'disabled'} client {name}",
        )
        record(
            db,
            action,
            administrator,
            object_type="client",
            object_id=name,
            source_ip=source_ip,
        )
        return self.get_client(name) or {}

    async def delete_client(
        self, name: str, *, administrator: str, source_ip: str | None = None, db=None
    ) -> int:
        doc = parse_clients(self._read())
        removed = doc.delete(name)
        if not removed:
            raise ClientValidationError(f"Client {name!r} not found")

        await self.tx.apply(
            label="clients",
            path=self.path,
            new_content=doc.render(),
            operation=CLIENT_DELETED,
            administrator=administrator,
            source_ip=source_ip,
            notes=f"deleted client {name}",
        )
        record(
            db,
            CLIENT_DELETED,
            administrator,
            object_type="client",
            object_id=name,
            source_ip=source_ip,
        )
        return removed

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _check_overlap(
        doc, name: str, address: str, ip_version: int, skip: str | None = None
    ) -> None:
        """Reject an address that is already claimed by another client.

        FreeRADIUS picks the most specific match, so an overlapping entry is
        almost always a configuration mistake.
        """
        try:
            new_net = ipaddress.ip_network(address, strict=False)
        except ValueError as exc:
            raise ClientValidationError(f"Invalid address: {exc}") from exc
        if new_net.version != ip_version:
            raise ClientValidationError("Address family does not match")

        for other in doc.clients:
            if other.name == skip or other.name == name:
                continue
            other_net = other.network
            if other_net is None or other_net.version != new_net.version:
                continue
            if new_net.overlaps(other_net):
                raise ClientValidationError(
                    f"Address {address} overlaps existing client "
                    f"{other.name!r} ({other.address})"
                )


def _to_dict(entry: ClientEntry) -> dict:
    """Serialise for the API. The shared secret is never included."""
    return {
        "name": entry.name,
        "address": entry.address,
        "address_kind": entry.address_kind,
        "has_secret": entry.has_secret,
        "nas_type": entry.nas_type,
        "description": entry.description,
        "enabled": entry.enabled,
        "status": "active" if entry.enabled else "disabled",
        "require_message_authenticator": entry.require_message_authenticator,
        "line_number": entry.line_number,
    }