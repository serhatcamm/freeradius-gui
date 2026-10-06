"""Filesystem locations and helpers for the FreeRADIUS installation.

Everything is overridable through environment variables so the parsers and
services can be unit-tested against a temporary directory.
"""
from __future__ import annotations

import os
from pathlib import Path


def _env_path(name: str, default: str) -> Path:
    return Path(os.environ.get(name, default))


#: Root of the FreeRADIUS configuration tree (3.0 even on FreeRADIUS 3.2.x).
RADDB_DIR = _env_path("FRW_RADDB_DIR", "/etc/freeradius/3.0")

#: NAS/client definitions.
CLIENTS_FILE = _env_path("FRW_CLIENTS_FILE", str(RADDB_DIR / "clients.conf"))

#: ``users`` is normally a symlink into mods-config; always follow it so we
#: edit the real file and never replace the symlink with a regular file.
USERS_FILE = _env_path("FRW_USERS_FILE", str(RADDB_DIR / "users"))

#: Accounting definitions (rlm_files style).
ACCOUNTING_FILE = _env_path(
    "FRW_ACCOUNTING_FILE", str(RADDB_DIR / "mods-config" / "files" / "accounting")
)

#: RADIUS groups. FreeRADIUS only reads this when the ``files`` module has an
#: active ``groupfile`` directive (see app/services/groups.py).
GROUPS_FILE = _env_path(
    "FRW_GROUPS_FILE", str(RADDB_DIR / "mods-config" / "files" / "groups")
)

#: Site definition that holds the virtual servers.
SITES_AVAILABLE = RADDB_DIR / "sites-available"

#: Module definitions. The linelog module's options live here.
MODS_AVAILABLE = RADDB_DIR / "mods-available"
MODS_ENABLED = RADDB_DIR / "mods-enabled"

#: Where the application stores its backups.
BACKUP_DIR = _env_path("FRW_BACKUP_DIR", "/var/lib/freeradius-web/backups")

#: Application database (SQLite now, PostgreSQL later via FRW_DATABASE_URL).
DATA_DIR = _env_path("FRW_DATA_DIR", "/var/lib/freeradius-web")

#: FreeRADIUS log directory, used for the authentication log viewer.
LOG_DIR = _env_path("FRW_LOG_DIR", "/var/log/freeradius")

#: Absolute path of the freeradius binary.
FREERADIUS_BIN = _env_path("FRW_FREERADIUS_BIN", "/usr/sbin/freeradius")

#: radtest binary, used by the authentication test page.
RADTEST_BIN = _env_path("FRW_RADTEST_BIN", "/usr/bin/radtest")

#: Files the application is allowed to modify. Anything outside this set is
#: refused by the services layer - it is the enforcement point for the
#: restrictive sudoers rules.
MANAGED_FILES = {
    "users": USERS_FILE,
    "clients": CLIENTS_FILE,
    "accounting": ACCOUNTING_FILE,
    "groups": GROUPS_FILE,
}

#: The subset of ``MANAGED_FILES`` the panel is allowed to rewrite. Every path
#: here must appear in the privileged writer's allow-list, which is the real
#: enforcement point; tests/test_write_allowlist.py keeps the two in step.
#: "accounting" is deliberately absent: it is reported in the UI but never
#: edited, so the privileged writer has no reason to accept it.
WRITABLE_KINDS = ("users", "clients", "groups")


def managed_path(kind: str) -> Path:
    """Return the managed file for ``kind`` or raise ``KeyError``."""
    return MANAGED_FILES[kind]


def describe_managed_files() -> dict[str, str]:
    return {k: str(v) for k, v in MANAGED_FILES.items()}