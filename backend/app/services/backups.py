"""Configuration backups.

Every modification writes a timestamped, self-describing backup directory
before the live file is touched. A backup contains:

* ``files/`` - verbatim copies of the affected configuration files;
* ``meta.json`` - timestamp, operation, administrator, source IP, checksums.

Backups are immutable and are the source of truth for rollback.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ..freeradius import paths

META_NAME = "meta.json"
FILES_DIR = "files"

_SAFE_LABEL_RE = re.compile(r"[^A-Za-z0-9_.-]+")


class BackupError(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _sanitize(value: str) -> str:
    return _SAFE_LABEL_RE.sub("-", value)[:64] or "unknown"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class BackupMeta:
    id: str
    created_at: datetime
    operation: str
    administrator: str
    source_ip: str | None
    hostname: str
    files: dict[str, dict] = field(default_factory=dict)
    notes: str | None = None

    def as_dict(self) -> dict:
        return {
            "id": self.id,
            "created_at": self.created_at.isoformat(),
            "operation": self.operation,
            "administrator": self.administrator,
            "source_ip": self.source_ip,
            "hostname": self.hostname,
            "files": self.files,
            "notes": self.notes,
        }


class BackupStore:
    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root or paths.BACKUP_DIR)

    # -- creation --------------------------------------------------------
    def create(
        self,
        files: list[tuple[str, Path]],
        operation: str,
        administrator: str,
        source_ip: str | None = None,
        notes: str | None = None,
    ) -> BackupMeta:
        """Snapshot ``files`` (a list of ``(label, path)``)."""
        self.root.mkdir(parents=True, exist_ok=True)

        created = _now()
        backup_id = f"{created.strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
        backup_dir = self.root / backup_id
        files_dir = backup_dir / FILES_DIR
        files_dir.mkdir(parents=True, exist_ok=False)

        meta = BackupMeta(
            id=backup_id,
            created_at=created,
            operation=_sanitize(operation),
            administrator=administrator,
            source_ip=source_ip,
            hostname=os.uname().nodename,
            notes=notes,
        )

        for label, path in files:
            src = Path(path)
            entry: dict = {"path": str(src), "present": False}
            if src.exists():
                data = src.read_bytes()
                # Preserve the real file, following the users symlink.
                dest = files_dir / _sanitize(label)
                dest.write_bytes(data)
                entry |= {
                    "present": True,
                    "stored_as": dest.name,
                    "sha256": sha256_bytes(data),
                    "size": len(data),
                    "mode": src.stat().st_mode & 0o7777,
                }
            meta.files[label] = entry

        (backup_dir / META_NAME).write_text(json.dumps(meta.as_dict(), indent=2))
        return meta

    # -- listing ---------------------------------------------------------
    def _iter_meta(self) -> list[BackupMeta]:
        out: list[BackupMeta] = []
        if not self.root.exists():
            return out
        for entry in sorted(self.root.iterdir(), reverse=True):
            meta_path = entry / META_NAME
            if not entry.is_dir() or not meta_path.exists():
                continue
            try:
                data = json.loads(meta_path.read_text())
            except json.JSONDecodeError:
                continue
            out.append(
                BackupMeta(
                    id=data["id"],
                    created_at=datetime.fromisoformat(data["created_at"]),
                    operation=data.get("operation", "unknown"),
                    administrator=data.get("administrator", "unknown"),
                    source_ip=data.get("source_ip"),
                    hostname=data.get("hostname", ""),
                    files=data.get("files", {}),
                    notes=data.get("notes"),
                )
            )
        return out

    def list(self, limit: int | None = None) -> list[BackupMeta]:
        metas = self._iter_meta()
        return metas[:limit] if limit else metas

    def get(self, backup_id: str) -> BackupMeta:
        self._validate_id(backup_id)
        for meta in self._iter_meta():
            if meta.id == backup_id:
                return meta
        raise BackupError(f"backup {backup_id!r} not found")

    def read_file(self, meta: BackupMeta, label: str) -> bytes | None:
        entry = meta.files.get(label, {})
        if not entry.get("present"):
            return None
        path = self.root / meta.id / FILES_DIR / entry["stored_as"]
        if not path.exists():
            raise BackupError(f"backup payload missing for {label}")
        return path.read_bytes()

    def diff(self, meta: BackupMeta) -> list[dict]:
        """Unified diff between the backup and the current live files."""
        import difflib

        results: list[dict] = []
        for label, entry in meta.files.items():
            original = self.read_file(meta, label)
            current_path = Path(entry["path"])
            current = current_path.read_text("utf-8", "replace") if current_path.exists() else ""
            before = (original or b"").decode("utf-8", "replace")
            delta = list(
                difflib.unified_diff(
                    before.splitlines(),
                    current.splitlines(),
                    fromfile=f"backup/{label}",
                    tofile=f"current/{label}",
                    lineterm="",
                )
            )
            results.append(
                {
                    "label": label,
                    "path": entry["path"],
                    "changed": bool(delta),
                    "diff": "\n".join(delta),
                }
            )
        return results

    # -- restore ---------------------------------------------------------
    def restore_target(self, meta: BackupMeta) -> list[tuple[str, Path, bytes | None]]:
        """Return ``(label, path, content)`` triples to be written."""
        targets: list[tuple[str, Path, bytes | None]] = []
        for label, entry in meta.files.items():
            path = Path(entry["path"])
            content = self.read_file(meta, label)
            targets.append((label, path, content))
        return targets

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _validate_id(backup_id: str) -> None:
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", backup_id or ""):
            raise BackupError("invalid backup id")

    def prune(self, keep: int = 100) -> int:
        """Delete the oldest backups, keeping the newest ``keep``."""
        metas = self.list()
        removed = 0
        for meta in metas[keep:]:
            shutil.rmtree(self.root / meta.id, ignore_errors=True)
            removed += 1
        return removed


def default_store() -> BackupStore:
    return BackupStore()