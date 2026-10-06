"""The configuration transaction.

Every change to a managed FreeRADIUS file follows one sequence::

    BACKUP -> MODIFY -> `freeradius -XC` -> APPLY

If validation fails the previous content is restored automatically and the
caller receives a :class:`ConfigValidationError`. Nothing is ever left in a
state that FreeRADIUS refuses to start.
"""
from __future__ import annotations

import logging
import os
import shutil
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..freeradius.validate import ValidationResult, validate_config
from .backups import BackupMeta, BackupStore, default_store

logger = logging.getLogger(__name__)


class ConfigError(RuntimeError):
    """Base class for configuration failures."""


class ConfigValidationError(ConfigError):
    """Raised when FreeRADIUS rejects the new configuration."""

    def __init__(self, validation: ValidationResult, rolled_back: bool):
        self.validation = validation
        self.rolled_back = rolled_back
        super().__init__(validation.summary)


class PermissionDeniedError(ConfigError):
    """The process may not write the requested file."""


class ConfigWriter(Protocol):
    """Abstraction over a privileged write, so it can be faked in tests."""

    async def write(self, path: Path, content: bytes, mode: int | None = None) -> None: ...


class LocalAtomicWriter:
    """Writes files directly, preserving ownership and mode.

    Used when the process already has write access (tests, or when the
    ``freeradius-web`` user owns the file). Writes go to a temporary file in
    the same directory and are moved into place with ``os.replace`` so a
    reader never observes a partial file.
    """

    async def write(self, path: Path, content: bytes, mode: int | None = None) -> None:
        path = Path(path)

        # /etc/freeradius/3.0/users is a *symlink* into
        # mods-config/files/authorize. Writing to the link path with
        # os.replace() would destroy the symlink and leave Debian's
        # mods-enabled/files symlink dangling. Always write through to the
        # real target so the link survives untouched.
        target = path
        if path.is_symlink():
            target = path.resolve(strict=True)

        directory = target.parent

        existing_mode = mode
        if existing_mode is None and target.exists():
            existing_mode = target.stat().st_mode & 0o7777
        if existing_mode is None:
            existing_mode = 0o640

        try:
            fd, tmp_name = tempfile.mkstemp(dir=directory, prefix=f".{target.name}.", suffix=".tmp")
            try:
                with os.fdopen(fd, "wb") as fh:
                    fh.write(content)
                    fh.flush()
                    os.fsync(fh.fileno())
                os.chmod(tmp_name, existing_mode)
                if os.geteuid() == 0 and target.exists():
                    st = target.stat()
                    try:
                        os.chown(tmp_name, st.st_uid, st.st_gid)
                    except PermissionError:
                        pass
                os.replace(tmp_name, target)
                # Durably record the rename itself.
                dir_fd = os.open(directory, os.O_RDONLY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except Exception:
                Path(tmp_name).unlink(missing_ok=True)
                raise
        except PermissionError as exc:
            raise PermissionDeniedError(f"cannot write {path}: {exc}") from exc


@dataclass
class TransactionResult:
    backup: BackupMeta
    validation: ValidationResult
    changed: bool
    path: Path


class ConfigTransaction:
    """Runs the backup/validate/apply sequence for a managed file."""

    def __init__(
        self,
        store: BackupStore | None = None,
        writer: ConfigWriter | None = None,
    ) -> None:
        self.store = store or default_store()
        if writer is None:
            # Root writes directly (tests/development); unprivileged processes
            # delegate to the root-owned helper over sudo, so the web account
            # never needs write access to /etc/freeradius.
            from .privileged_writer import default_writer

            writer = default_writer()
        self.writer = writer

    async def apply(
        self,
        label: str,
        path: Path,
        new_content: str,
        operation: str,
        administrator: str,
        source_ip: str | None = None,
        notes: str | None = None,
        validate: bool = True,
    ) -> TransactionResult:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)

        original_bytes = path.read_bytes() if path.exists() else b""
        new_bytes = new_content.encode("utf-8")

        if original_bytes == new_bytes:
            validation = await validate_config() if validate else ValidationResult(True, 0)
            logger.info("no-op change for %s", label)
            return TransactionResult(
                backup=None,  # type: ignore[arg-type]
                validation=validation,
                changed=False,
                path=path,
            )

        # 1. BACKUP
        backup = self.store.create(
            files=[(label, path)],
            operation=operation,
            administrator=administrator,
            source_ip=source_ip,
            notes=notes,
        )
        logger.info("backup %s created for %s", backup.id, label)

        # 2. MODIFY
        await self.writer.write(path, new_bytes)

        # 3. VALIDATE
        if validate:
            validation = await validate_config()
        else:
            validation = ValidationResult(True, 0)

        # 4. APPLY or ROLLBACK
        if not validation.ok:
            logger.error("validation failed, rolling back %s", label)
            rolled_back = True
            try:
                if original_bytes:
                    await self.writer.write(path, original_bytes)
                else:
                    path.unlink(missing_ok=True)
            except Exception:  # pragma: no cover - restore failure is fatal
                logger.exception("CRITICAL: rollback failed for %s", path)
                rolled_back = False
            raise ConfigValidationError(validation, rolled_back=rolled_back)

        return TransactionResult(
            backup=backup, validation=validation, changed=True, path=path
        )

    async def apply_group(
        self,
        entries: Sequence[tuple[str, Path, str]],
        operation: str,
        administrator: str,
        source_ip: str | None = None,
        notes: str | None = None,
    ) -> list[TransactionResult]:
        """Apply several files as one logical change.

        Some features touch more than one file - enabling request logging edits
        both ``mods-available/linelog`` and ``sites-available/default``. If the
        second file fails, the first must not be left applied, otherwise the
        panel reports a half-finished change and the operator has to reason
        about which file is authoritative.

        Each file still gets its own backup, so the individual steps remain
        individually recoverable; this only adds compensation so the *group* is
        all-or-nothing. Compensation writes the original bytes straight back
        through the writer rather than going through :meth:`apply` again: the
        backup for each step already exists, and re-running the full sequence
        would create a second round of backups for a recovery.
        """
        originals: list[tuple[Path, bytes]] = []
        results: list[TransactionResult] = []

        try:
            for label, path, new_content in entries:
                path = Path(path)
                originals.append((path, path.read_bytes() if path.exists() else b""))
                results.append(
                    await self.apply(
                        label=label,
                        path=path,
                        new_content=new_content,
                        operation=operation,
                        administrator=administrator,
                        source_ip=source_ip,
                        notes=notes,
                    )
                )
            return results
        except ConfigValidationError as exc:
            # Re-read before restoring: the failed step may already have rolled
            # itself back to its original content.
            restored = await self._compensate(originals)
            raise ConfigValidationError(exc.validation, rolled_back=restored) from exc
        except Exception:
            restored = await self._compensate(originals)
            if not restored:
                logger.critical(
                    "compensating restore failed for %s", [str(path) for path, _ in originals]
                )
            raise

    async def _compensate(self, originals: Sequence[tuple[Path, bytes]]) -> bool:
        """Restore every captured file to its pre-group content."""
        ok = True
        for path, original in originals:
            try:
                current = path.read_bytes() if path.exists() else b""
                if current == original:
                    continue
                if original:
                    await self.writer.write(path, original)
                else:
                    path.unlink(missing_ok=True)
            except Exception:
                logger.exception("compensating restore failed for %s", path)
                ok = False
        return ok

    async def rollback(
        self,
        backup_id: str,
        administrator: str,
        source_ip: str | None = None,
    ) -> tuple[BackupMeta, ValidationResult]:
        """Restore a backup, validating before the restore is accepted."""
        meta = self.store.get(backup_id)

        # Validate the *restored* content before committing to it: stage each
        # file into its real location, check, and roll forward only if valid.
        staged: list[tuple[str, Path, bytes | None, bytes]] = []
        for label, path, content in self.store.restore_target(meta):
            current = path.read_bytes() if path.exists() else b""
            staged.append((label, path, content, current))

        # Pre-validate by writing a copy of the restore into a scratch raddb
        # is not possible in general, so we validate after restoring and roll
        # forward to the pre-rollback state if the restore is invalid.
        pre_backup = self.store.create(
            files=[(label, path) for label, path, _, _ in staged],
            operation="PRE_ROLLBACK_SNAPSHOT",
            administrator=administrator,
            source_ip=source_ip,
            notes=f"snapshot taken before rolling back to {backup_id}",
        )

        for label, path, content, _ in staged:
            if content is None:
                path.unlink(missing_ok=True)
            else:
                await self.writer.write(path, content)

        validation = await validate_config()
        if not validation.ok:
            logger.error("rollback content is invalid; restoring pre-rollback state")
            for label, path, _, current in staged:
                if current:
                    await self.writer.write(path, current)
                else:
                    path.unlink(missing_ok=True)
            raise ConfigValidationError(validation, rolled_back=True)

        return meta, validation