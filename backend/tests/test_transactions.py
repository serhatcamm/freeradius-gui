"""ConfigTransaction tests: backups, atomic writes, validation, rollback."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from app.services import config_tx
from app.services.backups import BackupStore
from app.services.config_tx import ConfigTransaction, LocalAtomicWriter


@pytest.fixture
def store(tmp_path: Path) -> BackupStore:
    return BackupStore(tmp_path / "backups")


@pytest.fixture
def target(tmp_path: Path) -> Path:
    p = tmp_path / "raddb" / "authorize"
    p.parent.mkdir()
    p.write_text('bob\tCleartext-Password := "bobpass"\n', encoding="utf-8")
    return p


def ok_result():
    from app.freeradius.validate import ValidationResult

    return ValidationResult(ok=True, returncode=0, output="Configuration OK")


def bad_result():
    from app.freeradius.validate import ConfigIssue, ValidationResult

    return ValidationResult(
        ok=False,
        returncode=1,
        issues=[
            ConfigIssue(
                severity="error",
                message="Failed to parse the configuration file",
                file="authorize",
            )
        ],
        output="ERROR: Failed to parse the configuration file",
    )


@pytest.fixture
def validating(store, monkeypatch):
    """Patch the validator so tests never invoke the real freeradius binary."""
    state = {"result": ok_result()}

    async def fake_validate(binary=None):
        return state["result"]

    monkeypatch.setattr(config_tx, "validate_config", fake_validate)
    return state


@pytest.mark.asyncio
async def test_write_preserves_mode(target):
    os.chmod(target, 0o640)
    writer = LocalAtomicWriter()
    await writer.write(target, b'alice\tCleartext-Password := "x"\n')
    assert target.stat().st_mode & 0o7777 == 0o640
    assert target.read_text(encoding="utf-8").startswith("alice")


@pytest.mark.asyncio
async def test_write_follows_symlink_and_keeps_link_intact(tmp_path):
    """The real /etc/freeradius/3.0/users is a symlink and must survive."""
    mods = tmp_path / "mods-config" / "files"
    mods.mkdir(parents=True)
    real = mods / "authorize"
    real.write_text("original\n", encoding="utf-8")

    link = tmp_path / "users"
    link.symlink_to(real)

    await LocalAtomicWriter().write(link, b"replaced\n")

    assert link.is_symlink(), "the symlink itself must not be replaced"
    assert os.readlink(link) == str(real)
    assert real.read_text(encoding="utf-8") == "replaced\n"


@pytest.mark.asyncio
async def test_failed_validation_rolls_back(store, target, validating):
    original = target.read_text(encoding="utf-8")
    validating["result"] = bad_result()
    tx = ConfigTransaction(store=store)

    with pytest.raises(config_tx.ConfigValidationError):
        await tx.apply(
            "users file",
            target,
            "broken content\n",
            operation="USER_UPDATE",
            administrator="testadmin",
        )

    assert target.read_text(encoding="utf-8") == original, "content must be restored"


@pytest.mark.asyncio
async def test_backup_is_created_even_when_validation_fails(store, target, validating):
    validating["result"] = bad_result()
    tx = ConfigTransaction(store=store)

    with pytest.raises(config_tx.ConfigValidationError):
        await tx.apply(
            "users file",
            target,
            "broken\n",
            operation="USER_UPDATE",
            administrator="testadmin",
        )

    backups = store.list()
    assert len(backups) == 1, "a backup must survive a failed validation"
    assert store.read_file(backups[0], "users file").decode() == (
        'bob\tCleartext-Password := "bobpass"\n'
    )


@pytest.mark.asyncio
async def test_successful_apply_records_backup(store, target, validating):
    tx = ConfigTransaction(store=store)
    result = await tx.apply(
        "users file",
        target,
        "new content\n",
        operation="USER_UPDATE",
        administrator="testadmin",
    )

    assert result.changed is True
    assert target.read_text(encoding="utf-8") == "new content\n"
    assert store.read_file(result.backup, "users file").decode() == (
        'bob\tCleartext-Password := "bobpass"\n'
    )


@pytest.mark.asyncio
async def test_unchanged_content_is_a_noop(store, target, validating):
    original = target.read_text(encoding="utf-8")
    tx = ConfigTransaction(store=store)
    result = await tx.apply(
        "users file",
        target,
        original,
        operation="USER_UPDATE",
        administrator="testadmin",
    )

    assert result.changed is False
    assert store.list() == [], "a no-op must not create a backup"


@pytest.mark.asyncio
async def test_backup_payload_is_immutable_after_new_backups(store, target, validating):
    tx = ConfigTransaction(store=store)
    await tx.apply("users file", target, "one\n", operation="X", administrator="a")
    first = store.list()[0]
    payload_one = store.read_file(first, "users file")

    await tx.apply("users file", target, "two\n", operation="X", administrator="a")
    assert store.read_file(first, "users file") == payload_one


@pytest.mark.asyncio
async def test_rollback_restores_prior_content(store, target, validating):
    original = target.read_text(encoding="utf-8")
    tx = ConfigTransaction(store=store)
    result = await tx.apply(
        "users file", target, "changed\n", operation="X", administrator="a"
    )

    await tx.rollback(result.backup.id, administrator="a")
    assert target.read_text(encoding="utf-8") == original


@pytest.mark.asyncio
async def test_rollback_takes_pre_rollback_snapshot(store, target, validating):
    """Rolling back must itself be reversible."""
    original = target.read_text(encoding="utf-8")
    tx = ConfigTransaction(store=store)
    result = await tx.apply(
        "users file", target, "changed\n", operation="X", administrator="a"
    )

    await tx.rollback(result.backup.id, administrator="a")
    operations = [b.operation for b in store.list()]
    assert "PRE_ROLLBACK_SNAPSHOT" in operations


def test_backup_ids_are_unique(store, target):
    a = store.create(
        files=[("users file", target)], operation="X", administrator="a"
    )
    b = store.create(
        files=[("users file", target)], operation="X", administrator="a"
    )
    assert a.id != b.id


@pytest.mark.asyncio
async def test_apply_to_symlinked_users_file_keeps_link(store, tmp_path, validating):
    """End-to-end: writing the real users symlink must not destroy it."""
    mods = tmp_path / "mods-config" / "files"
    mods.mkdir(parents=True)
    real = mods / "authorize"
    real.write_text('bob\tCleartext-Password := "bobpass"\n', encoding="utf-8")
    link = tmp_path / "users"
    link.symlink_to(real)

    tx = ConfigTransaction(store=store)
    await tx.apply(
        "users file",
        link,
        'alice\tCleartext-Password := "new"\n',
        operation="USER_CREATE",
        administrator="a",
    )

    assert link.is_symlink()
    assert real.read_text(encoding="utf-8") == 'alice\tCleartext-Password := "new"\n'