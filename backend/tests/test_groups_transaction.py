"""The groups transaction must obey the same backup/validate/rollback contract
as every other managed file.

These run the real ConfigTransaction with validation stubbed, because the
behaviour under test is the write plumbing rather than `freeradius -XC`.
"""
from __future__ import annotations

import pytest

from app.services import config_tx as ct
from app.services.config_tx import ConfigTransaction

ORIGINAL = 'old\tReply-Message = "x"\n'
NEW = 'new\tReply-Message = "y"\n'


@pytest.fixture
def ok_validation(monkeypatch):
    async def fake():
        return ct.ValidationResult(True, 0, issues=[])

    monkeypatch.setattr(ct, "validate_config", fake)


@pytest.fixture
def broken_validation(monkeypatch):
    async def fake():
        return ct.ValidationResult(False, 1, issues=[])

    monkeypatch.setattr(ct, "validate_config", fake)


@pytest.fixture
def groups(tmp_path):
    target = tmp_path / "groups"
    target.write_text(ORIGINAL)
    return target


@pytest.mark.asyncio
async def test_change_is_backed_up_before_it_is_written(tmp_path, groups, ok_validation):
    store = ct.BackupStore(root=tmp_path / "backups")
    tx = ConfigTransaction(store=store)

    result = await tx.apply(
        label="groups",
        path=groups,
        new_content=NEW,
        operation="GROUP_UPDATED",
        administrator="tester",
    )
    assert result.changed is True
    assert groups.read_text() == NEW

    # The backup must hold the pre-change content.
    assert list(result.backup.files) == ["groups"]
    stored = tmp_path / "backups" / result.backup.id / "files" / "groups"
    assert stored.read_text() == ORIGINAL


@pytest.mark.asyncio
async def test_failed_validation_rolls_the_file_back(tmp_path, groups, broken_validation):
    store = ct.BackupStore(root=tmp_path / "backups")
    tx = ConfigTransaction(store=store)

    with pytest.raises(ct.ConfigValidationError) as excinfo:
        await tx.apply(
            label="groups",
            path=groups,
            new_content='broken\tReply-Message = "z"\n',
            operation="GROUP_UPDATED",
            administrator="tester",
        )
    assert excinfo.value.rolled_back is True
    assert groups.read_text() == ORIGINAL, "the live file must survive untouched"


@pytest.mark.asyncio
async def test_no_op_change_writes_nothing(tmp_path, groups, ok_validation):
    store = ct.BackupStore(root=tmp_path / "backups")
    tx = ConfigTransaction(store=store)

    result = await tx.apply(
        label="groups",
        path=groups,
        new_content=ORIGINAL,
        operation="GROUP_UPDATED",
        administrator="tester",
    )
    assert result.changed is False
    assert groups.read_text() == ORIGINAL
    assert not list((tmp_path / "backups").glob("*")), "a no-op must not create a backup"


@pytest.mark.asyncio
async def test_restoring_a_backup_puts_groups_back(tmp_path, groups, ok_validation):
    store = ct.BackupStore(root=tmp_path / "backups")
    tx = ConfigTransaction(store=store)

    await tx.apply(
        label="groups",
        path=groups,
        new_content=NEW,
        operation="GROUP_UPDATED",
        administrator="tester",
    )
    latest = store.list()[0]

    await tx.rollback(latest.id, administrator="tester")
    assert groups.read_text() == ORIGINAL