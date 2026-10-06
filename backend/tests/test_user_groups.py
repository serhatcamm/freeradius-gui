"""Assigning a user to a group via "Group = name" in authorize."""
from __future__ import annotations

import pytest

import app.services.config_tx as config_tx_mod
import app.services.users as users_mod
from app.freeradius.users_parser import parse_users
from app.services.backups import BackupStore
from app.services.config_tx import ConfigTransaction
from app.services.users import UserService, UserValidationError, validate_group


@pytest.fixture
def tx(tmp_path, monkeypatch) -> ConfigTransaction:
    """A real transaction that writes locally, with config validation stubbed."""
    store = BackupStore(tmp_path / "backups")

    async def always_valid(binary=None):
        from app.freeradius.validate import ValidationResult

        return ValidationResult(ok=True, returncode=0)

    monkeypatch.setattr(config_tx_mod, "validate_config", always_valid)
    return ConfigTransaction(store=store)


@pytest.fixture
def raddb(tmp_path, monkeypatch):
    """A sandbox authorize file holding two plain users."""
    mods_files = tmp_path / "etc" / "raddb" / "mods-config" / "files"
    mods_files.mkdir(parents=True)
    target = mods_files / "authorize"
    target.write_text(
        'alice\tCleartext-Password := "AlicePass1!"\n'
        'bob\tCleartext-Password := "BobPass123!"\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(users_mod.paths, "USERS_FILE", target)
    return target


@pytest.fixture
def users(raddb, tx) -> UserService:
    return UserService(tx=tx)


# -- validation ---------------------------------------------------------
def test_validate_group_accepts_a_name():
    assert validate_group("staff") == "staff"


def test_validate_group_empty_means_no_group():
    assert validate_group("") == ""
    assert validate_group("   ") == ""


def test_validate_group_rejects_bad_shape():
    for bad in ["has space", "has/slash", "-lead", "DEFAULT"]:
        with pytest.raises(UserValidationError):
            validate_group(bad)


# -- parser round trip --------------------------------------------------
def test_entry_exposes_its_group():
    doc = parse_users('carol\tCleartext-Password := "x"\n\tGroup = staff\n')
    assert doc.users[0].group == "staff"


def test_entry_without_group_is_empty():
    doc = parse_users('dave\tCleartext-Password := "x"\n')
    assert doc.users[0].group == ""


def test_set_group_replaces_an_existing_value():
    doc = parse_users('erin\tCleartext-Password := "x"\n\tGroup = old\n')
    doc.users[0].set_group("new")
    assert doc.users[0].group == "new"
    assert doc.render().count("Group") == 1


def test_set_group_empty_removes_it():
    doc = parse_users('frank\tCleartext-Password := "x"\n\tGroup = old\n')
    doc.users[0].set_group("")
    assert doc.users[0].group == ""
    assert "Group" not in doc.render()


def test_set_group_survives_a_render_round_trip():
    doc = parse_users('gina\tCleartext-Password := "x"\n')
    doc.users[0].set_group("staff")
    assert parse_users(doc.render()).users[0].group == "staff"


def test_group_is_reported_in_the_api_shape(raddb):
    assert UserService().get_user("alice")["group"] == ""


@pytest.mark.asyncio
async def test_create_user_can_start_in_a_group(users, raddb):
    await users.create_user(
        username="hank",
        password="HankPass12345!",
        administrator="admin",
        group="staff",
    )
    created = parse_users(raddb.read_text()).unique_find("hank")
    assert created is not None
    assert created.group == "staff"


@pytest.mark.asyncio
async def test_create_user_without_a_group(users, raddb):
    await users.create_user(
        username="iris", password="IrisPass12345!", administrator="admin"
    )
    assert parse_users(raddb.read_text()).unique_find("iris").group == ""


@pytest.mark.asyncio
async def test_create_user_rejects_a_bad_group(users, raddb):
    before = raddb.read_text()
    with pytest.raises(UserValidationError):
        await users.create_user(
            username="jane",
            password="JanePass12345!",
            administrator="admin",
            group="has space",
        )
    assert raddb.read_text() == before, "a rejected group must not touch the file"


# -- service ------------------------------------------------------------
@pytest.mark.asyncio
async def test_update_user_assigns_a_group(users, raddb):
    await users.update_user("alice", group="staff", administrator="admin")
    assert parse_users(raddb.read_text()).users[0].group == "staff"


@pytest.mark.asyncio
async def test_update_user_clears_a_group(users, raddb):
    await users.update_user("alice", group="staff", administrator="admin")
    await users.update_user("alice", group="", administrator="admin")
    assert parse_users(raddb.read_text()).users[0].group == ""


@pytest.mark.asyncio
async def test_group_omitted_leaves_it_untouched(users, raddb):
    """A password-only edit must not silently drop the group."""
    await users.update_user("alice", group="staff", administrator="admin")
    await users.update_user("alice", password="NewPass123!", administrator="admin")
    assert parse_users(raddb.read_text()).users[0].group == "staff"


@pytest.mark.asyncio
async def test_invalid_group_is_rejected(users, raddb):
    before = raddb.read_text()
    with pytest.raises(UserValidationError):
        await users.update_user("alice", group="has space", administrator="admin")
    assert raddb.read_text() == before, "a rejected group must not touch the file"


@pytest.mark.asyncio
async def test_missing_user_is_rejected(users):
    with pytest.raises(UserValidationError, match="not found"):
        await users.update_user("nobody", group="staff", administrator="admin")


@pytest.mark.asyncio
async def test_update_with_no_changes_still_rejected(users):
    with pytest.raises(UserValidationError, match="No changes"):
        await users.update_user("alice", administrator="admin")