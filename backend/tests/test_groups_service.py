"""Group service: validation, CRUD and the groupfile-enabled gate."""
from __future__ import annotations

import pytest

from app.freeradius import paths as paths_mod
from app.services.groups import (
    GroupService,
    GroupValidationError,
    groupfile_status,
    validate_attribute_key,
    validate_attribute_value,
    validate_group_name,
)


@pytest.fixture
def groups_file(tmp_path, monkeypatch):
    target = tmp_path / "groups"
    monkeypatch.setattr(paths_mod, "GROUPS_FILE", target)
    monkeypatch.setitem(paths_mod.MANAGED_FILES, "groups", target)
    return target


@pytest.fixture
def service(groups_file):
    return GroupService()


# -- name validation ----------------------------------------------------
@pytest.mark.parametrize("name", ["staff", "admins", "team-1", "a.b_c", "G0"])
def test_valid_names(name):
    assert validate_group_name(name) == name


@pytest.mark.parametrize(
    "name", ["", "  ", "-leading", ".dot", "has space", "has/slash", "a" * 65, "a\nb"]
)
def test_invalid_names(name):
    with pytest.raises(GroupValidationError):
        validate_group_name(name)


def test_default_group_cannot_be_renamed_by_the_operator():
    with pytest.raises(GroupValidationError, match="DEFAULT"):
        validate_group_name("DEFAULT")


# -- attribute validation ----------------------------------------------
@pytest.mark.parametrize("key", ["Reply-Message", "Session-Timeout", "Max-Monthly-Session"])
def test_valid_attribute_keys(key):
    assert validate_attribute_key(key) == key


@pytest.mark.parametrize(
    "key",
    [
        "Auth-Type",     # changes control flow
        "auth-type",
        "Filename",
        "groupfile",
        "Cleartext-Password",  # would let a group hand out credentials
        "bad key",
        "9leading",
        "",
    ],
)
def test_rejected_attribute_keys(key):
    with pytest.raises(GroupValidationError):
        validate_attribute_key(key)


@pytest.mark.parametrize("value", ["hello", "36000", "a b c", "x=y"])
def test_valid_attribute_values(value):
    assert validate_attribute_value(value) == value


@pytest.mark.parametrize(
    "value,why",
    [
        ("a,b", "comma splits the file line"),
        ('say "hi"', "quote breaks quoting"),
        ("back\\slash", "backslash is an escape"),
        ("line\nbreak", "newline ends the entry"),
        ("", "empty"),
        ("x" * 254, "too long"),
    ],
)
def test_rejected_attribute_values(value, why):
    with pytest.raises(GroupValidationError):
        validate_attribute_value(value)


# -- CRUD ---------------------------------------------------------------
@pytest.mark.asyncio
async def test_create_list_get(service, monkeypatch):
    recorded: dict = {}

    async def fake_apply(**kwargs):
        recorded.update(kwargs)
        # Simulate the privileged write landing.
        service.path.write_text(kwargs["new_content"])

    monkeypatch.setattr(service.tx, "apply", fake_apply)

    out = await service.create_group(
        name="staff",
        attributes=[{"key": "Reply-Message", "value": "welcome", "reply": True}],
        administrator="admin",
    )
    assert out["name"] == "staff"
    assert [g["name"] for g in service.list_groups()] == ["staff"]
    assert recorded["operation"] == "GROUP_CREATED"
    assert 'Reply-Message = "welcome"' in service.path.read_text()


@pytest.mark.asyncio
async def test_duplicate_create_rejected(service, monkeypatch):
    async def fake_apply(**kwargs):
        service.path.write_text(kwargs["new_content"])

    monkeypatch.setattr(service.tx, "apply", fake_apply)
    await service.create_group(
        name="staff", attributes=[], administrator="admin"
    )
    with pytest.raises(GroupValidationError, match="already exists"):
        await service.create_group(name="staff", attributes=[], administrator="admin")


@pytest.mark.asyncio
async def test_update_replaces_attributes(service, monkeypatch):
    async def fake_apply(**kwargs):
        service.path.write_text(kwargs["new_content"])

    monkeypatch.setattr(service.tx, "apply", fake_apply)
    await service.create_group(
        name="staff", attributes=[{"key": "Session-Timeout", "value": "60"}], administrator="a"
    )
    await service.update_group(
        name="staff", attributes=[{"key": "Session-Timeout", "value": "120"}], administrator="a"
)
    entry = service.get_group("staff")
    assert entry["attributes"][0]["value"] == "120"


@pytest.mark.asyncio
async def test_editing_a_group_submits_what_the_api_returned(service, monkeypatch):
    """The panel resubmits the values it was shown, so those must be writable.

    Guards the quoting mismatch: the writer rejects a value containing a quote,
    so an API that returned ``"120"`` would make every edit fail.
    """
    async def fake_apply(**kwargs):
        service.path.write_text(kwargs["new_content"])

    monkeypatch.setattr(service.tx, "apply", fake_apply)
    await service.create_group(
        name="staff",
        attributes=[{"key": "Session-Timeout", "value": "120"}],
        administrator="a",
    )

    shown = service.get_group("staff")
    assert '"' not in shown["attributes"][0]["value"]
    await service.update_group(
        name="staff",
        attributes=[
            {**attr, "value": "300"} for attr in shown["attributes"]
        ],
        administrator="a",
    )
    assert 'Session-Timeout = "300"' in service.path.read_text()


@pytest.mark.asyncio
async def test_update_missing_group_404(service):
    with pytest.raises(GroupValidationError, match="not found"):
        await service.update_group(name="nope", attributes=[], administrator="a")


@pytest.mark.asyncio
async def test_delete(service, monkeypatch):
    async def fake_apply(**kwargs):
        service.path.write_text(kwargs["new_content"])

    monkeypatch.setattr(service.tx, "apply", fake_apply)
    await service.create_group(name="staff", attributes=[], administrator="a")
    assert await service.delete_group("staff", administrator="a") == 1
    assert service.list_groups() == []


@pytest.mark.asyncio
async def test_delete_default_refused(service):
    groups_file = service.path
    groups_file.write_text('DEFAULT\tReply-Message = "x"\n')
    with pytest.raises(GroupValidationError, match="DEFAULT"):
        await service.delete_group("DEFAULT", administrator="a")


@pytest.mark.asyncio
@pytest.mark.asyncio
async def test_forbidden_attribute_never_reaches_the_file(service, monkeypatch):
    """A group must not be able to change how auth is processed."""

    async def fake_apply(**kwargs):  # pragma: no cover - must not run
        raise AssertionError("transaction must not run for an invalid attribute")

    monkeypatch.setattr(service.tx, "apply", fake_apply)
    with pytest.raises(GroupValidationError):
        await service.create_group(
            name="evil",
            attributes=[{"key": "Auth-Type", "value": "Accept"}],
            administrator="a",
        )
    assert not service.path.exists()


# -- groupfile gate -----------------------------------------------------
def test_groupfile_status_reports_disabled(tmp_path, monkeypatch):
    mods = tmp_path / "mods-available"
    mods.mkdir()
    (mods / "files").write_text("files {\n\tmoddir = ${modconfdir}/files\n}\n")
    monkeypatch.setattr(paths_mod, "MODS_AVAILABLE", mods)
    status = groupfile_status()
    assert status["enabled"] is False
    assert status["directive"] is None


def test_groupfile_status_reports_enabled(tmp_path, monkeypatch):
    mods = tmp_path / "mods-available"
    mods.mkdir()
    (mods / "files").write_text(
        "files {\n\tmoddir = ${modconfdir}/files\n\tgroupfile = ${moddir}/groups\n}\n"
    )
    monkeypatch.setattr(paths_mod, "MODS_AVAILABLE", mods)
    status = groupfile_status()
    assert status["enabled"] is True
    assert "groupfile" in str(status["directive"])


def test_groupfile_outside_the_files_section_does_not_count(tmp_path, monkeypatch):
    """A groupfile line in another module must not be mistaken for ours."""
    mods = tmp_path / "mods-available"
    mods.mkdir()
    (mods / "files").write_text(
        "files {\n\tmoddir = ${modconfdir}/files\n}\n"
        "other {\n\tgroupfile = /somewhere/else\n}\n"
    )
    monkeypatch.setattr(paths_mod, "MODS_AVAILABLE", mods)
    assert groupfile_status()["enabled"] is False


def test_groupfile_commented_line_does_not_count(tmp_path, monkeypatch):
    mods = tmp_path / "mods-available"
    mods.mkdir()
    (mods / "files").write_text(
        "files {\n\tmoddir = ${modconfdir}/files\n\t#groupfile = ${moddir}/groups\n}\n"
    )
    monkeypatch.setattr(paths_mod, "MODS_AVAILABLE", mods)
    assert groupfile_status()["enabled"] is False


def test_groupfile_status_survives_a_missing_module_file(tmp_path, monkeypatch):
    monkeypatch.setattr(paths_mod, "MODS_AVAILABLE", tmp_path / "nope")
    status = groupfile_status()
    assert status["enabled"] is False
    assert "error" in status


# -- membership ---------------------------------------------------------
def test_members_read_from_the_users_file(service, tmp_path, monkeypatch):
    users = tmp_path / "authorize"
    users.write_text(
        'alice\tCleartext-Password := "x"\n\tGroup = staff\n'
        'bob\tCleartext-Password := "y"\n\tGroup = staff\n'
        'carol\tCleartext-Password := "z"\n'
    )
    monkeypatch.setattr(paths_mod, "USERS_FILE", users)
    assert service.members("staff") == ["alice", "bob"]


def test_members_empty_when_users_file_missing(service, tmp_path, monkeypatch):
    monkeypatch.setattr(paths_mod, "USERS_FILE", tmp_path / "gone")
    assert service.members("staff") == []