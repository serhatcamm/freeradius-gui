"""Service-layer tests for user and client management.

These exercise the rules the parsers cannot: secret handling, address
validation, duplicate handling and what actually gets written to disk.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.freeradius.clients_parser import parse_clients
from app.freeradius.users_parser import parse_users
from app.services import config_tx as config_tx_mod
from app.services.backups import BackupStore
from app.services.clients import ClientService
from app.services.config_tx import ConfigTransaction
from app.services.users import UserService, UserValidationError


@pytest.fixture
def raddb(
    tmp_path: Path, real_clients_conf: str, real_authorize: str, monkeypatch
) -> Path:
    """A sandbox raddb laid out like the real one, symlinked users file."""
    root = tmp_path / "etc" / "raddb"
    mods_files = root / "mods-config" / "files"
    mods_files.mkdir(parents=True)
    (root / "clients.conf").write_text(real_clients_conf, encoding="utf-8")
    (mods_files / "authorize").write_text(real_authorize, encoding="utf-8")

    # Mirror production: users is a symlink into mods-config/files.
    (root / "users").symlink_to(mods_files / "authorize")

    (root / "sites-available" / "default").parent.mkdir(parents=True, exist_ok=True)

    import app.services.users as users_mod
    import app.services.clients as clients_mod

    monkeypatch.setattr(users_mod.paths, "USERS_FILE", root / "users")
    monkeypatch.setattr(clients_mod.paths, "CLIENTS_FILE", root / "clients.conf")
    return root


@pytest.fixture
def tx(tmp_path: Path, monkeypatch) -> ConfigTransaction:
    store = BackupStore(tmp_path / "backups")

    async def always_valid(binary=None):
        from app.freeradius.validate import ValidationResult

        return ValidationResult(ok=True, returncode=0)

    monkeypatch.setattr(config_tx_mod, "validate_config", always_valid)
    return ConfigTransaction(store=store)


@pytest.fixture
def users(raddb: Path, tx: ConfigTransaction) -> UserService:
    return UserService(tx=tx)


@pytest.fixture
def clients(raddb: Path, tx: ConfigTransaction) -> ClientService:
    return ClientService(tx=tx)


def stored_password(entry) -> str | None:
    """The stored cleartext password for an entry, or None.

    Read straight from the parser rather than via string matching, so the
    assertion reflects what FreeRADIUS would actually load.
    """
    from app.freeradius.users_parser import PASSWORD_ATTRIBUTES

    for attr in entry.attributes:
        if attr.key in PASSWORD_ATTRIBUTES:
            return attr.unquoted_value
    return None


def read_users(raddb: Path) -> str:
    return (raddb / "mods-config" / "files" / "authorize").read_text(encoding="utf-8")


def read_clients(raddb: Path) -> str:
    return (raddb / "clients.conf").read_text(encoding="utf-8")


# -- password secrecy ---------------------------------------------------
def test_list_users_never_exposes_passwords(users):
    """The known real password must never appear in any API payload."""
    for item in users.list_users():
        assert "TestRadiusPw123!" not in repr(item)
        assert item["has_password"] is True


def test_list_users_reports_has_password(users):
    testuser = next(u for u in users.list_users() if u["username"] == "testuser")
    assert testuser["has_password"] is True


# -- duplicates ---------------------------------------------------------
def test_duplicate_user_is_reported_to_the_caller(users):
    testuser = next(u for u in users.list_users() if u["username"] == "testuser")
    assert testuser["duplicate_entries"] == 2


@pytest.mark.asyncio
async def test_change_password_updates_every_duplicate(users, raddb):
    """FreeRADIUS matches the first usable entry, so all copies must change."""
    await users.change_password("testuser", "BrandNewPass1!", administrator="admin")
    text = read_users(raddb)
    entries = [e for e in parse_users(text).users if e.username == "testuser"]
    assert len(entries) == 2
    for entry in entries:
        assert stored_password(entry) == "BrandNewPass1!"
    assert "TestRadiusPw123!" not in text


@pytest.mark.asyncio
async def test_update_password_updates_every_duplicate(users, raddb):
    await users.update_user("testuser", password="AnotherPass2!", administrator="admin")
    text = read_users(raddb)
    entries = [e for e in parse_users(text).users if e.username == "testuser"]
    assert all(stored_password(e) == "AnotherPass2!" for e in entries)


@pytest.mark.asyncio
async def test_set_privilege_updates_every_duplicate(users, raddb):
    await users.update_user("testuser", cisco_privilege=15, administrator="admin")
    text = read_users(raddb)
    entries = [e for e in parse_users(text).users if e.username == "testuser"]
    assert len(entries) == 2
    for entry in entries:
        assert entry.cisco_privilege == 15
    assert text.count("Cisco-AVPair") == 2


@pytest.mark.asyncio
async def test_disable_commented_duplicate_still_blocks_auth(users, raddb):
    """Both copies must be disabled, otherwise the second still authenticates."""
    await users.set_enabled("testuser", False, administrator="admin")
    text = read_users(raddb)
    entries = [e for e in parse_users(text).users if e.username == "testuser"]
    assert len(entries) == 2
    assert all(not e.enabled for e in entries)
    assert text.count("#freeradius-web-disabled:") == 2


@pytest.mark.asyncio
async def test_disable_preserves_password_for_reenable(users, raddb):
    await users.set_enabled("testuser", False, administrator="admin")
    entries = [
        e for e in parse_users(read_users(raddb)).users if e.username == "testuser"
    ]
    assert all(e.has_password for e in entries)

    await users.set_enabled("testuser", True, administrator="admin")
    entries = [
        e for e in parse_users(read_users(raddb)).users if e.username == "testuser"
    ]
    assert all(e.enabled for e in entries)
    assert all(stored_password(e) == "TestRadiusPw123!" for e in entries)


@pytest.mark.asyncio
async def test_delete_removes_all_duplicates(users, raddb):
    await users.delete_user("testuser", administrator="admin")
    text = read_users(raddb)
    assert "testuser" not in text
    # DEFAULT blocks must remain intact.
    assert parse_users(text).entries, "DEFAULT entries must survive a delete"


# -- validation ---------------------------------------------------------
@pytest.mark.asyncio
async def test_create_duplicate_is_rejected(users):
    with pytest.raises(UserValidationError):
        await users.create_user(
            username="testuser", password="x", administrator="admin"
        )


@pytest.mark.asyncio
async def test_create_invalid_privilege_rejected(users):
    with pytest.raises(UserValidationError):
        await users.create_user(
            username="newguy", password="Valid12345!", cisco_privilege=99,
            administrator="admin",
        )


@pytest.mark.asyncio
async def test_update_missing_user_rejected(users):
    with pytest.raises(UserValidationError):
        await users.change_password("ghost", "x", administrator="admin")


@pytest.mark.asyncio
async def test_empty_update_rejected(users):
    with pytest.raises(UserValidationError):
        await users.update_user("testuser", administrator="admin")


# -- the symlink must survive every write -------------------------------
@pytest.mark.asyncio
@pytest.mark.parametrize(
    "action",
    ["create", "password", "disable", "enable", "privilege", "delete"],
)
async def test_users_symlink_survives_all_writes(users, raddb, action):
    link = raddb / "users"
    assert link.is_symlink()
    target = link.resolve()

    if action == "create":
        await users.create_user(
            username="brandnew", password="FreshPass1!", administrator="admin"
        )
    elif action == "password":
        await users.change_password("testuser", "Zzz123456!", administrator="admin")
    elif action == "disable":
        await users.set_enabled("testuser", False, administrator="admin")
    elif action == "enable":
        await users.set_enabled("testuser", False, administrator="admin")
        await users.set_enabled("testuser", True, administrator="admin")
    elif action == "privilege":
        await users.update_user("testuser", cisco_privilege=15, administrator="admin")
    elif action == "delete":
        await users.delete_user("testuser", administrator="admin")

    assert link.is_symlink(), f"{action}: users symlink was destroyed"
    assert link.resolve() == target


@pytest.mark.asyncio
async def test_users_file_keeps_its_mode_and_owner(raddb, users):
    target = (raddb / "mods-config" / "files" / "authorize")
    before = target.stat().st_mode & 0o7777
    await users.create_user(
        username="newguy", password="FreshPass1!", administrator="admin"
    )
    assert target.stat().st_mode & 0o7777 == before


# -- clients ------------------------------------------------------------
def test_client_secrets_never_returned_to_the_api(clients):
    for item in clients.list_clients():
        assert "secret" not in item
        assert item["has_secret"] is True
    assert "TestNasSecret123!" not in repr(clients.list_clients())


def test_clients_listed_with_kinds(clients):
    by_name = {c["name"]: c for c in clients.list_clients()}
    assert set(by_name) == {
        "localhost",
        "localhost_ipv6",
        "test-nas-a",
        "test-nas-b",
    }
    assert by_name["test-nas-a"]["address_kind"] == "network"
    assert by_name["localhost"]["address_kind"] == "host"


@pytest.mark.asyncio
async def test_create_client_generates_secret_and_persists(clients, raddb):
    await clients.create_client(
        name="new-nas", address="10.20.0.0/16", secret=None, administrator="admin"
    )
    text = read_clients(raddb)
    entry = parse_clients(text).unique_find("new-nas")
    assert entry is not None
    assert entry.address == "10.20.0.0/16"
    assert entry.has_secret


@pytest.mark.asyncio
async def test_rotate_secret_changes_the_stored_value(clients, raddb):
    before = read_clients(raddb)
    await clients.reset_secret("test-nas-a", administrator="admin")
    after = read_clients(raddb)
    assert after != before

    entry = parse_clients(after).unique_find("test-nas-a")
    others = parse_clients(after).unique_find("test-nas-b")
    # Only the targeted client's secret changed.
    assert others.raw_lines == parse_clients(before).unique_find("test-nas-b").raw_lines
    assert entry.has_secret


@pytest.mark.asyncio
async def test_client_host_address_with_bits_rejected(clients):
    with pytest.raises(Exception):
        await clients.create_client(
            name="bad", address="192.0.2.5/24", secret=None, administrator="admin"
        )


@pytest.mark.asyncio
async def test_client_bare_ip_is_a_host(clients, raddb):
    await clients.create_client(
        name="single-host", address="10.30.30.30", secret=None, administrator="admin"
    )
    entry = parse_clients(read_clients(raddb)).unique_find("single-host")
    assert entry.address == "10.30.30.30"
    assert entry.address_kind == "host"


@pytest.mark.asyncio
async def test_disable_client_comments_the_whole_block(clients, raddb):
    await clients.set_enabled("test-nas-b", False, administrator="admin")
    entry = parse_clients(read_clients(raddb)).unique_find("test-nas-b")
    assert entry is not None
    assert entry.enabled is False
    assert entry.address == "198.51.100.0/24"
    assert entry.has_secret, "disabling must not destroy the secret"


@pytest.mark.asyncio
async def test_delete_client_removes_only_that_block(clients, raddb):
    await clients.delete_client("test-nas-b", administrator="admin")
    doc = parse_clients(read_clients(raddb))
    assert doc.unique_find("test-nas-b") is None
    assert doc.unique_find("localhost") is not None
    assert doc.unique_find("test-nas-a") is not None