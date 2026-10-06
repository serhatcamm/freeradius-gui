"""Shared pytest fixtures.

Tests run against copies of the *real* FreeRADIUS configuration captured from
the target host, so the parsers are exercised with genuine syntax rather than
idealised input.
"""
from __future__ import annotations

import asyncio
import importlib
import itertools
import os
import shutil
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:  # pragma: no cover
    from fastapi.testclient import TestClient

BACKEND = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND))

#: Directories a test must never write to, whatever the sandbox fixtures say.
#: Resolved lazily by `no_live_writes` so importing conftest has no side effects.
LIVE_RADDB = Path("/etc/freeradius")

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def real_clients_conf() -> str:
    return (FIXTURES / "clients.conf.orig").read_text(encoding="utf-8")


@pytest.fixture(scope="session")
def real_authorize() -> str:
    return (FIXTURES / "authorize.orig").read_text(encoding="utf-8")


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch, real_clients_conf, real_authorize) -> Path:
    """An isolated copy of the managed configuration files.

    ``paths`` is imported as a module by every service, so patching the module
    attributes is enough - and unlike reloading it, monkeypatch restores the
    originals automatically without leaving stale references behind.
    """
    raddb = tmp_path / "raddb"
    raddb.mkdir()
    (raddb / "clients.conf").write_text(real_clients_conf, encoding="utf-8")
    (raddb / "authorize").write_text(real_authorize, encoding="utf-8")

    from app.freeradius import paths as paths_mod

    monkeypatch.setattr(paths_mod, "RADDB_DIR", raddb)
    monkeypatch.setattr(paths_mod, "CLIENTS_FILE", raddb / "clients.conf")
    monkeypatch.setattr(paths_mod, "USERS_FILE", raddb / "authorize")
    monkeypatch.setattr(paths_mod, "BACKUP_DIR", tmp_path / "backups")

    monkeypatch.setenv("FRW_RADDB_DIR", str(raddb))
    monkeypatch.setenv("FRW_CLIENTS_FILE", str(raddb / "clients.conf"))
    monkeypatch.setenv("FRW_USERS_FILE", str(raddb / "authorize"))
    monkeypatch.setenv("FRW_BACKUP_DIR", str(tmp_path / "backups"))

    assert_paths_sandboxed()

    from app.core import config as config_mod

    config_mod.get_settings.cache_clear()
    yield tmp_path
    config_mod.get_settings.cache_clear()


@pytest.fixture(scope="session")
def db_env(tmp_path_factory):
    """One database for the whole session.

    Creating a fresh engine per test means disposing an engine while
    TestClient's worker threads may still be serving requests from the
    previous test, which produced non-deterministic auth failures. The
    database is therefore created once and the tables are truncated between
    tests instead (see ``db_session``).
    """
    from app.core import config as config_mod
    from app.core import db as db_mod

    directory = tmp_path_factory.mktemp("db")
    keys = ("FRW_DATABASE_URL", "FRW_SECRET_KEY_FILE")
    saved = {k: os.environ.get(k) for k in keys}

    os.environ["FRW_DATABASE_URL"] = f"sqlite:///{directory / 'app.db'}"
    os.environ["FRW_SECRET_KEY_FILE"] = str(directory / "secret_key")

    config_mod.get_settings.cache_clear()
    db_mod.reset_engine()
    db_mod.init_db()

    yield directory

    db_mod.reset_engine()
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    config_mod.get_settings.cache_clear()


def truncate_auth_tables(session) -> None:
    """Empty the tables the API tests write to."""
    from app.models.db import Administrator, AuditLog, LoginAttempt
    from app.models.db import AdSettings, Alert, AlertRule
    from app.models.db import Session as SessionRow

    # Alerts first: they reference alert_rules by foreign key.
    for model in (
        Alert,
        AlertRule,
        AdSettings,
        SessionRow,
        LoginAttempt,
        AuditLog,
        Administrator,
    ):
        session.query(model).delete()
    session.commit()


@pytest.fixture
def db_session(db_env):
    from app.core import db as db_mod

    session = db_mod.get_sessionmaker()()
    truncate_auth_tables(session)
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def app_client(db_env):
    """A TestClient wired to the session database."""
    from app.core import config as config_mod

    keys = ("FRW_ENABLE_DOCS", "FRW_COOKIE_SECURE", "FRW_LOGIN_MAX_ATTEMPTS")
    saved = {k: os.environ.get(k) for k in keys}
    os.environ["FRW_ENABLE_DOCS"] = "true"
    os.environ["FRW_COOKIE_SECURE"] = "false"
    os.environ["FRW_LOGIN_MAX_ATTEMPTS"] = "5"
    config_mod.get_settings.cache_clear()

    from app.main import app as fastapi_app

    from fastapi.testclient import TestClient

    with TestClient(fastapi_app) as client:
        yield client

    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    config_mod.get_settings.cache_clear()


@pytest.fixture
def logged_in(client, admin):
    """An authenticated TestClient."""
    resp = login(client, "admin", ADMIN_PASSWORD)
    assert resp.status_code == 200, resp.text
    return client


# --------------------------------------------------------------------------
# API fixtures
#
# These live here rather than in test_api.py so every API-facing test module
# (auth, RBAC, logging endpoints) shares the same sandbox and accounts.
# --------------------------------------------------------------------------

ADMIN_PASSWORD = "Str0ngPassw0rd!"
VIEWER_PASSWORD = "V1ewerPassw0rd!"
OPERATOR_PASSWORD = "Oper4torPassw0rd!"


@pytest.fixture
def env(db_env, tmp_path, monkeypatch, real_clients_conf, real_authorize):
    """An isolated copy of the managed config files plus a clean database.

    The API tests exercise mutating endpoints, so the paths the services
    resolve must point at a sandbox. Without this they would write the live
    /etc/freeradius/3.0 files.

    The database itself is shared across the session (see ``db_env``) and only
    truncated here; rebuilding the engine per test raced with TestClient's
    worker threads.
    """
    raddb = tmp_path / "raddb"
    mods_files = raddb / "mods-config" / "files"
    mods_files.mkdir(parents=True)
    (raddb / "clients.conf").write_text(real_clients_conf, encoding="utf-8")
    (mods_files / "authorize").write_text(real_authorize, encoding="utf-8")
    (raddb / "users").symlink_to(mods_files / "authorize")

    import app.services.clients as clients_mod
    import app.services.users as users_mod

    monkeypatch.setattr(users_mod.paths, "USERS_FILE", raddb / "users")
    monkeypatch.setattr(clients_mod.paths, "CLIENTS_FILE", raddb / "clients.conf")
    monkeypatch.setattr(users_mod.paths, "BACKUP_DIR", tmp_path / "backups")
    # The request-logging feature resolves sites-available/ and mods-available/
    # relative to RADDB_DIR, so the whole root has to point at the sandbox or
    # enabling logging writes the live files.
    monkeypatch.setattr(users_mod.paths, "RADDB_DIR", raddb)

    monkeypatch.setenv("FRW_BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setenv("FRW_COOKIE_SECURE", "false")
    monkeypatch.setenv("FRW_ENABLE_DOCS", "false")

    # app.main reads the static directory at import time and registers the SPA
    # routes only if it exists, so tests must pin it. Otherwise the suite's
    # behaviour depends on whether a bundle happens to be installed on the host
    # running it (it was reading the production /opt/freeradius-web/static).
    static = tmp_path / "static"
    static.mkdir()
    (static / "index.html").write_text(
        "<!doctype html><html><body><div id=\"root\"></div></body></html>",
        encoding="utf-8",
    )
    monkeypatch.setenv("FRW_STATIC_DIR", str(static))
    import app.main as main_mod
    importlib.reload(main_mod)

    assert_paths_sandboxed()

    # The transaction layer must not shell out to the real freeradius binary.
    async def always_valid(binary=None):
        from app.freeradius.validate import ValidationResult

        return ValidationResult(ok=True, returncode=0)

    from app.services import config_tx as config_tx_mod

    monkeypatch.setattr(config_tx_mod, "validate_config", always_valid)

    from app.core import config as config_mod
    from app.core import db as db_mod

    config_mod.get_settings.cache_clear()

    # Start every test from a clean database so accounts and login
    # rate-limit counters from earlier tests cannot leak in.
    session = db_mod.get_sessionmaker()()
    try:
        truncate_auth_tables(session)
    finally:
        session.close()

    yield
    config_mod.get_settings.cache_clear()


@pytest.fixture(autouse=True)
def no_live_writes(monkeypatch):
    """Fail the test rather than write the real FreeRADIUS configuration.

    History: an earlier version of this suite ran the mutating API tests with
    the managed paths still resolving to ``/etc/freeradius/3.0``. Twenty-eight
    real backups appeared in ``/var/lib/freeradius-web/backups`` and the live
    host gained a ``newguy`` user and a rotated ``localhost`` secret. The
    sandbox fixtures fix that, but a silent regression would write production
    configuration again, so this guard is explicit and global.

    It *asserts* instead of redirecting: silently repointing the writer would
    hide the very thing worth failing on, namely which code path escaped the
    sandbox.
    """
    from app.services import privileged_writer as pw_mod

    # ConfigTransaction imports default_writer lazily from privileged_writer,
    # so that is the name to patch. It resolves to the direct local writer when
    # the suite runs as root and to the sudo-based writer otherwise; either is
    # fine, since the guard only needs something to delegate to once the path
    # check has passed.
    real_writer = pw_mod.default_writer()

    class GuardWriter:
        """Delegate to the real writer, refusing live-configuration targets."""

        async def write(self, path: Path, content: bytes, mode: int | None = None) -> None:
            resolved = Path(path).resolve()
            live = LIVE_RADDB.resolve()
            if resolved == live or live in resolved.parents:
                pytest.fail(
                    f"a test tried to write {resolved}, which is inside the live "
                    f"FreeRADIUS configuration ({live}). The sandbox fixture "
                    f"should have redirected this path; do not run the suite "
                    f"against a real server."
                )
            await real_writer.write(resolved, content, mode)

    monkeypatch.setattr(pw_mod, "default_writer", lambda: GuardWriter())
    yield


def assert_paths_sandboxed():
    """Fail if the managed paths still point at the live configuration.

    Called by the sandbox fixtures *after* they patch the path attributes, so
    a fixture that forgets to redirect one of them fails immediately instead of
    letting the next mutating test write production configuration.
    """
    from app.freeradius import paths as paths_mod

    live_root = LIVE_RADDB.resolve()
    offenders = []
    for attribute in ("RADDB_DIR", "USERS_FILE", "CLIENTS_FILE"):
        live_value = getattr(paths_mod, attribute, None)
        if live_value is None:
            continue
        resolved_live = Path(live_value).resolve()
        if resolved_live == live_root or live_root in resolved_live.parents:
            offenders.append(f"{attribute}={resolved_live}")

    if offenders:
        pytest.fail(
            "the test sandbox did not redirect the managed paths; they still "
            f"point at the live configuration: {', '.join(offenders)}"
        )


_ip_counter = itertools.count(1)


@pytest.fixture
def client(env) -> "TestClient":
    from app.main import app
    from fastapi.testclient import TestClient

    with TestClient(app) as c:
        # Login throttling is keyed on client IP as well as username, so give
        # every test its own source address. Otherwise one test's deliberate
        # failures lock out the next one (order-dependent failures).
        n = next(_ip_counter)
        c.headers["X-Forwarded-For"] = f"10.99.{(n - 1) // 250}.{n % 250}"
        yield c


def _make_account(username: str, password: str, role: str):
    from app.core import db as db_mod
    from app.models.db import Administrator, utcnow
    from app.security.passwords import hash_password

    with db_mod.get_sessionmaker()() as session:
        user = Administrator(
            username=username,
            password_hash=hash_password(password),
            role=role,
            is_active=True,
            created_at=utcnow(),
        )
        session.add(user)
        session.commit()
        session.refresh(user)
        session.expunge(user)
        return user


@pytest.fixture
def admin(env):
    return _make_account("admin", ADMIN_PASSWORD, "admin")


@pytest.fixture
def viewer(env):
    """A read-only account. The password must satisfy the policy."""
    return _make_account("viewer", VIEWER_PASSWORD, "viewer")


@pytest.fixture
def operator(env):
    return _make_account("operator", OPERATOR_PASSWORD, "operator")


# -- helpers used by several test modules ---------------------------------
def diagnose(c: "TestClient | None" = None) -> str:
    """Context for an auth failure.

    Included in assertion messages because a wrong-looking 401 almost always
    means a session cookie, database or account lookup did not line up, and
    the raw response body ("Session not found") hides which one.
    """
    from sqlalchemy import select

    from app.core.db import get_engine
    from app.models.db import Administrator, Session as SessionRow

    out = []
    try:
        with get_engine().connect() as conn:
            admins = [row[0] for row in conn.execute(select(Administrator.username))]
            sessions = [row[0] for row in conn.execute(select(SessionRow.id))]
        out.append(f"engine={get_engine().url.database}")
        out.append(f"admins={admins}")
        out.append(f"sessions={len(sessions)}")
        if c is not None:
            out.append(f"has_cookie={'frw_session' in c.cookies}")
    except Exception as exc:  # noqa: BLE001
        out.append(f"diagnose failed: {exc!r}")
    return " | ".join(out)


def login(c: "TestClient", username: str, password: str, ok: bool = True):
    """Log in. ``ok=False`` for attempts that are meant to be rejected."""
    r = c.post("/api/auth/login", json={"username": username, "password": password})
    if ok:
        # Fail loudly here rather than letting a failed login surface as a
        # confusing 401 several assertions later.
        assert r.status_code == 200, (
            f"login failed for {username}: {r.status_code} {r.text} :: {diagnose(c)}"
        )
    return r


def csrf_headers(c: "TestClient") -> dict:
    return {"X-CSRF-Token": c.cookies.get("frw_csrf", "")}