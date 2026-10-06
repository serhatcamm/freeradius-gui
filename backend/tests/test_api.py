"""API tests: authentication, CSRF, RBAC and secret redaction.

The fixtures (``client``, ``admin``, ``viewer``, ``operator``) and the helpers
(``login``, ``csrf_headers``) come from ``conftest`` so the other API test
modules share the same sandbox and accounts.
"""
from __future__ import annotations

from app.core import db as db_mod
from app.models.db import Administrator
from conftest import csrf_headers, diagnose, login  # noqa: F401


def test_operator_can_change_users_but_not_restart_service(client, operator):
    """Role separation must be enforced in both directions."""
    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post(
        "/api/users",
        json={"username": "opuser", "password": "Oper4torPassw0rd!"},
        headers=csrf_headers(client),
    )
    assert r.status_code == 201, r.text

    r = client.post("/api/service/restart", headers=csrf_headers(client))
    assert r.status_code == 403


def _diagnose(c) -> str:
    """Kept as an alias so existing call sites read naturally."""
    return diagnose(c)


# -- health -------------------------------------------------------------
def test_health_is_public(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert "status" in r.json()


# -- authentication -----------------------------------------------------
def test_protected_endpoints_require_auth(client):
    for path in ("/api/users", "/api/clients", "/api/dashboard", "/api/backups"):
        assert client.get(path).status_code == 401, path


def test_login_with_valid_credentials(client, admin):
    r = login(client, "admin", "Str0ngPassw0rd!")
    assert r.status_code == 200
    assert "password" not in r.text.lower()
    assert client.cookies.get("frw_session")


def test_login_with_wrong_password(client, admin):
    r = login(client, "admin", "wrong", ok=False)
    assert r.status_code == 401


def test_login_with_unknown_user(client, admin):
    r = login(client, "nosuchuser", "Str0ngPassw0rd!", ok=False)
    assert r.status_code == 401


def test_login_response_gives_csrf_token(client, admin):
    r = login(client, "admin", "Str0ngPassw0rd!")
    assert r.json().get("csrf_token")
    assert client.cookies.get("frw_csrf")


def test_logout_clears_session(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    assert client.get("/api/users").status_code == 200
    # Logout is an unsafe method, so it needs the CSRF header too.
    r = client.post("/api/auth/logout", headers=csrf_headers(client))
    assert r.status_code == 200
    assert client.get("/api/users").status_code == 401


def test_logout_without_csrf_does_nothing(client, admin):
    """A forged logout must not be able to clear another session."""
    login(client, "admin", "Str0ngPassw0rd!")
    assert client.post("/api/auth/logout").status_code == 403
    assert client.get("/api/users").status_code == 200


def test_inactive_admin_cannot_log_in(client, env, admin):
    with db_mod.get_sessionmaker()() as session:
        a = session.query(Administrator).filter_by(username="admin").one()
        a.is_active = False
        session.commit()
    assert login(client, "admin", "Str0ngPassw0rd!", ok=False).status_code == 403


def test_password_never_echoed(client, admin):
    r = client.get("/api/auth/me")
    assert "Str0ngPassw0rd!" not in r.text
    assert "password_hash" not in r.text


# -- CSRF ---------------------------------------------------------------
def test_unsafe_request_without_csrf_rejected(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    r = client.post("/api/radius/test", json={"username": "x", "password": "y"})
    assert r.status_code == 403


def test_unsafe_request_with_wrong_csrf_rejected(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    r = client.post(
        "/api/radius/test",
        json={"username": "x", "password": "y"},
        headers={"X-CSRF-Token": "not-the-right-token"},
    )
    assert r.status_code == 403


def test_safe_requests_do_not_need_csrf(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    assert client.get("/api/users").status_code == 200


# -- RBAC ---------------------------------------------------------------
def test_viewer_can_read(client, viewer):
    login(client, "viewer", "V1ewerPassw0rd!")
    r = client.get("/api/users")
    assert r.status_code == 200, f"{r.text} :: {_diagnose(client)}"
    assert client.get("/api/dashboard").status_code == 200


def test_viewer_cannot_mutate(client, viewer):
    login(client, "viewer", "V1ewerPassw0rd!")
    r = client.post(
        "/api/users",
        json={"username": "newguy", "password": "Passw0rd123!"},
        headers=csrf_headers(client),
    )
    assert r.status_code == 403


def test_viewer_cannot_rotate_secrets(client, viewer):
    login(client, "viewer", "V1ewerPassw0rd!")
    r = client.post(
        "/api/clients/localhost/reset-secret",
        headers=csrf_headers(client),
    )
    assert r.status_code == 403


def test_viewer_cannot_restart_service(client, viewer):
    login(client, "viewer", "V1ewerPassw0rd!")
    r = client.post("/api/service/restart", headers=csrf_headers(client))
    assert r.status_code == 403, r.text


def test_viewer_cannot_rollback_backups(client, viewer):
    login(client, "viewer", "V1ewerPassw0rd!")
    r = client.post("/api/backups/whatever/rollback", headers=csrf_headers(client))
    assert r.status_code == 403


def test_viewer_cannot_run_radius_test(client, viewer):
    """radtest needs operator: it authenticates against live credentials."""
    login(client, "viewer", "V1ewerPassw0rd!")
    r = client.post(
        "/api/radius/test",
        json={"username": "testuser", "password": "x"},
        headers=csrf_headers(client),
    )
    assert r.status_code == 403, f"{r.status_code} {r.text} :: {_diagnose(client)}"


def test_viewer_can_still_read_backups_and_settings(client, viewer):
    login(client, "viewer", "V1ewerPassw0rd!")
    assert client.get("/api/backups").status_code == 200
    assert client.get("/api/settings").status_code == 200


# -- radius test: secret resolution -------------------------------------
def test_radius_test_requires_a_client_or_secret(client, operator):
    """The UI sends only username+password+client.

    With no secret and no client name there is nothing to sign the
    Access-Request with, so this is a 422 by construction.
    """
    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post(
        "/api/radius/test",
        json={"username": "testuser", "password": "TestRadiusPw123!"},
        headers=csrf_headers(client),
    )
    assert r.status_code == 422, f"{r.status_code} {r.text} :: {_diagnose(client)}"


def test_radius_test_unknown_client_is_404(client, operator):
    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post(
        "/api/radius/test",
        json={"username": "testuser", "password": "x", "client": "no-such-nas"},
        headers=csrf_headers(client),
    )
    assert r.status_code == 404, f"{r.status_code} {r.text} :: {_diagnose(client)}"


def test_radius_test_resolves_secret_from_client(client, operator, monkeypatch):
    """The secret comes from clients.conf, never from the request body."""
    captured: dict = {}

    async def fake_run_test(**kwargs):
        captured.update(kwargs)
        return {
            "result": "Access-Accept",
            "response_time_ms": 1.0,
            "username": kwargs["username"],
            "server": kwargs["server"],
            "port": kwargs["port"],
            "returned_attributes": [],
            "request_attributes": [],
            "message_authenticator": None,
            "error": None,
        }

    monkeypatch.setattr("app.services.radius_test.run_test", fake_run_test)

    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post(
        "/api/radius/test",
        json={"username": "testuser", "password": "TestRadiusPw123!", "client": "test-nas-a"},
        headers=csrf_headers(client),
    )
    assert r.status_code == 200, f"{r.status_code} {r.text} :: {_diagnose(client)}"
    assert captured["secret"] == "TestNasSecret123!", captured
    # The secret must not be echoed back to the browser.
    assert "TestNasSecret123!" not in r.text


def test_radius_test_client_without_secret_is_409(client, operator, env, monkeypatch):
    """A NAS with no secret cannot sign a request; say so plainly."""
    from app.freeradius import paths as paths_mod

    paths_mod.CLIENTS_FILE.write_text(
        "client no_secret_nas {\n"
        "    ipaddr = 192.0.2.90\n"
        "    nas_type = other\n"
        "}\n",
        encoding="utf-8",
    )

    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post(
        "/api/radius/test",
        json={"username": "testuser", "password": "x", "client": "no_secret_nas"},
        headers=csrf_headers(client),
    )
    assert r.status_code == 409, f"{r.status_code} {r.text} :: {_diagnose(client)}"


def test_radius_test_explicit_secret_still_works(client, operator, monkeypatch):
    """Callers that already hold a secret can keep passing one."""
    captured: dict = {}

    async def fake_run_test(**kwargs):
        captured.update(kwargs)
        return {
            "result": "Access-Accept",
            "response_time_ms": 1.0,
            "username": kwargs["username"],
            "server": kwargs["server"],
            "port": kwargs["port"],
            "returned_attributes": [],
            "request_attributes": [],
            "message_authenticator": None,
            "error": None,
        }

    monkeypatch.setattr("app.services.radius_test.run_test", fake_run_test)

    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post(
        "/api/radius/test",
        json={"username": "testuser", "password": "x", "secret": "ExplicitSecret123!"},
        headers=csrf_headers(client),
    )
    assert r.status_code == 200, f"{r.status_code} {r.text} :: {_diagnose(client)}"
    assert captured["secret"] == "ExplicitSecret123!", captured


# -- data exposure ------------------------------------------------------
def test_client_secrets_are_not_exposed(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    r = client.get("/api/clients")
    assert r.status_code == 200
    assert "TestNasSecret123!" not in r.text
    for item in r.json():
        assert "secret" not in item


def test_user_passwords_are_not_exposed(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    r = client.get("/api/users")
    assert "TestRadiusPw123!" not in r.text


def test_docs_disabled_when_configured_off(client):
    # The docs live under /api, not /. Asserting on "/docs" only passed while no
    # bundle was installed, because the SPA catch-all did not exist yet; with a
    # bundle present every non-API path legitimately returns index.html.
    for path in ("/api/docs", "/api/redoc", "/api/openapi.json"):
        assert client.get(path).status_code in (403, 404), path


def test_spa_fallback_serves_index_for_unknown_paths(client):
    """Unknown non-API paths belong to the SPA and must return the shell."""
    r = client.get("/some/deep/spa/route")
    assert r.status_code == 200
    assert 'id="root"' in r.text


def test_unknown_api_paths_are_json_404(client):
    """The SPA must never swallow a mistyped API path."""
    r = client.get("/api/definitely-not-a-route")
    assert r.status_code == 404
    assert "Not found" in r.text


def test_login_rate_limit_blocks_bruteforce(client, admin, monkeypatch):
    """Repeated failures must lock the account out."""
    for _ in range(15):
        login(client, "admin", "wrong-password", ok=False)
    r = login(client, "admin", "Str0ngPassw0rd!", ok=False)
    assert r.status_code in (401, 423, 429)