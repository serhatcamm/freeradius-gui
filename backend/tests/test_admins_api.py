"""Administrator management endpoint tests.

The assertions that matter here are the guardrails: a mistaken role change or
deactivation must not be able to lock the last administrator out of the panel,
and losing access must take effect immediately rather than at session expiry.

Clients are created per session rather than via the ``client`` fixture because
several tests need two independent sessions alive at the same time.
"""
from __future__ import annotations

from contextlib import ExitStack

import pytest
from fastapi.testclient import TestClient

from app.main import app
from conftest import (  # noqa: F401
    ADMIN_PASSWORD,
    OPERATOR_PASSWORD,
    VIEWER_PASSWORD,
    csrf_headers,
    login,
)

NEW_PASSWORD = "N3wAdminPassw0rd!"

_ip = iter(range(1, 400))


@pytest.fixture
def browser(env, admin):
    """A factory for independent clients, optionally already logged in.

    Login throttling is keyed on source IP as well as username, so each client
    gets its own address; otherwise one test's deliberate failures would lock
    out the next.
    """
    stack = ExitStack()

    def make(username: str | None = None, password: str | None = None) -> TestClient:
        client = stack.enter_context(TestClient(app))
        n = next(_ip)
        client.headers["X-Forwarded-For"] = f"10.99.{n // 250}.{n % 250}"
        if username is not None:
            login(client, username, password or ADMIN_PASSWORD)
        return client

    yield make
    stack.close()


@pytest.fixture
def root(browser):
    return browser("admin")


def create(client, username="second", role="operator", password=NEW_PASSWORD):
    return client.post(
        "/api/administrators",
        json={"username": username, "password": password, "role": role},
        headers=csrf_headers(client),
    )


# -- listing ------------------------------------------------------------
def test_lists_administrators_with_session_count(root):
    body = root.get("/api/administrators").json()
    assert body["count"] == 1
    entry = body["administrators"][0]
    assert entry["username"] == "admin"
    assert entry["role"] == "admin"
    assert entry["is_active"] is True
    assert entry["session_count"] == 1
    assert entry["is_self"] is True
    assert body["active_admin_count"] == 1


def test_viewer_cannot_list_administrators(browser, viewer):
    client = browser("viewer", VIEWER_PASSWORD)
    assert client.get("/api/administrators").status_code == 403


def test_operator_cannot_list_administrators(browser, operator):
    client = browser("operator", OPERATOR_PASSWORD)
    assert client.get("/api/administrators").status_code == 403


def test_anonymous_cannot_list_administrators(browser):
    assert browser().get("/api/administrators").status_code == 401


# -- creation -----------------------------------------------------------
def test_created_administrator_can_log_in(root, browser):
    assert create(root).status_code == 201

    fresh = browser()
    assert login(fresh, "second", NEW_PASSWORD).status_code == 200


def test_created_role_is_honoured(root):
    create(root, username="readers", role="viewer")
    body = root.get("/api/administrators").json()
    entry = next(r for r in body["administrators"] if r["username"] == "readers")
    assert entry["role"] == "viewer"


def test_new_account_cannot_manage_administrators(root, browser):
    create(root, username="readers", role="viewer")
    reader = browser("readers", NEW_PASSWORD)
    assert reader.get("/api/administrators").status_code == 403
    assert create(reader, username="sneaky").status_code == 403


def test_rejects_password_that_passes_length_but_fails_policy(root):
    """Long enough for the schema, still rejected by the password policy.

    The policy enforces length and surrounding whitespace only - it deliberately
    does not demand character classes, so the only way to reach the policy error
    as a 400 (rather than the schema's 422) is leading or trailing whitespace.
    """
    response = create(root, username="padded", password=" N3wAdminPassw0rd!")
    assert response.status_code == 400
    assert root.get("/api/administrators").json()["count"] == 1


def test_rejects_unknown_role(root):
    assert create(root, username="super", role="superuser").status_code == 400


def test_rejects_duplicate_username(root):
    assert create(root, username="dupe").status_code == 201
    assert create(root, username="dupe").status_code == 400
    assert root.get("/api/administrators").json()["count"] == 2


def test_rejects_invalid_username_characters(root):
    assert create(root, username="bad user!").status_code == 400


# -- self-protection ----------------------------------------------------
def test_cannot_change_own_role(root):
    response = root.patch(
        "/api/administrators/admin", json={"role": "viewer"}, headers=csrf_headers(root)
    )
    assert response.status_code == 400
    assert "own role" in response.json()["detail"]


def test_cannot_disable_own_account_via_patch(root):
    response = root.patch(
        "/api/administrators/admin", json={"is_active": False}, headers=csrf_headers(root)
    )
    assert response.status_code == 400
    assert "own account" in response.json()["detail"]


def test_cannot_delete_own_account(root):
    response = root.request("DELETE", "/api/administrators/admin", headers=csrf_headers(root))
    assert response.status_code == 400


def test_can_still_rename_own_full_name(root):
    response = root.patch(
        "/api/administrators/admin",
        json={"full_name": "Primary Operator"},
        headers=csrf_headers(root),
    )
    assert response.status_code == 200
    assert response.json()["full_name"] == "Primary Operator"


# -- last-admin protection ----------------------------------------------
def test_cannot_demote_the_last_admin_from_another_operator(browser, admin):
    root = browser("admin")
    create(root, username="op", role="operator")

    # An operator cannot demote anyone, admin or not.
    operator = browser("op", NEW_PASSWORD)
    assert operator.get("/api/administrators").status_code == 403

    # The remaining admin demoting themselves is refused.
    response = root.patch(
        "/api/administrators/admin", json={"role": "viewer"}, headers=csrf_headers(root)
    )
    assert response.status_code == 400
    assert "own role" in response.json()["detail"]


def test_cannot_deactivate_the_last_admin_from_another_admin(root, browser):
    create(root, username="second-admin", role="admin")
    # Two admins exist, so deactivating the actor's own account is still refused.
    assert root.request(
        "DELETE", "/api/administrators/admin", headers=csrf_headers(root)
    ).status_code == 400

    other = browser("second-admin", NEW_PASSWORD)
    response = other.request(
        "DELETE", "/api/administrators/admin", headers=csrf_headers(other)
    )
    assert response.status_code == 200

    # Now only one admin is left and cannot be removed by itself.
    assert other.request(
        "DELETE", "/api/administrators/second-admin", headers=csrf_headers(other)
    ).status_code == 400


def test_last_admin_guard_fires_for_a_non_admin_actor(env, admin, viewer):
    """The invariant, exercised the only way it can actually trigger.

    Through the API the actor is always an active admin, so the actor's own
    account already satisfies "an admin remains". Calling the service with a
    viewer as the actor is what proves the guard is not just dead code.
    """
    from app.core import db as db_mod
    from app.models.db import Administrator
    from app.services import admins as admins_service

    with db_mod.get_sessionmaker()() as db:
        actor = db.get(Administrator, viewer.id)
        target = db.get(Administrator, admin.id)
        with pytest.raises(admins_service.AdminError) as excinfo:
            admins_service.update_administrator(
                db, actor, target, role="operator", full_name=None, is_active=None, source_ip=None
            )
    assert "last active administrator" in str(excinfo.value)


# -- role changes -------------------------------------------------------
def test_role_change_applies_to_a_live_session(root, browser):
    create(root, username="promote", role="viewer")
    reader = browser("promote", NEW_PASSWORD)
    assert reader.get("/api/administrators").status_code == 403

    assert root.patch(
        "/api/administrators/promote", json={"role": "admin"}, headers=csrf_headers(root)
    ).status_code == 200

    # No re-login: the point is that the existing session is re-evaluated.
    assert reader.get("/api/administrators").status_code == 200


def test_demotion_applies_to_a_live_session(root, browser):
    create(root, username="demote", role="admin")
    colleague = browser("demote", NEW_PASSWORD)
    assert colleague.get("/api/administrators").status_code == 200

    assert root.patch(
        "/api/administrators/demote", json={"role": "viewer"}, headers=csrf_headers(root)
    ).status_code == 200

    assert colleague.get("/api/administrators").status_code == 403
    # Still a valid session, just with fewer rights.
    assert colleague.get("/api/auth/me").status_code == 200


# -- deactivation and sessions ------------------------------------------
def test_deactivation_signs_out_active_sessions(root, browser):
    create(root, username="leaver", role="operator")
    leaver = browser("leaver", NEW_PASSWORD)
    assert leaver.get("/api/auth/me").status_code == 200

    assert root.request(
        "DELETE", "/api/administrators/leaver", headers=csrf_headers(root)
    ).status_code == 200

    # The old cookie stops working at once, not at session expiry.
    assert leaver.get("/api/auth/me").status_code == 401
    # Re-authenticating is refused too: the account still exists, but disabled.
    assert login(leaver, "leaver", NEW_PASSWORD, ok=False).status_code == 403


def test_deactivation_is_reversible(root, browser):
    create(root, username="returner", role="operator")
    root.request("DELETE", "/api/administrators/returner", headers=csrf_headers(root))
    response = root.patch(
        "/api/administrators/returner", json={"is_active": True}, headers=csrf_headers(root)
    )
    assert response.status_code == 200
    assert response.json()["is_active"] is True
    assert login(browser(), "returner", NEW_PASSWORD).status_code == 200


# -- password reset -----------------------------------------------------
def test_password_reset_changes_credential_and_signs_out_sessions(root, browser):
    create(root, username="rotator", role="operator")
    rotator = browser("rotator", NEW_PASSWORD)

    assert root.post(
        "/api/administrators/rotator/password",
        json={"new_password": "Rotat3dPassw0rd!"},
        headers=csrf_headers(root),
    ).status_code == 200

    assert rotator.get("/api/auth/me").status_code == 401
    assert login(browser(), "rotator", NEW_PASSWORD, ok=False).status_code == 401
    assert login(browser(), "rotator", "Rotat3dPassw0rd!").status_code == 200


def test_cannot_reset_own_password_through_admin_endpoint(root, browser):
    response = root.post(
        "/api/administrators/admin/password",
        json={"new_password": "SelfServ1cePass!"},
        headers=csrf_headers(root),
    )
    assert response.status_code == 400
    assert "self-service" in response.json()["detail"]
    # The existing password is untouched, so a locked-out operator can get back in.
    assert login(browser(), "admin", ADMIN_PASSWORD).status_code == 200


def test_password_reset_rejects_policy_violation(root, browser):
    """A rejected reset must leave the old password working."""
    create(root, username="target")
    response = root.post(
        "/api/administrators/target/password",
        json={"new_password": " PaddedPassw0rd!"},
        headers=csrf_headers(root),
    )
    assert response.status_code == 400
    assert login(browser(), "target", NEW_PASSWORD).status_code == 200


def test_password_reset_clears_failed_attempts(root, browser):
    create(root, username="counted")
    target = browser()
    for _ in range(3):
        target.post("/api/auth/login", json={"username": "counted", "password": "wrong-on-purpose"})

    body = root.get("/api/administrators").json()
    entry = next(r for r in body["administrators"] if r["username"] == "counted")
    assert entry["failed_attempts"] == 3

    root.post(
        "/api/administrators/counted/password",
        json={"new_password": "Res3tPassw0rd!"},
        headers=csrf_headers(root),
    )
    body = root.get("/api/administrators").json()
    entry = next(r for r in body["administrators"] if r["username"] == "counted")
    assert entry["failed_attempts"] == 0


# -- unlock -------------------------------------------------------------
def test_unlock_clears_failure_counters(root):
    create(root, username="locked")
    for _ in range(3):
        root.post("/api/auth/login", json={"username": "locked", "password": "wrong-on-purpose"})

    body = root.get("/api/administrators").json()
    entry = next(r for r in body["administrators"] if r["username"] == "locked")
    assert entry["failed_attempts"] == 3

    assert root.post(
        "/api/administrators/locked/unlock", headers=csrf_headers(root)
    ).status_code == 200

    body = root.get("/api/administrators").json()
    entry = next(r for r in body["administrators"] if r["username"] == "locked")
    assert entry["failed_attempts"] == 0
    assert entry["locked_until"] is None


# -- auditing -----------------------------------------------------------
def test_mutations_are_audited(root):
    create(root, username="watched", role="viewer")
    root.patch(
        "/api/administrators/watched", json={"role": "operator"}, headers=csrf_headers(root)
    )
    actions = {e["action"] for e in root.get("/api/audit?limit=200").json()["entries"]}
    assert "ADMIN_CREATED" in actions
    assert "ADMIN_UPDATED" in actions


def test_audit_never_contains_the_password(root):
    create(root, username="secretive", password="Unl3akableSecret!")
    assert "Unl3akableSecret!" not in root.get("/api/audit?limit=200").text


def test_deactivation_is_audited(root):
    create(root, username="departing")
    root.request("DELETE", "/api/administrators/departing", headers=csrf_headers(root))
    actions = {e["action"] for e in root.get("/api/audit?limit=200").json()["entries"]}
    assert "ADMIN_DEACTIVATED" in actions


# -- unknown targets ----------------------------------------------------
def test_unknown_username_is_404(root):
    response = root.patch(
        "/api/administrators/nobody", json={"role": "viewer"}, headers=csrf_headers(root)
    )
    assert response.status_code == 404


def test_creation_requires_admin_role(browser, viewer):
    client = browser("viewer", VIEWER_PASSWORD)
    assert create(client, username="sneaky").status_code == 403