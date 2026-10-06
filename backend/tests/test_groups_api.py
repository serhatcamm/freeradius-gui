"""Group endpoints, including the roles and the groupfile-enabled warning."""
from __future__ import annotations

import pytest

from app.freeradius import paths as paths_mod
from conftest import csrf_headers, diagnose, login  # noqa: F401


def _diagnose(c) -> str:
    return diagnose(c)


@pytest.fixture
def groups_env(tmp_path, monkeypatch):
    """Point the groups service at a temp file and keep the users file sane."""
    groups = tmp_path / "groups"
    users = tmp_path / "authorize"
    users.write_text('alice\tCleartext-Password := "x"\n\tGroup = staff\n')

    monkeypatch.setattr(paths_mod, "GROUPS_FILE", groups)
    monkeypatch.setitem(paths_mod.MANAGED_FILES, "groups", groups)
    monkeypatch.setattr(paths_mod, "USERS_FILE", users)
    return groups


# -- roles --------------------------------------------------------------
def test_viewer_can_list_groups(client, viewer, groups_env):
    login(client, "viewer", "V1ewerPassw0rd!")
    r = client.get("/api/groups")
    assert r.status_code == 200, r.text
    assert r.json() == []


def test_viewer_cannot_create_group(client, viewer, groups_env):
    login(client, "viewer", "V1ewerPassw0rd!")
    r = client.post(
        "/api/groups",
        json={"name": "staff", "attributes": []},
        headers=csrf_headers(client),
    )
    assert r.status_code == 403, r.text


def test_operator_can_create_group(client, operator, groups_env):
    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post(
        "/api/groups",
        json={
            "name": "staff",
            "attributes": [{"key": "Reply-Message", "value": "hi", "reply": True}],
        },
        headers=csrf_headers(client),
    )
    assert r.status_code == 201, f"{r.status_code} {r.text} :: {_diagnose(client)}"
    assert r.json()["name"] == "staff"


def test_group_get_includes_members(client, operator, groups_env):
    login(client, "operator", "Oper4torPassw0rd!")
    client.post(
        "/api/groups",
        json={"name": "staff", "attributes": []},
        headers=csrf_headers(client),
    )
    r = client.get("/api/groups/staff")
    assert r.status_code == 200, r.text
    assert r.json()["members"] == ["alice"]


def test_group_get_missing_is_404(client, operator, groups_env):
    login(client, "operator", "Oper4torPassw0rd!")
    assert client.get("/api/groups/nope").status_code == 404


def test_update_and_delete(client, operator, groups_env):
    login(client, "operator", "Oper4torPassw0rd!")
    client.post(
        "/api/groups",
        json={"name": "staff", "attributes": []},
        headers=csrf_headers(client),
    )
    r = client.patch(
        "/api/groups/staff",
        json={"attributes": [{"key": "Session-Timeout", "value": "60"}]},
        headers=csrf_headers(client),
    )
    assert r.status_code == 200, f"{r.status_code} {r.text}"
    r = client.delete("/api/groups/staff", headers=csrf_headers(client))
    assert r.status_code == 200, f"{r.status_code} {r.text}"
    assert client.get("/api/groups/staff").status_code == 404


def test_duplicate_create_is_400(client, operator, groups_env):
    login(client, "operator", "Oper4torPassw0rd!")
    body = {"name": "staff", "attributes": []}
    assert client.post("/api/groups", json=body, headers=csrf_headers(client)).status_code == 201
    r = client.post("/api/groups", json=body, headers=csrf_headers(client))
    assert r.status_code == 400, r.text


def test_forbidden_attribute_is_400(client, operator, groups_env):
    """A group must not be able to change how auth is processed."""
    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post(
        "/api/groups",
        json={"name": "evil", "attributes": [{"key": "Auth-Type", "value": "Accept"}]},
        headers=csrf_headers(client),
    )
    assert r.status_code == 400, r.text
    assert client.get("/api/groups/evil").status_code == 404


# -- status endpoint ----------------------------------------------------
def test_status_reports_groupfile_state(client, operator, tmp_path, monkeypatch):
    mods = tmp_path / "mods-available"
    mods.mkdir()
    (mods / "files").write_text("files {\n\tmoddir = ${modconfdir}/files\n}\n")
    monkeypatch.setattr(paths_mod, "MODS_AVAILABLE", mods)

    login(client, "operator", "Oper4torPassw0rd!")
    r = client.get("/api/groups/status")
    assert r.status_code == 200, r.text
    body = r.json()
    # The warning must be visible: edits would otherwise silently do nothing.
    assert body["enabled"] is False
    assert body["module_file"].endswith("files")
    assert body["groups"] == []


def test_status_reports_enabled_groupfile(client, operator, tmp_path, monkeypatch):
    mods = tmp_path / "mods-available"
    mods.mkdir()
    (mods / "files").write_text(
        "files {\n\tmoddir = ${modconfdir}/files\n\tgroupfile = ${moddir}/groups\n}\n"
    )
    monkeypatch.setattr(paths_mod, "MODS_AVAILABLE", mods)

    login(client, "operator", "Oper4torPassw0rd!")
    r = client.get("/api/groups/status")
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True


def test_unsafe_write_without_csrf_is_403(client, operator, groups_env):
    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post("/api/groups", json={"name": "staff", "attributes": []})
    assert r.status_code == 403