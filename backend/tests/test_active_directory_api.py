"""Active Directory API tests.

The panel must be able to store and show an AD configuration on a host that
has neither winbind nor a domain, and it must refuse to *enable* AD there
rather than writing config that cannot work. Those are the properties checked
here; nothing connects to a domain.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import csrf_headers, login

from app.services import active_directory as ad

BASE_DN = "dc=corp,dc=example,dc=com"
BIND_DN = "cn=svc-radius,ou=svc,dc=corp,dc=example,dc=com"
BIND_PASSWORD = "Bind-Secret-Not-Real-42"
AD_GROUP = "CN=RADIUS-STAFF,OU=Groups,dc=corp,dc=example,dc=com"

pytestmark = pytest.mark.usefixtures("env")


def put(client, **overrides):
    """PUT the settings with a CSRF header, like the browser does."""
    return client.put("/api/active-directory", json=payload(**overrides), headers=csrf_headers(client))


def post(client, path: str):
    return client.post(path, headers=csrf_headers(client))


def payload(**overrides) -> dict:
    body = {
        "domain": "corp.example.com",
        "base_dn": BASE_DN,
        "bind_dn": BIND_DN,
        "servers": ["dc1.corp.example.com"],
        "bind_password": BIND_PASSWORD,
        "group_map": {AD_GROUP: "staff"},
    }
    body.update(overrides)
    return body


def satisfied(monkeypatch, monkey: pytest.MonkeyPatch | None = None) -> None:
    """Pretend every local prerequisite is met."""
    monkeypatch.setattr(ad, "ldap_module_exists", lambda: True)
    monkeypatch.setattr(ad, "ntlm_auth_available", lambda: True)
    monkeypatch.setattr(ad, "winbind_installed", lambda: True)
    monkeypatch.setattr(ad, "winbind_joined", lambda: True)


# -- access control -----------------------------------------------------
def test_requires_authentication(client):
    assert client.get("/api/active-directory").status_code == 401


def test_viewer_cannot_read_ad_settings(client, viewer):
    login(client, "viewer", "V1ewerPassw0rd!")
    r = client.get("/api/active-directory")
    assert r.status_code == 403


def test_operator_cannot_configure_ad(client, operator):
    login(client, "operator", "Oper4torPassw0rd!")
    assert put(client).status_code == 403


def test_admin_can_read_status(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    r = client.get("/api/active-directory")
    assert r.status_code == 200
    assert r.json()["configured"] is False


# -- status -------------------------------------------------------------
def test_unconfigured_status_lists_prerequisites(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    body = client.get("/api/active-directory").json()
    assert body["configured"] is False
    assert body["bind_password_set"] is False
    assert isinstance(body["ldap_module_installed"], bool)
    names = {p["name"] for p in body["prerequisites"]}
    assert {"freeradius-ldap", "ntlm_auth module", "winbind", "domain membership"} == names


# -- storing settings ---------------------------------------------------
def test_admin_can_store_settings_without_enabling(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    r = put(client)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["configured"] is True
    assert body["enabled"] is False, "storing settings must not enable AD on its own"
    assert body["domain"] == "corp.example.com"
    assert body["group_map"] == {AD_GROUP: "staff"}
    assert body["bind_password_set"] is True


def test_bind_password_is_never_returned(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    put(client)
    for path in ("/api/active-directory",):
        assert BIND_PASSWORD not in client.get(path).text


def test_omitting_the_password_keeps_the_stored_one(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    put(client)

    update = payload(domain="new.example.com")
    update.pop("bind_password")
    r = client.put("/api/active-directory", json=update, headers=csrf_headers(client))
    assert r.status_code == 200
    assert r.json()["domain"] == "new.example.com"
    assert r.json()["bind_password_set"] is True, (
        "dropping the password from an unrelated update must not clear it"
    )


def test_rejects_a_plain_ldap_bind(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    r = put(client, start_tls=False, use_ldaps=False)
    assert r.status_code == 400
    assert "StartTLS" in r.json()["detail"]


def test_rejects_duplicate_radius_groups(client, admin):
    """Two AD groups claiming one RADIUS group would make the effective
    mapping depend on dictionary order."""
    login(client, "admin", "Str0ngPassw0rd!")
    r = put(
        client,
        group_map={
            "CN=A,OU=Groups," + BASE_DN: "staff",
            "CN=B,OU=Groups," + BASE_DN: "staff",
        },
    )
    assert r.status_code == 400
    assert "two AD groups" in r.json()["detail"]


def test_rejects_an_invalid_dn(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    r = put(client, base_dn="nope")
    assert r.status_code == 400


def test_rejects_unknown_fields(client, admin):
    """extra="forbid" so a typo in a security-relevant field cannot be
    silently ignored."""
    login(client, "admin", "Str0ngPassw0rd!")
    r = put(client, use_ldaps_please=True)
    assert r.status_code == 422


def test_short_password_is_rejected_by_the_schema(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    r = put(client, bind_password="short")
    assert r.status_code == 422


# -- enabling -----------------------------------------------------------
def test_cannot_enable_without_the_prerequisites(client, admin):
    """The test host has no winbind; enabling must fail with an explanation
    rather than writing config that cannot authenticate anyone."""
    login(client, "admin", "Str0ngPassw0rd!")
    r = put(client, enable=True)
    assert r.status_code == 409, r.text
    body = r.json()["detail"]
    assert "winbind" in body or "domain membership" in body


def test_enabling_is_refused_even_when_settings_were_already_stored(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    put(client)
    r = put(client, enable=True)
    assert r.status_code == 409


def test_enable_writes_the_module_and_site(client, admin, monkeypatch, tmp_path):
    """With the prerequisites satisfied and the raddb sandboxed, enabling
    installs the managed block through the normal transactional path."""
    raddb = tmp_path / "raddb-ad"
    (raddb / "mods-available").mkdir(parents=True)
    (raddb / "sites-available").mkdir(parents=True)
    (raddb / "mods-available" / "ldap").write_text(
        (Path("/etc/freeradius/3.0/mods-available/ldap")).read_text("utf-8"),
        encoding="utf-8",
    )
    (raddb / "sites-available" / "default").write_text(
        Path("/etc/freeradius/3.0/sites-available/default").read_text("utf-8"),
        encoding="utf-8",
    )

    from app.freeradius import paths as paths_mod

    monkeypatch.setattr(paths_mod, "SITES_AVAILABLE", raddb / "sites-available")
    monkeypatch.setattr(paths_mod, "MODS_AVAILABLE", raddb / "mods-available")
    monkeypatch.setattr(paths_mod, "BACKUP_DIR", tmp_path / "backups")
    satisfied(monkeypatch)

    login(client, "admin", "Str0ngPassw0rd!")
    r = put(client, enable=True)
    assert r.status_code == 200, r.text
    assert r.json()["enabled"] is True
    assert r.json()["ldap_block_installed"] is True

    module = (raddb / "mods-available" / "ldap").read_text("utf-8")
    assert ad._LDAP_BEGIN in module
    assert BIND_PASSWORD in module
    site = (raddb / "sites-available" / "default").read_text("utf-8")
    assert ad._AUTHZ_BEGIN in site and ad._POSTAUTH_BEGIN in site
    # The distro ldap instance remains disabled; the managed ldap_ad instance
    # is the one AD uses.
    assert "ldap_ad" in site
    assert "-ldap" in site


def test_disconnect_removes_the_block(client, admin, monkeypatch, tmp_path):
    raddb = tmp_path / "raddb-ad"
    (raddb / "mods-available").mkdir(parents=True)
    (raddb / "sites-available").mkdir(parents=True)
    (raddb / "mods-available" / "ldap").write_text(
        ad.install_ldap_block(
            ad.AdSettings(
                domain="corp.example.com",
                base_dn=BASE_DN,
                bind_dn=BIND_DN,
                servers=["dc1.corp.example.com"],
                bind_password=BIND_PASSWORD,
            ),
            "",
        ),
        encoding="utf-8",
    )
    (raddb / "sites-available" / "default").write_text(
        ad.install_authorize_block(
            Path("/etc/freeradius/3.0/sites-available/default").read_text("utf-8")
        ),
        encoding="utf-8",
    )

    from app.freeradius import paths as paths_mod

    monkeypatch.setattr(paths_mod, "SITES_AVAILABLE", raddb / "sites-available")
    monkeypatch.setattr(paths_mod, "MODS_AVAILABLE", raddb / "mods-available")
    monkeypatch.setattr(paths_mod, "BACKUP_DIR", tmp_path / "backups")
    satisfied(monkeypatch)

    login(client, "admin", "Str0ngPassw0rd!")
    put(client, enable=True)

    r = post(client, "/api/active-directory/disconnect")
    assert r.status_code == 200, r.text
    module = (raddb / "mods-available" / "ldap").read_text("utf-8")
    assert ad._LDAP_BEGIN not in module
    site = (raddb / "sites-available" / "default").read_text("utf-8")
    assert ad._AUTHZ_BEGIN not in site
    assert ad._POSTAUTH_BEGIN not in site
    assert client.get("/api/active-directory").json()["enabled"] is False


def test_disconnect_without_configuration_is_404(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    assert post(client, "/api/active-directory/disconnect").status_code == 404


# -- audit --------------------------------------------------------------
def test_enabling_is_audited_without_the_password(client, admin, monkeypatch, tmp_path):
    raddb = tmp_path / "raddb-ad"
    (raddb / "mods-available").mkdir(parents=True)
    (raddb / "sites-available").mkdir(parents=True)
    (raddb / "mods-available" / "ldap").write_text("ldap {\n}\n", encoding="utf-8")
    (raddb / "sites-available" / "default").write_text(
        Path("/etc/freeradius/3.0/sites-available/default").read_text("utf-8"),
        encoding="utf-8",
    )

    from app.freeradius import paths as paths_mod

    monkeypatch.setattr(paths_mod, "SITES_AVAILABLE", raddb / "sites-available")
    monkeypatch.setattr(paths_mod, "MODS_AVAILABLE", raddb / "mods-available")
    monkeypatch.setattr(paths_mod, "BACKUP_DIR", tmp_path / "backups")
    satisfied(monkeypatch)

    login(client, "admin", "Str0ngPassw0rd!")
    put(client, enable=True)

    rows = client.get("/api/audit?limit=50").json()["entries"]
    actions = {row["action"] for row in rows}
    assert "AD_ENABLED" in actions
    assert "AD_CONFIGURED" in actions
    rendered = json.dumps(rows)
    assert BIND_PASSWORD not in rendered


def test_audited_password_rotation_when_stored_only(client, admin):
    login(client, "admin", "Str0ngPassw0rd!")
    put(client)
    rows = client.get("/api/audit?limit=50").json()["entries"]
    assert "AD_CONFIGURED" in {row["action"] for row in rows}
    assert BIND_PASSWORD not in json.dumps(rows)
