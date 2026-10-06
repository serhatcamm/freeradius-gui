"""Tests for the request-logging endpoints.

Enabling request logging edits two files. The tests pin the RBAC boundary and
the enable/disable round trip against real (copied) FreeRADIUS files.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from conftest import csrf_headers, login

# Mirrors the real sites-available/default layout: section names are not
# indented even though they sit inside `server`.
SITES_DEFAULT = """\
server localhost {
listen {
	type = auth
}
listen {
	type = acct
}
listen {
	type = inner-tunnel
}
authorize {
	filter_username
	preprocess
	authenticate {
	}
	postauth {
	}
}
authenticate {
	eapol
	%{if "%{sql}" == ""}
	%{else}
		sql
	%{endif}
	%{if "%{called_station_id}" =~ /^:/}
	%{else}
		files
	%{endif}
	%{if "%{username}" =~ "[@/]$"}
	%{else}
		pap
	%{endif}
}
preacct {
	preprocess
	acct_unique
}
postauth {
	Post-Auth-Type REJECT {
	}
}
}

server inner-tunnel {
listen {
	type = inner-tunnel
}
authorize {
}
authenticate {
}
postauth {
	Post-Auth-Type REJECT {
	}
}
}
"""

LINELOG_MOD = """\
linelog {
    file = ${logdir}/linelog
    permissions = 0644
    radiusd {
        ok = info
        bad = warn
    }
    linelog_accounting {
        detail = detail
    }
}
"""


@pytest.fixture
def logging_tree(tmp_path, monkeypatch):
    """Add sites-available/default and mods-available/linelog to the sandbox.

    The ``env`` fixture has already created the raddb tree and the managed
    users/clients files, so this only adds the two files the request-logging
    feature touches and repoints the module-level paths at them.
    """
    import app.services.clients as clients_mod
    import app.services.users as users_mod

    raddb = tmp_path / "raddb"
    (raddb / "sites-available").mkdir(parents=True, exist_ok=True)
    (raddb / "mods-available").mkdir(parents=True, exist_ok=True)

    site = raddb / "sites-available" / "default"
    mod = raddb / "mods-available" / "linelog"
    site.write_text(SITES_DEFAULT, encoding="utf-8")
    mod.write_text(LINELOG_MOD, encoding="utf-8")

    paths = users_mod.paths
    monkeypatch.setattr(paths, "RADDB_DIR", raddb)
    monkeypatch.setattr(paths, "SITES_AVAILABLE", raddb / "sites-available")
    monkeypatch.setattr(paths, "MODS_AVAILABLE", raddb / "mods-available")
    monkeypatch.setattr(paths, "BACKUP_DIR", tmp_path / "backups")
    monkeypatch.setattr(clients_mod.paths, "BACKUP_DIR", tmp_path / "backups")
    return {"raddb": raddb, "site": site, "mod": mod}


# -- RBAC ----------------------------------------------------------------
def test_viewer_cannot_enable_request_logging(client, viewer, logging_tree):
    login(client, "viewer", "V1ewerPassw0rd!")
    r = client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))
    assert r.status_code == 403


def test_viewer_cannot_disable_request_logging(client, viewer, logging_tree):
    login(client, "viewer", "V1ewerPassw0rd!")
    r = client.post("/api/logs/disable-request-logging", headers=csrf_headers(client))
    assert r.status_code == 403


def test_operator_can_enable_request_logging(client, operator, logging_tree):
    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))
    assert r.status_code == 200, r.text
    assert r.json()["ok"] is True


def test_viewer_can_still_read_logs(client, viewer):
    login(client, "viewer", "V1ewerPassw0rd!")
    assert client.get("/api/logs").status_code == 200
    assert client.get("/api/logs/capability").status_code == 200


# -- behaviour -----------------------------------------------------------
def test_enable_installs_both_changes(client, operator, logging_tree):
    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))
    assert r.status_code == 200, r.text

    site = logging_tree["site"].read_text(encoding="utf-8")
    mod = logging_tree["mod"].read_text(encoding="utf-8")
    assert "linelog" in site
    assert "auth_goodpass" in mod
    assert "auth_badpass" in mod


def test_enable_preserves_unrelated_content(client, operator, logging_tree):
    login(client, "operator", "Oper4torPassw0rd!")
    client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))

    site = logging_tree["site"].read_text(encoding="utf-8")
    # Nothing outside the managed block may be lost.
    assert "eapol" in site
    assert "server localhost" in site
    assert "postauth" in site
    assert "server inner-tunnel" in site

    mod = logging_tree["mod"].read_text(encoding="utf-8")
    assert "linelog_accounting" in mod
    assert "permissions = 0644" in mod


def test_enable_reports_validation(client, operator, logging_tree):
    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))
    assert r.status_code == 200
    assert r.json()["validation"]["ok"] is True


def test_enable_is_idempotent(client, operator, logging_tree):
    """Running it twice must not stack duplicate linelog invocations."""
    login(client, "operator", "Oper4torPassw0rd!")
    client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))
    client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))

    site = logging_tree["site"].read_text(encoding="utf-8")
    assert site.count("\tlinelog") <= 1, site


def test_disable_removes_both_changes(client, operator, logging_tree):
    login(client, "operator", "Oper4torPassw0rd!")
    client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))
    r = client.post("/api/logs/disable-request-logging", headers=csrf_headers(client))
    assert r.status_code == 200, r.text

    site = logging_tree["site"].read_text(encoding="utf-8")
    mod = logging_tree["mod"].read_text(encoding="utf-8")
    assert "freeradius-web request logging" not in site
    assert "auth_goodpass" not in mod


def test_enable_alone_preserves_every_other_byte(client, operator, logging_tree):
    """Install must be a pure insertion."""
    login(client, "operator", "Oper4torPassw0rd!")
    client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))

    after = logging_tree["site"].read_text(encoding="utf-8")
    # Everything before the insertion point is byte-identical.
    assert after.startswith(SITES_DEFAULT.split("authenticate {")[0])
    assert "\teapol\n" in after, "existing indentation must be untouched"
    assert "\ttype = auth\n" in after


def test_enable_mod_file_is_a_pure_insertion(client, operator, logging_tree):
    login(client, "operator", "Oper4torPassw0rd!")
    client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))

    after = logging_tree["mod"].read_text(encoding="utf-8")
    assert after.startswith(LINELOG_MOD.split("linelog {")[0])
    assert "\tfile" not in after.split("# >>>")[0], "no reindentation"
    assert "\n    file = ${logdir}/linelog\n" in after
    assert "\n    permissions = 0644\n" in after


def test_disable_alone_preserves_every_other_byte(client, operator, logging_tree):
    login(client, "operator", "Oper4torPassw0rd!")
    client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))
    client.post("/api/logs/disable-request-logging", headers=csrf_headers(client))

    assert logging_tree["site"].read_text(encoding="utf-8") == SITES_DEFAULT
    assert logging_tree["mod"].read_text(encoding="utf-8") == LINELOG_MOD


def test_enable_disable_restores_original_bytes(client, operator, logging_tree):
    """The round trip must be lossless."""
    login(client, "operator", "Oper4torPassw0rd!")
    client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))
    client.post("/api/logs/disable-request-logging", headers=csrf_headers(client))

    assert logging_tree["site"].read_text(encoding="utf-8") == SITES_DEFAULT
    assert logging_tree["mod"].read_text(encoding="utf-8") == LINELOG_MOD


def test_missing_module_is_reported_not_crashed(client, operator, logging_tree):
    logging_tree["mod"].unlink()
    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] is False
    assert "not found" in body["error"]


def test_backups_are_created_for_both_files(client, operator, logging_tree):
    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))
    ids = r.json()["backup_ids"]
    assert len(ids) == 2, "each edited file needs its own backup"
    assert len(set(ids)) == 2


# -- all-or-nothing behaviour ---------------------------------------------
def _fail_after_first_write(monkeypatch, logging_tree):
    """Make validation reject only the *second* file of the group."""
    from app.freeradius.validate import ValidationResult

    site = logging_tree["site"]
    seen: list[bool] = []

    async def selective(binary=None):
        # First call validates after mods-available/linelog was written,
        # second after sites-available/default. Fail only the second.
        seen.append(True)
        ok = len(seen) == 1
        return ValidationResult(ok=ok, returncode=0 if ok else 1)

    from app.services import config_tx as config_tx_mod

    monkeypatch.setattr(config_tx_mod, "validate_config", selective)
    assert site.exists()


def test_enable_failure_rolls_back_both_files(client, operator, logging_tree, monkeypatch):
    """If the site edit fails, the module edit must not survive.

    Leaving `mods-available/linelog` configured while the site never invokes
    it is a half-installed feature: the panel would report failure but the host
    would be in a state nobody chose.
    """
    _fail_after_first_write(monkeypatch, logging_tree)
    login(client, "operator", "Oper4torPassw0rd!")
    r = client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))

    # The shared error handler turns a validation failure into 422.
    assert r.status_code == 422, r.text
    body = r.json()
    assert body["rolled_back"] is True, "compensation must have restored both files"

    assert logging_tree["site"].read_text(encoding="utf-8") == SITES_DEFAULT
    assert logging_tree["mod"].read_text(encoding="utf-8") == LINELOG_MOD


def test_disable_failure_rolls_back_both_files(client, operator, logging_tree, monkeypatch):
    """The same guarantee applies when turning the feature off."""
    login(client, "operator", "Oper4torPassw0rd!")
    enabled = client.post("/api/logs/enable-request-logging", headers=csrf_headers(client))
    assert enabled.status_code == 200, enabled.text

    enabled_site = logging_tree["site"].read_text(encoding="utf-8")
    enabled_mod = logging_tree["mod"].read_text(encoding="utf-8")
    assert enabled_site != SITES_DEFAULT

    _fail_after_first_write(monkeypatch, logging_tree)
    r = client.post("/api/logs/disable-request-logging", headers=csrf_headers(client))
    assert r.status_code == 422, r.text
    assert r.json()["rolled_back"] is True

    # Both files must be back in their *enabled* state, not partially removed.
    assert logging_tree["site"].read_text(encoding="utf-8") == enabled_site
    assert logging_tree["mod"].read_text(encoding="utf-8") == enabled_mod