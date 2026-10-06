"""Alert rule evaluation and endpoint tests.

Alert counting reads the same parsed log events the Logs page shows, so these
tests write real linelog/radius.log lines into a sandboxed log directory rather
than stubbing the counter.
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient

import app.services.alerts as alerts_mod
import app.services.logs as logs_mod
from app.freeradius import paths as paths_mod
from app.main import app
from app.models.db import Alert, AlertRule
from conftest import ADMIN_PASSWORD, VIEWER_PASSWORD, csrf_headers, login

_ip = iter(range(1, 400))


@pytest.fixture
def browser(env, admin):
    from contextlib import ExitStack

    stack = ExitStack()

    def make(username: str | None = None, password: str | None = None) -> TestClient:
        client = stack.enter_context(TestClient(app))
        n = next(_ip)
        client.headers["X-Forwarded-For"] = f"10.98.{n // 250}.{n % 250}"
        if username is not None:
            login(client, username, password or ADMIN_PASSWORD)
        return client

    yield make
    stack.close()


@pytest.fixture
def root(browser):
    return browser("admin")


@pytest.fixture
def logdir(tmp_path, monkeypatch):
    """Sandboxed log directory plus a writer for dated request lines."""
    monkeypatch.setattr(paths_mod, "LOG_DIR", tmp_path)
    (tmp_path / "linelog").write_text("", encoding="utf-8")
    (tmp_path / "radius.log").write_text("", encoding="utf-8")

    def write(rejects: int = 0, accepts: int = 0, user: str = "bob", client: str = "switch-a"):
        """Append request lines dated now, in the shape radius.log writes.

        Uses the spelled-out attribute names, not the panel's abbreviated
        ``nas=``/``client=``, so the parser is exercised the way a real server
        would feed it.
        """
        stamp = datetime.now().astimezone().strftime("%a %b %d %H:%M:%S %Y")
        lines = []
        for _ in range(rejects + accepts):
            result = "Access-Reject" if len(lines) < rejects else "Access-Accept"
            lines.append(
                f"{stamp} : Info: {result} : user={user}, "
                f"NAS-IP-Address=198.51.100.9, Called-Station-Id={client}"
            )
        if lines:
            with (tmp_path / "radius.log").open("a", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")

    write.path = tmp_path
    return write


@pytest.fixture
def db(db_session):
    return db_session


def make_rule(db, name="brute-force", metric="failures", threshold=5, window=3600, **kwargs):
    return alerts_mod.create_rule(db, "admin", name, metric, threshold, window, **kwargs)


# -- counting ------------------------------------------------------------
def test_counts_rejects_over_threshold(db, logdir):
    """``evaluate`` returns the observed count, not a fired/not-fired flag."""
    rule = make_rule(db, threshold=5)
    logdir(rejects=3)
    assert alerts_mod.evaluate(db, rule) == 3
    # Below the threshold, so nothing is recorded.
    assert alerts_mod.list_alerts(db) == []

    logdir(rejects=3)
    assert alerts_mod.evaluate(db, rule) == 6
    assert len(alerts_mod.list_alerts(db)) == 1


def test_threshold_of_one_fires_immediately(db, logdir):
    rule = make_rule(db, threshold=1)
    logdir(rejects=1)
    assert alerts_mod.evaluate(db, rule) == 1


def test_accepts_do_not_count_as_failures(db, logdir):
    rule = make_rule(db, threshold=2)
    logdir(accepts=10)
    assert alerts_mod.evaluate(db, rule) == 0


def test_username_scope_excludes_other_users(db, logdir):
    rule = make_rule(db, threshold=1, username="alice")
    logdir(rejects=5, user="bob")
    assert alerts_mod.evaluate(db, rule) == 0

    logdir(rejects=1, user="alice")
    assert alerts_mod.evaluate(db, rule) == 1


def test_username_scope_is_case_insensitive(db, logdir):
    rule = make_rule(db, threshold=1, username="Alice")
    logdir(rejects=1, user="aLiCe")
    assert alerts_mod.evaluate(db, rule) == 1


def test_events_outside_the_window_are_ignored(db, logdir):
    rule = make_rule(db, threshold=1, window=60)
    old = datetime.now().astimezone() - timedelta(hours=2)
    stamp = old.strftime("%a %b %d %H:%M:%S %Y")
    (logdir.path / "radius.log").write_text(
        f"{stamp} : Info: Access-Reject : user=carol, NAS-IP-Address=198.51.100.9\n",
        encoding="utf-8",
    )
    assert alerts_mod.evaluate(db, rule) == 0


def test_undated_linelog_lines_are_not_counted(db, logdir):
    """A bare linelog line has no timestamp, so it cannot be placed in a window."""
    rule = make_rule(db, threshold=1)
    (logdir.path / "linelog").write_text(
        "REJECT user=dave nas=198.51.100.9\n", encoding="utf-8"
    )
    assert alerts_mod.evaluate(db, rule) == 0


def test_disabled_rule_is_not_evaluated(db, logdir):
    rule = make_rule(db, threshold=1)
    rule.enabled = False
    db.commit()
    logdir(rejects=5)
    assert alerts_mod.evaluate(db, rule) == 0


# -- alert lifecycle -----------------------------------------------------
def test_evaluation_raises_one_alert(db, logdir):
    rule = make_rule(db, threshold=2)
    logdir(rejects=5)
    alerts_mod.evaluate(db, rule)
    rows = alerts_mod.list_alerts(db)
    assert len(rows) == 1
    assert rows[0].observed == 5
    assert rows[0].rule_id == rule.id


def test_sustained_condition_does_not_duplicate_alerts(db, logdir):
    rule = make_rule(db, threshold=2)
    logdir(rejects=5)
    for _ in range(5):
        alerts_mod.evaluate(db, rule)
    assert len(alerts_mod.list_alerts(db)) == 1
    # Each pass still reports the live count, so a stale total is never shown.
    assert alerts_mod.evaluate(db, rule) == 5


def test_alert_refires_after_the_window(db, logdir):
    from app.models.db import utcnow

    rule = make_rule(db, threshold=2, window=60)
    logdir(rejects=5)
    alerts_mod.evaluate(db, rule)
    assert len(alerts_mod.list_alerts(db)) == 1

    # Rewind last_fired_at past the window to simulate time passing.
    rule.last_fired_at = utcnow() - timedelta(seconds=120)
    db.commit()
    logdir(rejects=1)
    alerts_mod.evaluate(db, rule)
    assert len(alerts_mod.list_alerts(db)) == 2


def test_acknowledging_records_who_and_when(db, logdir):
    rule = make_rule(db, threshold=1)
    logdir(rejects=1)
    alerts_mod.evaluate(db, rule)
    alert = alerts_mod.list_alerts(db)[0]
    alerts_mod.acknowledge(db, alert, "admin")
    assert alert.acknowledged_by == "admin"
    assert alert.acknowledged_at is not None


def test_deleting_a_rule_removes_its_alerts(db, logdir):
    rule = make_rule(db, threshold=1)
    logdir(rejects=1)
    alerts_mod.evaluate(db, rule)
    alerts_mod.delete_rule(db, rule)
    assert alerts_mod.list_alerts(db) == []
    assert db.query(Alert).count() == 0


# -- validation ----------------------------------------------------------
@pytest.mark.parametrize(
    "kwargs",
    [
        {"metric": "nonsense"},
        {"threshold": 0},
        {"threshold": 100_001},
        {"window_seconds": 30},
        {"window_seconds": 999_999_999},
        {"username": "has space"},
        {"client": "has space"},
    ],
)
def test_invalid_configuration_is_rejected(db, kwargs):
    base = {"name": "rule", "metric": "failures", "threshold": 5, "window_seconds": 3600}
    base.update(kwargs)
    with pytest.raises(alerts_mod.AlertConfigError):
        alerts_mod.create_rule(db, "admin", **base)


def test_duplicate_rule_name_is_rejected(db):
    make_rule(db, name="twice")
    with pytest.raises(alerts_mod.AlertConfigError):
        make_rule(db, name="twice")


# -- endpoints -----------------------------------------------------------
def test_create_list_and_evaluate_through_the_api(root, logdir):
    response = root.post(
        "/api/alerts/rules",
        json={
            "name": "wifi-brute-force",
            "metric": "failures",
            "threshold": 3,
            "window_seconds": 900,
            "client": "switch-a",
        },
        headers=csrf_headers(root),
    )
    assert response.status_code == 201, response.text
    rule_id = response.json()["id"]

    logdir(rejects=4)
    rules = root.get("/api/alerts/rules").json()
    rule = next(r for r in rules if r["id"] == rule_id)
    assert rule["observed"] == 4
    assert rule["would_fire"] is True
    assert rule["metric_label"] == "Failed authentications"

    alerts = root.get("/api/alerts").json()
    assert alerts["count"] == 1
    assert alerts["alerts"][0]["rule_name"] == "wifi-brute-force"


def test_invalid_rule_is_a_400(root):
    response = root.post(
        "/api/alerts/rules",
        json={"name": "bad", "metric": "failures", "threshold": 0, "window_seconds": 600},
        headers=csrf_headers(root),
    )
    assert response.status_code == 400


def test_operator_can_read_rules_but_not_create_them(browser, logdir, viewer):
    root = browser("admin")
    root.post(
        "/api/alerts/rules",
        json={
            "name": "some-rule",
            "metric": "failures",
            "threshold": 5,
            "window_seconds": 600,
        },
        headers=csrf_headers(root),
    )
    root.post("/api/auth/logout", headers=csrf_headers(root))

    # A viewer may read and an operator may acknowledge, but only an admin may
    # change what the panel watches for.
    viewer = browser("viewer", VIEWER_PASSWORD)
    assert viewer.get("/api/alerts/rules").status_code == 200
    response = viewer.post(
        "/api/alerts/rules",
        json={"name": "x", "metric": "failures", "threshold": 1, "window_seconds": 600},
        headers=csrf_headers(viewer),
    )
    assert response.status_code == 403


def test_rule_patch_and_delete(root, logdir):
    created = root.post(
        "/api/alerts/rules",
        json={"name": "temp", "metric": "failures", "threshold": 5, "window_seconds": 600},
        headers=csrf_headers(root),
    ).json()

    patched = root.patch(
        f"/api/alerts/rules/{created['id']}",
        json={"threshold": 50, "enabled": False},
        headers=csrf_headers(root),
    )
    assert patched.status_code == 200
    assert patched.json()["threshold"] == 50
    assert patched.json()["enabled"] is False

    assert root.request(
        "DELETE", f"/api/alerts/rules/{created['id']}", headers=csrf_headers(root)
    ).status_code == 200
    assert root.get("/api/alerts/rules").json() == []


def test_rule_patch_rejects_out_of_range_threshold(root):
    created = root.post(
        "/api/alerts/rules",
        json={"name": "temp2", "metric": "failures", "threshold": 5, "window_seconds": 600},
        headers=csrf_headers(root),
    ).json()
    response = root.patch(
        f"/api/alerts/rules/{created['id']}", json={"threshold": 0}, headers=csrf_headers(root)
    )
    assert response.status_code == 400


def test_acknowledge_through_the_api(root, logdir):
    root.post(
        "/api/alerts/rules",
        json={"name": "ack-me", "metric": "failures", "threshold": 1, "window_seconds": 600},
        headers=csrf_headers(root),
    )
    logdir(rejects=2)
    alerts = root.get("/api/alerts").json()["alerts"]
    assert len(alerts) == 1

    alert_id = alerts[0]["id"]
    assert root.post(f"/api/alerts/{alert_id}/acknowledge", headers=csrf_headers(root)).status_code == 200

    body = root.get("/api/alerts").json()
    assert body["alerts"][0]["acknowledged_by"] == "admin"
    assert root.get("/api/alerts?unacknowledged_only=true").json()["count"] == 0


def test_unknown_rule_is_404(root):
    assert root.patch(
        "/api/alerts/rules/9999", json={"threshold": 1}, headers=csrf_headers(root)
    ).status_code == 404
    assert root.request(
        "DELETE", "/api/alerts/rules/9999", headers=csrf_headers(root)
    ).status_code == 404


def test_rule_changes_are_audited(root):
    created = root.post(
        "/api/alerts/rules",
        json={"name": "audited", "metric": "failures", "threshold": 5, "window_seconds": 600},
        headers=csrf_headers(root),
    ).json()
    root.patch(
        f"/api/alerts/rules/{created['id']}", json={"threshold": 9}, headers=csrf_headers(root)
    )
    root.request("DELETE", f"/api/alerts/rules/{created['id']}", headers=csrf_headers(root))

    actions = {e["action"] for e in root.get("/api/audit?limit=200").json()["entries"]}
    assert "ALERT_RULE_CREATED" in actions
    assert "ALERT_RULE_UPDATED" in actions
    assert "ALERT_RULE_DELETED" in actions


def test_anonymous_cannot_read_alerts(browser):
    assert browser().get("/api/alerts").status_code == 401
    assert browser().get("/api/alerts/rules").status_code == 401


def test_no_rules_is_not_an_error(root, logdir):
    assert root.get("/api/alerts/rules").json() == []
    assert root.get("/api/alerts").json() == {"alerts": [], "count": 0}


def test_missing_log_directory_is_not_an_error(root, tmp_path, monkeypatch):
    monkeypatch.setattr(paths_mod, "LOG_DIR", tmp_path / "does-not-exist")
    root.post(
        "/api/alerts/rules",
        json={"name": "no-logs", "metric": "failures", "threshold": 1, "window_seconds": 600},
        headers=csrf_headers(root),
    )
    rules = root.get("/api/alerts/rules").json()
    assert rules[0]["observed"] == 0
    assert rules[0]["would_fire"] is False