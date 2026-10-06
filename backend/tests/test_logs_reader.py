"""Tests for the log reader, including the linelog file.

The panel's request-logging feature writes to ``linelog``, so if the reader
only looked at ``radius.log`` the feature would appear to work while showing
nothing. These tests pin the merged behaviour.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from app.services import logs as logs_mod

# A realistic linelog file as produced by the messages block the panel
# installs: bare lines, no syslog prefix, key=value fields.
LINELOG_SAMPLE = """\
ACCEPT user=testuser nas=192.0.2.5 client=00-11-22-33-44-55 calling=00-AA-BB-CC-DD-EE reply=Welcome
REJECT user=baduser nas=192.0.2.5 client=00-11-22-33-44-55 calling=00-AA-BB-CC-DD-EE reply=Access denied
ACCEPT user=alice nas=192.0.2.20 client=test-nas-a calling=+15550100 reply=OK
"""

RADIUS_LOG_SAMPLE = """\
Tue Oct  7 12:00:01 2025 : Info: +- [:] (main) server_start
Tue Oct  7 12:00:02 2025 : Info: Access-Accept : user=testuser, NAS-IP-Address=192.0.2.5
Tue Oct  7 12:00:03 2025 : Error: Access-Reject : user=baduser, NAS-IP-Address=192.0.2.5
"""


@pytest.fixture
def logdir(tmp_path, monkeypatch):
    """An isolated log directory with both files populated."""
    monkeypatch.setattr(logs_mod.paths, "LOG_DIR", tmp_path)
    (tmp_path / "radius.log").write_text(RADIUS_LOG_SAMPLE, encoding="utf-8")
    (tmp_path / "linelog").write_text(LINELOG_SAMPLE, encoding="utf-8")
    return tmp_path


# -- parsing -------------------------------------------------------------
def test_bare_linelog_line_is_parsed():
    ev = logs_mod.parse_log_line(
        "ACCEPT user=testuser nas=192.0.2.5", source="linelog"
    )
    assert ev is not None
    assert ev.result == "Access-Accept"
    assert ev.username == "testuser"
    assert ev.nas_ip == "192.0.2.5"
    assert ev.source == "linelog"


def test_linelog_reject_line_is_parsed():
    ev = logs_mod.parse_log_line("REJECT user=baduser nas=192.0.2.5", source="linelog")
    assert ev is not None
    assert ev.result == "Access-Reject"
    assert ev.username == "baduser"


def test_syslog_prefix_line_is_parsed():
    ev = logs_mod.parse_log_line(
        "Tue Oct  7 12:00:02 2025 : Info: Access-Accept : user=testuser, "
        "NAS-IP-Address=192.0.2.5"
    )
    assert ev is not None
    assert ev.result == "Access-Accept"
    assert ev.timestamp is not None


def test_real_radius_log_line_shape_is_recognised():
    """Verbatim shape from the live host's radius.log.

    The regex previously omitted the month field, so *no* real line ever
    matched and every event silently lost its timestamp.
    """
    line = (
        "Mon Oct  5 20:00:36 2026 : Info: "
        "Access-Accept : user=testuser, NAS-IP-Address=192.0.2.5"
    )
    ev = logs_mod.parse_log_line(line)
    assert ev is not None
    assert ev.timestamp is not None
    assert ev.timestamp.year == 2026
    assert ev.timestamp.month == 10
    assert ev.timestamp.day == 5
    assert ev.result == "Access-Accept"


def test_warning_severity_is_recognised():
    ev = logs_mod.parse_log_line(
        "Mon Oct  5 20:00:36 2026 : Warning: Shared secret for client "
        "localhost is short, and likely can be broken by an attacker."
    )
    assert ev is not None
    assert ev.severity == "WARNING"


def test_timestamps_are_timezone_aware():
    """Naive timestamps would break sorting against linelog entries."""
    ev = logs_mod.parse_log_line(
        "Mon Oct  5 20:00:36 2026 : Info: Access-Accept : user=testuser"
    )
    assert ev is not None
    assert ev.timestamp.tzinfo is not None


def test_naive_since_filter_does_not_raise(tmp_path, monkeypatch):
    from datetime import datetime as dt

    monkeypatch.setattr(logs_mod.paths, "LOG_DIR", tmp_path)
    (tmp_path / "radius.log").write_text(RADIUS_LOG_SAMPLE, encoding="utf-8")
    # A naive cutoff must be interpreted locally, not compared against aware
    # timestamps.
    out = logs_mod.read_events(since=dt(2020, 1, 1))
    assert out["events"]


def test_blank_lines_are_ignored():
    assert logs_mod.parse_log_line("   ") is None


# -- merging -------------------------------------------------------------
def test_both_files_are_read(logdir: Path):
    out = logs_mod.read_events()
    sources = {e["source"] for e in out["events"]}
    assert "radius.log" in sources
    assert "linelog" in sources


def test_linelog_events_reach_the_panel(logdir: Path):
    out = logs_mod.read_events()
    users = {e["username"] for e in out["events"]}
    assert "alice" in users, "linelog-only user must appear in the log view"


def test_source_paths_lists_both_files(logdir: Path):
    out = logs_mod.read_events()
    assert len(out["source_paths"]) == 2
    assert any(p.endswith("linelog") for p in out["source_paths"])


def test_result_filter_matches_linelog(logdir: Path):
    out = logs_mod.read_events(result_filter="Access-Reject")
    assert out["events"], "linelog rejects must be filterable"
    assert all(e["result"] == "Access-Reject" for e in out["events"])


def test_username_filter_matches_linelog(logdir: Path):
    out = logs_mod.read_events(username="alice")
    assert [e["username"] for e in out["events"]] == ["alice"]


def test_nas_filter_matches_linelog(logdir: Path):
    out = logs_mod.read_events(nas_ip="192.0.2.20")
    assert out["events"]
    assert all("192.0.2.20" in (e["nas_ip"] or "") for e in out["events"])


def test_events_are_sorted_oldest_first(logdir: Path):
    events = logs_mod.read_events()["events"]
    assert events, "expected events"
    # Timestamped entries come last because bare linelog lines have none.
    timed = [e for e in events if e["timestamp"]]
    assert timed, "radius.log entries should carry timestamps"


def test_missing_linelog_file_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(logs_mod.paths, "LOG_DIR", tmp_path)
    (tmp_path / "radius.log").write_text(RADIUS_LOG_SAMPLE, encoding="utf-8")
    out = logs_mod.read_events()
    assert out["events"], "radius.log alone must still work"


def test_empty_log_directory_is_not_an_error(tmp_path, monkeypatch):
    monkeypatch.setattr(logs_mod.paths, "LOG_DIR", tmp_path)
    out = logs_mod.read_events()
    assert out["events"] == []


def test_tail_limit_avoids_reading_whole_file(tmp_path, monkeypatch):
    """Only the tail is read, and a truncated first line is discarded."""
    monkeypatch.setattr(logs_mod.paths, "LOG_DIR", tmp_path)
    big = "".join(f"ACCEPT user=u{i}\n" for i in range(20000))
    (tmp_path / "linelog").write_text(big, encoding="utf-8")

    out = logs_mod.read_events(limit=5)
    assert len(out["events"]) == 5
    # u0 may be cut mid-line, but the last entries must be intact.
    assert out["events"][-1]["username"] == "u19999"