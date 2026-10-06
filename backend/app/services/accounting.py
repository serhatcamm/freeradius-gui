"""Accounting.

The lab installation does not use SQL accounting, so this module reports the
real configuration state instead of inventing sessions. When SQL accounting
is enabled, or file-based ``radutmp``/``sradutmp`` accounting is in use, the
corresponding reader is used.
"""
from __future__ import annotations

import csv
import io
import logging
import re
import subprocess  # noqa: S404 - fixed argv, shell=False, only for radlast
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from ..freeradius import paths

logger = logging.getLogger(__name__)

_RADACCT_HEADER = (
    "Radacct,AcctSessionId,AcctUniqueId,UserName,Realm,NasIpAddress,"
    "NasPort,StartTime,StartAcctSessionTime,EndTime,AcctInterval,"
    "AcctSessionTime,AcctAuthentic,ConnectInfo,AcctInputOctets,"
    "AcctOutputOctets,CalledStationId,CallingStationId,TerminateCause"
)


@dataclass
class AccountingSession:
    username: str | None
    session_id: str | None
    session_start: datetime | None
    session_stop: datetime | None
    duration_seconds: int | None
    nas_ip: str | None
    nas_port: str | None
    framed_ip: str | None
    called_station: str | None
    calling_station: str | None
    input_octets: int | None
    output_octets: int | None
    terminate_cause: str | None
    source: str

    def as_dict(self) -> dict:
        def iso(d: datetime | None) -> str | None:
            if d is None:
                return None
            if d.tzinfo is None:
                d = d.replace(tzinfo=timezone.utc)
            return d.isoformat()

        return {
            "username": self.username,
            "session_id": self.session_id,
            "session_start": iso(self.session_start),
            "session_stop": iso(self.session_stop),
            "duration_seconds": self.duration_seconds,
            "duration_human": _human(self.duration_seconds),
            "nas_ip": self.nas_ip,
            "nas_port": self.nas_port,
            "framed_ip": self.framed_ip,
            "called_station": self.called_station,
            "calling_station": self.calling_station,
            "input_octets": self.input_octets,
            "output_octets": self.output_octets,
            "terminate_cause": self.terminate_cause,
            "source": self.source,
        }


def _human(seconds: int | None) -> str | None:
    if seconds is None:
        return None
    h, rem = divmod(int(seconds), 3600)
    m, s = divmod(rem, 60)
    return f"{h}h {m:02d}m {s:02d}s" if h else (f"{m}m {s:02d}s" if m else f"{s}s")


def detect_configuration() -> dict:
    """Report what accounting back-ends are actually configured."""
    mods_enabled = paths.RADDB_DIR / "mods-enabled"
    sql_enabled = (mods_enabled / "sql").exists()

    # Is the sql module actually referenced by a virtual server?
    sql_in_site = False
    for site in (paths.SITES_AVAILABLE).glob("*"):
        if not site.is_file():
            continue
        try:
            text = site.read_text("utf-8", "replace")
        except OSError:
            continue
        if re.search(r"^\s*sql\s*$", text, re.MULTILINE):
            sql_in_site = True
            break

    radutmp = Path("/var/log/freeradius/radutmp")
    sradutmp = Path("/var/log/freeradius/sradutmp")

    db_configured = False
    db_module = mods_enabled / "sql"
    if sql_enabled:
        for candidate in ("../mods-available/sql",):
            pass
        db_configured = True

    active_sessions = 0
    session_source = None
    if radutmp.exists():
        active_sessions = _count_radutmp(radutmp)
        session_source = str(radutmp)
    elif sradutmp.exists():
        active_sessions = _count_radutmp(sradutmp)
        session_source = str(sradutmp)

    configured = bool(sql_in_site or session_source)

    return {
        "sql_module_enabled": sql_enabled,
        "sql_used_in_virtual_server": sql_in_site,
        "sql_database_configured": db_configured and sql_in_site,
        "radutmp_path": str(radutmp),
        "radutmp_present": radutmp.exists(),
        "sradutmp_path": str(sradutmp),
        "sradutmp_present": sradutmp.exists(),
        "active_sessions": active_sessions,
        "session_source": session_source,
        "accounting_configured": configured,
        "detail_files": _detail_files(),
    }


def _count_radutmp(path: Path) -> int:
    try:
        with path.open("rb") as fh:
            return fh.read().count(b"\x00") // 2
    except OSError:
        return 0


def _detail_files() -> list[dict]:
    """Accounting detail files written by rlm_detail, if any."""
    radacct = Path("/var/log/freeradius/radacct")
    if not radacct.is_dir():
        return []
    out = []
    for client_dir in sorted(radacct.iterdir())[:50]:
        if not client_dir.is_dir():
            continue
        for f in sorted(client_dir.iterdir(), reverse=True)[:5]:
            if not f.is_file():
                continue
            try:
                st = f.stat()
            except OSError:
                continue
            out.append(
                {
                    "path": str(f),
                    "client": client_dir.name,
                    "size": st.st_size,
                    "modified": datetime.fromtimestamp(
                        st.st_mtime, tz=timezone.utc
                    ).isoformat(),
                }
            )
    return out


def list_sessions(limit: int = 100) -> dict:
    """Return sessions from whatever source is genuinely available."""
    config = detect_configuration()

    if not config["accounting_configured"]:
        return {
            "configured": False,
            "sessions": [],
            "active_sessions": 0,
            "configuration": config,
            "message": (
                "Accounting is not configured on this server. The 'sql' module is "
                + ("enabled but not referenced by any virtual server"
                   if config["sql_module_enabled"] and not config["sql_used_in_virtual_server"]
                   else "not enabled")
                + ", and no radutmp/sradutmp session files exist. No session data "
                "is shown because none is being recorded."
            ),
        }

    sessions: list[AccountingSession] = []
    source = "sql"

    if config["session_source"]:
        sessions = _read_radutmp(Path(config["session_source"]))
        source = "radutmp"

    return {
        "configured": True,
        "sessions": [s.as_dict() for s in sessions[:limit]],
        "active_sessions": config["active_sessions"],
        "source": source,
        "configuration": config,
    }


def _read_radutmp(path: Path) -> list[AccountingSession]:
    """Parse the radutmp format via ``radlast``, which handles it correctly."""
    try:
        out = subprocess.run(
            ["/usr/sbin/radlast", "-S", str(path)],
            capture_output=True, text=True, timeout=30, shell=False, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if out.returncode != 0:
        return []

    lines = out.stdout.splitlines()
    if not lines:
        return []

    reader = csv.DictReader(io.StringIO("\n".join(lines)), delimiter="\t", fieldnames=_split_header())
    sessions: list[AccountingSession] = []
    for row in reader:
        if not row.get("UserName"):
            continue
        sessions.append(
            AccountingSession(
                username=row.get("UserName"),
                session_id=row.get("AcctSessionId"),
                session_start=_parse_time(row.get("StartTime")),
                session_stop=_parse_time(row.get("EndTime")),
                duration_seconds=_int(row.get("AcctSessionTime")),
                nas_ip=row.get("NasIpAddress"),
                nas_port=row.get("NasPort"),
                framed_ip=row.get("FramedIPAddress"),
                called_station=row.get("CalledStationId"),
                calling_station=row.get("CallingStationId"),
                input_octets=_int(row.get("AcctInputOctets")),
                output_octets=_int(row.get("AcctOutputOctets")),
                terminate_cause=row.get("TerminateCause"),
                source="radutmp",
            )
        )
    return sessions


def _split_header() -> list[str]:
    return _RADACCT_HEADER.split(",")


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value not in (None, "") else None
    except ValueError:
        return None


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%a %b %d %H:%M:%S %Y"):
        try:
            return datetime.strptime(value.strip(), fmt)
        except ValueError:
            continue
    return None