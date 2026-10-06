"""Authentication log reading.

Two sources are used, both real:

* ``/var/log/freeradius/radius.log`` - FreeRADIUS's own syslog-format file;
* the systemd journal for the unit.

FreeRADIUS does **not** record per-request Access-Accept/Access-Reject lines
by default (``auth_goodpass`` / ``auth_badpass`` are ``no``). Rather than
fabricating entries, this module detects that condition, reports it as
"not configured", and offers an idempotent, backed-up change that turns on
``linelog`` so real request records appear.
"""
from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..core.config import get_settings
from ..freeradius import paths
from ..freeradius.runner import run_command
from .config_tx import ConfigTransaction

logger = logging.getLogger(__name__)

#: radius.log line: "Mon Oct  5 20:03:01 2026 : Info: message"
_LOG_RE = re.compile(
    # syslog classic: "Mon Oct  5 20:00:36 2026 : Info: message"
    # Note the weekday *and* month, and the padding before a single-digit day.
    r"^(?P<ts>\w{3}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})\s+:\s+"
    r"(?P<sev>Debug|Info|Warn|Warning|Error|Fatal)\s*:\s*(?P<msg>.*)$"
)

_RE_ACCEPT = re.compile(r"Access-Accept", re.IGNORECASE)
_RE_REJECT = re.compile(r"Access-Reject", re.IGNORECASE)

#: Log files the panel reads, in the order they are merged.
LOG_SOURCES = ("radius.log", "linelog")

#: linelog messages we install for request-level logging.
LINELOG_MESSAGES = """messages {
	default = "Unknown packet type %{Packet-Type}"
	Access-Accept = "ACCEPT user=%{User-Name} nas=%{NAS-IP-Address} client=%{Called-Station-Id} calling=%{Calling-Station-Id} reply=%{reply:Messages}"
	Access-Reject = "REJECT user=%{User-Name} nas=%{NAS-IP-Address} client=%{Called-Station-Id} calling=%{Calling-Station-Id} reply=%{reply:Messages}"
	Access-Challenge = "CHALLENGE user=%{User-Name} nas=%{NAS-IP-Address} client=%{Called-Station-Id} calling=%{Calling-Station-Id}"
}"""

_BEGIN = "# >>> freeradius-web request logging >>>"
_END = "# <<< freeradius-web request logging <<<"

#: Markers for the linelog module options (a different file, with its own
#: backup).
_BEGIN_DETAIL = "# >>> freeradius-web linelog detail >>>"
_END_DETAIL = "# <<< freeradius-web linelog detail <<<"


@dataclass
class LogEvent:
    timestamp: datetime | None
    severity: str
    message: str
    source: str = "radius.log"
    result: str | None = None
    username: str | None = None
    nas_ip: str | None = None
    client: str | None = None
    calling_station: str | None = None
    reply: str | None = None

    def as_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "severity": self.severity,
            "message": self.message,
            "source": self.source,
            "result": self.result,
            "username": self.username,
            "nas_ip": self.nas_ip,
            "client": self.client,
            "calling_station": self.calling_station,
            "reply": self.reply,
        }


def _local_tz():
    """The host's local timezone.

    FreeRADIUS writes timestamps in local time with no offset, so the only
    correct way to interpret them is in the server's own zone. Anything else
    would silently shift every log timestamp by the UTC offset.
    """
    return datetime.now().astimezone().tzinfo


def _parse_ts(value: str) -> datetime | None:
    try:
        naive = datetime.strptime(value, "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None
    return naive.replace(tzinfo=_local_tz())


def _classify(message: str) -> dict:
    """Pull fields out of a linelog-style line written by our linelog block."""
    out: dict = {}
    m = re.match(r"^(ACCEPT|REJECT|CHALLENGE)\b", message)
    if m:
        out["result"] = {
            "ACCEPT": "Access-Accept",
            "REJECT": "Access-Reject",
            "CHALLENGE": "Access-Challenge",
        }[m.group(1)]
        for key, name in (
            ("user", "username"),
            ("nas", "nas_ip"),
            ("client", "client"),
            ("calling", "calling_station"),
            ("reply", "reply"),
        ):
            fm = re.search(rf"\b{key}=(\S*)", message)
            if fm:
                out[name] = fm.group(1) or None
        return out

    if _RE_ACCEPT.search(message):
        out["result"] = "Access-Accept"
    elif _RE_REJECT.search(message):
        out["result"] = "Access-Reject"
    um = re.search(r"(?:user|User-Name)\s*=\s*\"?([^\"\s]+)", message)
    if um:
        out["username"] = um.group(1)
    # linelog lines use the same key=value shape as radius.log, so the NAS and
    # client filters work on request-log entries too.
    for key, name in (("nas", "nas_ip"), ("client", "client")):
        km = re.search(rf"\b{key}=(\S*)", message)
        if km:
            out[name] = km.group(1) or None
    return out


def parse_log_line(line: str, source: str = "radius.log") -> LogEvent | None:
    m = _LOG_RE.match(line)
    if m:
        ts = _parse_ts(m.group("ts"))
        sev = m.group("sev")
        msg = m.group("msg")
    else:
        # Linelog writes bare lines without the syslog prefix.
        ts, sev, msg = None, "Info", line

    stripped = line.strip()
    if not stripped:
        return None

    extra = _classify(msg)
    severity = "ERROR" if sev in {"Error", "Fatal"} else sev.upper()
    return LogEvent(
        timestamp=ts, severity=severity, message=msg, source=source, **extra
    )


def _read_radius_log(max_bytes: int = 512 * 1024) -> list[str]:
    return _read_log_file("radius.log", max_bytes)


def _read_log_file(name: str, max_bytes: int = 512 * 1024) -> list[str]:
    """Return the tail of a log file as text lines.

    Only the last ``max_bytes`` are read so a busy server cannot make the
    panel memory-hungry, and a partial first line is discarded.
    """
    path = Path(paths.LOG_DIR) / name
    if not path.exists():
        return []
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            if size > max_bytes:
                fh.seek(-max_bytes, os_seek_end())
                fh.readline()  # discard partial first line
            data = fh.read()
    except OSError:
        return []
    return data.decode("utf-8", "replace").splitlines()


def os_seek_end() -> int:
    import os

    return os.SEEK_END


def read_events(
    limit: int = 200,
    result_filter: str | None = None,
    username: str | None = None,
    nas_ip: str | None = None,
    since: datetime | None = None,
) -> dict:
    """Return parsed log events plus a capability report.

    Both ``radius.log`` and the ``linelog`` file are read. The latter matters
    because radius.log is not guaranteed to carry the request lines; the
    panel's own "request logging" feature writes to it, and hiding those
    records would make the feature useless.
    """
    events: list[LogEvent] = []
    total_lines = 0
    for name in LOG_SOURCES:
        raw_lines = _read_log_file(name)
        total_lines += len(raw_lines)
        for line in raw_lines:
            ev = parse_log_line(line, source=name)
            if ev:
                events.append(ev)

    # radius.log lines carry a timestamp; linelog lines are bare. Undated
    # entries cannot be interleaved truthfully, so they sort to the front
    # rather than pretending to a time we do not know.
    undated = datetime.min.replace(tzinfo=_local_tz())
    events.sort(key=lambda e: e.timestamp or undated)

    request_events = [e for e in events if e.result]

    # A caller may pass a naive ``since``; interpret it in local time to match
    # how log timestamps are produced, rather than mixing aware and naive.
    if since is not None and since.tzinfo is None:
        since = since.replace(tzinfo=_local_tz())

    def keep(ev: LogEvent) -> bool:
        if result_filter and result_filter != "ALL":
            if (ev.result or "") != result_filter:
                return False
        if username and (ev.username or "").lower() != username.lower():
            return False
        if nas_ip and nas_ip not in (ev.nas_ip or ev.client or ""):
            return False
        if since and ev.timestamp:
            if ev.timestamp < since:
                return False
        return True

    filtered = [e for e in events if keep(e)]

    return {
        "events": [e.as_dict() for e in filtered[-limit:]],
        "total_lines": total_lines,
        "request_event_count": len(request_events),
        "capability": logging_capability(),
        "source_paths": [str(Path(paths.LOG_DIR) / n) for n in LOG_SOURCES],
    }


def logging_capability() -> dict:
    """Report honestly whether request-level logging is available."""
    site = paths.SITES_AVAILABLE / "default"
    mod = paths.MODS_AVAILABLE / "linelog"
    linelog_path = Path(paths.LOG_DIR) / "linelog"

    mod_text = mod.read_text("utf-8", "replace") if mod.exists() else ""
    # These options belong to the linelog *module*, not to radiusd.conf.
    goodpass = _read_directive(mod, "auth_goodpass")
    badpass = _read_directive(mod, "auth_badpass")

    site_text = site.read_text("utf-8", "replace") if site.exists() else ""
    linelog_in_site = bool(re.search(r"^\s*linelog\s*$", site_text, re.MULTILINE))
    site_block_installed = _BEGIN in site_text
    detail_installed = _BEGIN_DETAIL in mod_text

    reasons: list[str] = []
    if not linelog_in_site:
        reasons.append("the 'linelog' module is not invoked in sites-available/default")
    if not detail_installed:
        reasons.append("auth_goodpass/auth_badpass are not enabled in mods-available/linelog")
    if not linelog_path.exists():
        reasons.append(f"{linelog_path} does not exist yet (FreeRADIUS has not written it)")

    configured = linelog_in_site and linelog_path.exists()
    return {
        "request_logging_configured": configured,
        "auth_goodpass": goodpass,
        "auth_badpass": badpass,
        "linelog_referenced": linelog_in_site,
        "managed_block_installed": site_block_installed,
        "linelog_detail_installed": detail_installed,
        "linelog_path": str(linelog_path),
        "reasons": [] if configured else reasons,
        "hint": (
            "Per-request Access-Accept/Access-Reject logging is active."
            if configured
            else "FreeRADIUS is not recording per-request results. Enable request "
            "logging to populate this view; a backup and validation are performed "
            "automatically and the change can be rolled back."
        ),
    }


def _read_directive(path: Path, key: str) -> str | None:
    if not path.exists():
        return None
    for line in path.read_text("utf-8", "replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        m = re.match(rf"^{key}\s*=\s*(\S+)", stripped)
        if m:
            return m.group(1).strip('"')
    return None


def _insert_into_section(text: str, section_re: str, block: str) -> str:
    """Insert ``block`` as the first thing inside the matching section.

    Raises if the section is missing or unbalanced rather than guessing.
    """
    m = re.search(section_re, text, re.MULTILINE)
    if not m:
        raise ValueError(f"no {section_re} section found")

    depth = 0
    end = None
    for idx in range(m.end() - 1, len(text)):
        if text[idx] == "{":
            depth += 1
        elif text[idx] == "}":
            depth -= 1
            if depth == 0:
                end = idx
                break
    if end is None:
        raise ValueError("unterminated section")

    return text[: m.end()] + "\n" + block + text[m.end() : end] + text[end:]


def install_request_logging_block() -> str:
    """Return the site content with the managed linelog block installed.

    ``authenticate`` is unlang, so it *invokes* the module by name; a
    ``linelog { ... }`` sub-section here is a parse error
    ("Errors parsing linelog sub-section"). Module options therefore live in
    ``mods-available/linelog`` and are managed by
    :func:`install_linelog_detail_block`.
    """
    site = paths.SITES_AVAILABLE / "default"
    text = site.read_text("utf-8", "replace")
    if _BEGIN in text:
        return text

    block = f"""{_BEGIN}
	#
	# Added by the FreeRADIUS Web Management Panel.
	# Calls the linelog module so one line per authentication request is
	# written to ${{logdir}}/linelog, giving the panel real
	# Access-Accept / Access-Reject records to display.
	# Remove this block (or roll back the backup) to disable it.
	#
	linelog
{_END}"""
    # The block deliberately ends at the closing marker with no trailing
    # newline: _insert_into_section supplies the separators, so removal can
    # restore the original bytes exactly.
    return _insert_into_section(text, r"^authenticate\s*\{", block)


def remove_request_logging_block() -> str:
    site = paths.SITES_AVAILABLE / "default"
    text = site.read_text("utf-8", "replace")
    # Remove exactly what install_request_logging_block added: the newline it
    # inserted after the opening brace plus the block itself. A trailing
    # ``\s*`` or ``\n?`` here would also eat the indentation of the following
    # line, which silently reformats unrelated configuration.
    pattern = re.compile(
        rf"\n{re.escape(_BEGIN)}.*?{re.escape(_END)}", re.DOTALL
    )
    return pattern.sub("", text)


#: Options added to the first ``linelog`` instance. These produce the detailed
#: per-attempt records, including the reply message for a reject.
_DETAIL_OPTIONS = (
    _BEGIN_DETAIL
    + """
	#
	# Added by the FreeRADIUS Web Management Panel.
	# auth_goodpass / auth_badpass record one line per authentication
	# attempt, including the failure reason. These are off by default.
	#
	# The value list is '|' separated attribute references. This exact form
	# is verified by tests/test_logging_config.py against freeradius -XC.
	#
	auth_goodpass = file=%{User-Name}|%{Packet-Src-IP-Address}|%{Called-Station-Id}|%{NAS-IP-Address}|%{request:NAS-Port}
	auth_badpass = file=%{User-Name}|%{Packet-Src-IP-Address}|%{Called-Station-Id}|%{NAS-IP-Address}|%{request:NAS-Port}
"""
    + _END_DETAIL
)


def linelog_detail_installed() -> bool:
    mod = paths.MODS_AVAILABLE / "linelog"
    return mod.exists() and _BEGIN_DETAIL in mod.read_text("utf-8", "replace")


def install_linelog_detail_block() -> str:
    """Return mods-available/linelog with auth_goodpass/auth_badpass enabled."""
    mod = paths.MODS_AVAILABLE / "linelog"
    text = mod.read_text("utf-8", "replace")
    if _BEGIN_DETAIL in text:
        return text
    # Only the first `linelog { }` instance is patched; the accounting
    # instance must keep its own (empty) settings.
    return _insert_into_section(text, r"^linelog\s*\{", _DETAIL_OPTIONS)


def remove_linelog_detail_block() -> str:
    mod = paths.MODS_AVAILABLE / "linelog"
    text = mod.read_text("utf-8", "replace")
    # Mirrors remove_request_logging_block: remove the inserted newline and
    # the block, leaving the next line's indentation untouched.
    pattern = re.compile(
        rf"\n{re.escape(_BEGIN_DETAIL)}.*?{re.escape(_END_DETAIL)}", re.DOTALL
    )
    return pattern.sub("", text)


async def tail_events(limit: int = 100) -> list[dict]:
    """Async wrapper so SSE handlers can await file access."""
    return await asyncio.to_thread(lambda: read_events(limit=limit))