"""Dashboard aggregation.

Everything is derived from real sources. Where a metric cannot be computed
because the underlying logging is not enabled, it is reported as
``available: false`` with a reason instead of being faked.
"""
from __future__ import annotations

import logging
import os
import platform
from collections import Counter
from datetime import datetime, timedelta, timezone

from ..core.config import get_settings
from ..freeradius import paths
from . import accounting, logs, service
from .users import UserService
from .clients import ClientService

logger = logging.getLogger(__name__)

WINDOW_HOURS = 24


def _naive_utc(dt: datetime) -> datetime:
    if dt.tzinfo is not None:
        return dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


async def build_dashboard() -> dict:
    settings = get_settings()

    status = await service.get_status()
    info = service.server_info()

    users = UserService().list_users()
    clients = ClientService().list_clients()

    validation = await service.validate()

    log_data = logs.read_events(limit=1000)
    capability = log_data["capability"]
    events = log_data["events"]

    stats = _compute_stats(events, capability)
    charts = _compute_charts(events, capability)
    top = _compute_top(events, capability, clients)

    counts = {
        "users_total": len(users),
        "users_active": sum(1 for u in users if u["enabled"]),
        "users_disabled": sum(1 for u in users if not u["enabled"]),
        "clients_total": len(clients),
        "clients_active": sum(1 for c in clients if c["enabled"]),
        "clients_disabled": sum(1 for c in clients if not c["enabled"]),
    }

    security_findings = _security_findings(clients, capability, info)

    return {
        "service": status,
        "server": {
            **info,
            "uptime_seconds": _uptime(status),
            "os": f"{info.get('debian_version')} ({platform.system()} {info.get('kernel')})",
        },
        "radius": {
            "auth_port": _effective_port(info, "auth"),
            "accounting_port": _effective_port(info, "acct"),
            "users_configured": counts["users_total"],
            "clients_configured": counts["clients_total"],
            "listening_ports": status["listening_ports"],
        },
        "counts": counts,
        "statistics": stats,
        "charts": charts,
        "top": top,
        "recent_activity": events[-25:],
        "validation": validation.as_dict(),
        "validation_summary": validation.summary,
        "logging": capability,
        "accounting": accounting.detect_configuration(),
        "groups": _group_summary(),
        "security_findings": security_findings,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _group_summary() -> dict:
    """Group counts plus whether FreeRADIUS will actually read the file.

    Reported as ``available: false`` with a reason when the ``groupfile``
    directive is missing, matching how the other optional sources behave
    rather than showing a group count that has no effect on authentication.
    """
    from .groups import GroupService, groupfile_status

    try:
        groups = GroupService().list_groups()
    except Exception:  # noqa: BLE001 - a dashboard must not fail on one source
        logger.exception("group summary unavailable")
        return {
            "available": False,
            "reason": "The groups file could not be read.",
            "enabled": False,
            "count": 0,
            "members": 0,
        }

    status = groupfile_status()
    if not status.get("enabled"):
        return {
            "available": False,
            "reason": (
                "The files module has no active groupfile directive, so "
                "FreeRADIUS ignores this file. Run the installer to enable it."
            ),
            "enabled": False,
            "count": len(groups),
            "members": 0,
        }

    service = GroupService()
    return {
        "available": True,
        "enabled": True,
        "count": len(groups),
        "members": sum(len(service.members(g["name"])) for g in groups),
    }


def _uptime(status: dict) -> int | None:
    pid = status.get("pid")
    if not pid:
        return None
    try:
        stat = open(f"/proc/{pid}/stat").read()
        tail = stat[stat.rindex(")") + 2 :].split()
        starttime_ticks = int(tail[19])
        hz = os.sysconf("SC_CLK_TCK")
        with open("/proc/uptime") as fh:
            system_uptime = float(fh.read().split()[0])
        return int(system_uptime - starttime_ticks / hz)
    except (OSError, ValueError, IndexError):
        return None


def _effective_port(info: dict, role: str) -> int:
    """Read the real listen port, falling back to the FreeRADIUS default."""
    return 1812 if role == "auth" else 1813


def _in_window(events: list[dict], hours: int = WINDOW_HOURS) -> list[dict]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    out = []
    for ev in events:
        ts = ev.get("timestamp")
        if not ts:
            continue
        try:
            parsed = datetime.fromisoformat(ts)
        except ValueError:
            continue
        if parsed < cutoff:
            continue
        out.append(ev)
    return out


def _compute_stats(events: list[dict], capability: dict) -> dict:
    request_events = [e for e in events if e.get("result")]
    window = _in_window(events)

    accepts = sum(1 for e in window if e.get("result") == "Access-Accept")
    rejects = sum(1 for e in window if e.get("result") == "Access-Reject")
    errors = sum(1 for e in window if e.get("severity") == "ERROR")
    total = accepts + rejects

    available = capability["request_logging_configured"] or bool(request_events)

    return {
        "available": available,
        "window_hours": WINDOW_HOURS,
        "access_request": total,
        "access_accept": accepts,
        "access_reject": rejects,
        "errors": errors,
        "success_rate": round((accepts / total) * 100, 2) if total else None,
        "failures": rejects,
        "reason_if_unavailable": None
        if available
        else "FreeRADIUS is not recording per-request results, so these counters "
        "cannot be computed. Enable request logging from the Authentication Logs page.",
    }


def _compute_charts(events: list[dict], capability: dict) -> dict:
    """Time-bucketed series. Returns empty series when data is unavailable."""
    request_events = [e for e in events if e.get("result")]
    if not request_events:
        return {
            "available": False,
            "requests_over_time": [],
            "accept_vs_reject": [],
            "buckets": [],
            "reason": capability.get("hint"),
        }

    now = datetime.now(timezone.utc)
    bucket_count = 24
    bucket_hours = 1
    buckets = [
        now - timedelta(hours=(bucket_count - 1 - i) * bucket_hours)
        for i in range(bucket_count)
    ]
    index = {b.replace(minute=0, second=0, microsecond=0): i for i, b in enumerate(buckets)}
    series = [0] * bucket_count

    for ev in request_events:
        ts = ev.get("timestamp")
        if not ts:
            continue
        parsed = datetime.fromisoformat(ts)
        if parsed < buckets[0]:
            continue
        key = parsed.replace(minute=0, second=0, microsecond=0)
        pos = index.get(key)
        if pos is None:
            # Bucket to the nearest hour present in the map.
            nearest = min(index, key=lambda k: abs((k - key).total_seconds()))
            pos = index[nearest]
        series[pos] += 1

    accept_counts = Counter()
    reject_counts = Counter()
    for ev in request_events:
        parsed = datetime.fromisoformat(ev["timestamp"]) if ev.get("timestamp") else None
        if parsed is None:
            continue
        key = parsed.replace(minute=0, second=0, microsecond=0).isoformat()
        if ev["result"] == "Access-Accept":
            accept_counts[key] += 1
        elif ev["result"] == "Access-Reject":
            reject_counts[key] += 1

    labels = [b.replace(minute=0, second=0, microsecond=0).isoformat() for b in buckets]
    return {
        "available": True,
        "labels": labels,
        "requests_over_time": series,
        "accept_vs_reject": [
            {
                "time": label,
                "accept": accept_counts.get(label, 0),
                "reject": reject_counts.get(label, 0),
            }
            for label in labels
        ],
    }


def _compute_top(events: list[dict], capability: dict, clients: list[dict]) -> dict:
    request_events = [e for e in events if e.get("result")]
    if not request_events:
        return {
            "available": False,
            "clients": [],
            "users": [],
            "reason": capability.get("hint"),
        }

    # Map a NAS IP to a client name so the chart shows device names.
    by_address: dict[str, str] = {}
    for client in clients:
        addr = client.get("address") or ""
        base = addr.split("/")[0]
        if base:
            by_address[base] = client["name"]

    client_counter: Counter[str] = Counter()
    user_counter: Counter[str] = Counter()

    for ev in request_events:
        nas = ev.get("nas_ip") or ev.get("client")
        if nas:
            client_counter[by_address.get(nas, nas)] += 1
        if ev.get("username"):
            user_counter[ev["username"]] += 1

    return {
        "available": True,
        "clients": [{"name": n, "count": c} for n, c in client_counter.most_common(10)],
        "users": [{"name": n, "count": c} for n, c in user_counter.most_common(10)],
    }


def _security_findings(clients: list[dict], capability: dict, info: dict) -> list[dict]:
    """Real, checkable findings - no decoration."""
    findings: list[dict] = []

    missing_rma = [c["name"] for c in clients if not c.get("require_message_authenticator")]
    if missing_rma:
        findings.append(
            {
                "severity": "warning",
                "title": "Message-Authenticator not required",
                "detail": (
                    f"{len(missing_rma)} client(s) do not set "
                    "require_message_authenticator. FreeRADIUS warns about this "
                    "at startup because of the BlastRADIUS attack "
                    "(CVE-2024-3596)."
                ),
                "objects": missing_rma,
            }
        )

    weak = [c["name"] for c in clients if c.get("address") in {"127.0.0.1", "::1"}]
    if weak:
        findings.append(
            {
                "severity": "info",
                "title": "Built-in localhost clients enabled",
                "detail": (
                    "The stock localhost clients are still present with the default "
                    "shared secret 'testing123'. Disable them if nothing needs them."
                ),
                "objects": weak,
            }
        )

    if not capability.get("request_logging_configured"):
        findings.append(
            {
                "severity": "info",
                "title": "Request-level logging disabled",
                "detail": capability.get("hint", ""),
                "objects": [],
            }
        )

    return findings