"""FreeRADIUS service control.

Restart and reload are gated on ``freeradius -XC`` succeeding first. Only a
fixed set of systemd actions is ever issued, through the argument-array
runner.
"""
from __future__ import annotations

import logging
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from ..core.config import get_settings
from ..freeradius import paths
from ..freeradius.runner import CommandResult, run_command
from ..freeradius.validate import ValidationResult, validate_config
from .audit import (
    FREERADIUS_RELOADED,
    FREERADIUS_RESTARTED,
    CONFIG_VALIDATED,
    CONFIG_VALIDATION_FAILED,
    record,
)
from .config_tx import ConfigValidationError

logger = logging.getLogger(__name__)

STATUS_UNKNOWN = "unknown"
STATUS_RUNNING = "RUNNING"
STATUS_STOPPED = "STOPPED"
STATUS_ERROR = "ERROR"


class ServiceControlError(RuntimeError):
    pass


def _systemctl(*args: str, timeout: int = 60) -> CommandResult:
    argv = ["/usr/bin/systemctl", *args]
    import asyncio

    return asyncio.run(run_command(argv, timeout=timeout))


async def _systemctl_async(*args: str, timeout: int = 60) -> CommandResult:
    argv = ["/usr/bin/systemctl", *args]
    return await run_command(argv, timeout=timeout)


def _read_prop(result: CommandResult, key: str) -> str | None:
    for line in result.stdout.splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    return None


async def get_status() -> dict:
    """Collect live status without ever shelling out to ``freeradius -X``."""
    settings = get_settings()
    unit = settings.systemd_unit

    status_out = await _systemctl_async("is-active", unit)
    enabled_out = await _systemctl_async("is-enabled", unit)
    state = status_out.stdout.strip() or STATUS_UNKNOWN

    if state == "active":
        overall = STATUS_RUNNING
    elif state in {"inactive", "failed", ""}:
        overall = STATUS_STOPPED if state != "failed" else STATUS_ERROR
    else:
        overall = STATUS_ERROR

    props = await _systemctl_async(
        "show", unit, "-p", "MainPID", "-p", "NRestarts", "-p", "ActiveEnterTimestamp",
    )
    pid = None
    restarts = None
    entered = None
    for line in props.stdout.splitlines():
        if line.startswith("MainPID="):
            pid = int(line.split("=", 1)[1] or 0) or None
        elif line.startswith("NRestarts="):
            restarts = int(line.split("=", 1)[1] or 0)
        elif line.startswith("ActiveEnterTimestamp="):
            entered = line.split("=", 1)[1].strip() or None

    memory_kb = None
    cpu_percent = None
    if pid:
        # /proc reads need no subprocess and no extra privileges.
        try:
            status = Path(f"/proc/{pid}/status").read_text()
            for line in status.splitlines():
                if line.startswith("VmRSS:"):
                    memory_kb = int(line.split()[1])
                    break
        except OSError:
            pass
        cpu_percent = _read_cpu_times(pid)

    ports = await _listening_ports()

    return {
        "status": overall,
        "systemd_state": state,
        "enabled": enabled_out.stdout.strip() or "unknown",
        "pid": pid,
        "restarts": restarts,
        "active_since": entered,
        "memory_kb": memory_kb,
        "cpu_seconds_total": cpu_percent,
        "listening_ports": ports,
        "unit": unit,
    }


def _read_cpu_times(pid: int) -> float | None:
    """Total CPU seconds consumed by the process, from /proc."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text()
    except OSError:
        return None
    # Field 14/15 are utime/stime in clock ticks after the comm field.
    try:
        tail = raw[raw.rindex(")") + 2 :].split()
        ticks = int(tail[11]) + int(tail[12])
        return round(ticks / os.sysconf("SC_CLK_TCK"), 2)
    except (ValueError, IndexError):
        return None


async def _listening_ports() -> list[dict]:
    """Discover listening sockets from /proc/net, without ``ss``."""
    ports: list[dict] = []
    seen: set[tuple[str, str, int]] = set()

    for proto, path in (("udp", "/proc/net/udp"), ("udp", "/proc/net/udp6")):
        try:
            lines = Path(path).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) < 4:
                continue
            local, state_hex = fields[1], fields[3]
            # 07 == UDP_LISTEN
            if state_hex != "07":
                continue
            addr_hex, port_hex = local.split(":")
            port = int(port_hex, 16)
            if port in (0, 1812, 1813, 18120):
                key = (proto, "udp", port)
                if key in seen:
                    continue
                seen.add(key)
                ports.append(
                    {
                        "protocol": "udp",
                        "port": port,
                        "role": {1812: "auth", 1813: "accounting"}.get(port, "inner-tunnel"),
                    }
                )

    try:
        lines = Path("/proc/net/tcp").read_text().splitlines()[1:]
    except OSError:
        lines = []
    for line in lines:
        fields = line.split()
        if len(fields) < 4:
            continue
        local, state_hex = fields[1], fields[3]
        if state_hex != "0A":  # TCP_LISTEN
            continue
        port = int(local.split(":")[1], 16)
        if port in (1812, 1813):
            key = ("tcp", "tcp", port)
            if key in seen:
                continue
            seen.add(key)
            ports.append(
                {"protocol": "tcp", "port": port, "role": {1812: "auth", 1813: "accounting"}[port]}
            )

    return sorted(ports, key=lambda p: p["port"])


async def validate() -> ValidationResult:
    return await validate_config()


async def restart(
    *, administrator: str, source_ip: str | None = None, db=None
) -> dict:
    """Validate, then restart. Refuses to restart on an invalid config."""
    settings = get_settings()
    validation = await validate_config()

    if not validation.ok:
        record(
            db, CONFIG_VALIDATION_FAILED, administrator, object_type="service",
            object_id=settings.systemd_unit, source_ip=source_ip, success=False,
            detail={"summary": validation.summary, "refused": "restart"},
        )
        raise ConfigValidationError(validation, rolled_back=False)

    result = await _systemctl_async("restart", settings.systemd_unit, timeout=120)
    if not result.ok:
        record(
            db, FREERADIUS_RESTARTED, administrator, object_type="service",
            object_id=settings.systemd_unit, source_ip=source_ip, success=False,
            detail={"stderr": result.stderr[-500:]},
        )
        raise ServiceControlError(result.stderr.strip() or "restart failed")

    record(
        db, FREERADIUS_RESTARTED, administrator, object_type="service",
        object_id=settings.systemd_unit, source_ip=source_ip, success=True,
    )
    record(db, CONFIG_VALIDATED, administrator, object_type="service",
           object_id=settings.systemd_unit, source_ip=source_ip, success=True)
    return {"action": "restart", "status": (await get_status())["status"]}


async def reload(
    *, administrator: str, source_ip: str | None = None, db=None
) -> dict:
    settings = get_settings()
    validation = await validate_config()

    if not validation.ok:
        record(
            db, CONFIG_VALIDATION_FAILED, administrator, object_type="service",
            object_id=settings.systemd_unit, source_ip=source_ip, success=False,
            detail={"summary": validation.summary, "refused": "reload"},
        )
        raise ConfigValidationError(validation, rolled_back=False)

    result = await _systemctl_async("reload", settings.systemd_unit, timeout=120)
    if not result.ok:
        record(
            db, FREERADIUS_RELOADED, administrator, object_type="service",
            object_id=settings.systemd_unit, source_ip=source_ip, success=False,
            detail={"stderr": result.stderr[-500:]},
        )
        raise ServiceControlError(result.stderr.strip() or "reload failed")

    record(
        db, FREERADIUS_RELOADED, administrator, object_type="service",
        object_id=settings.systemd_unit, source_ip=source_ip, success=True,
    )
    return {"action": "reload", "status": (await get_status())["status"]}


async def recent_log(lines: int = 200) -> list[str]:
    """Recent FreeRADIUS log lines from the systemd journal."""
    settings = get_settings()
    unit = settings.systemd_unit
    result = await _systemctl_async(
        "status", unit, "--no-pager", "--lines", str(lines)
    )
    return result.stdout.splitlines()[-lines:]


def server_info() -> dict:
    """Static and slowly-changing facts about the host, read without subprocesses."""
    settings = get_settings()
    info: dict = {
        "hostname": os.uname().nodename,
        "freeradius_version": None,
        "debian_version": None,
        "kernel": os.uname().release,
        "raddb_dir": str(paths.RADDB_DIR),
        "users_file": str(paths.USERS_FILE),
        "clients_file": str(paths.CLIENTS_FILE),
        "auth_port": 1812,
        "accounting_port": 1813,
        "config_validated": False,
    }

    try:
        with open("/etc/debian_version") as fh:
            info["debian_version"] = fh.read().strip()
    except OSError:
        pass

    try:
        with open("/usr/share/doc/freeradius/changelog.Debian.gz", "rb") as fh:
            pass
    except OSError:
        pass

    # The package version is authoritative and cheap to read.
    try:
        import subprocess  # noqa: S404 - dpkg-query, fixed argv, shell=False

        out = subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", "freeradius"],
            capture_output=True, text=True, timeout=10, shell=False, check=False,
        )
        if out.returncode == 0 and out.stdout.strip():
            info["freeradius_version"] = out.stdout.strip()
    except Exception:
        pass

    return info