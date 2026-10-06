"""Authentication log endpoints, including a Server-Sent Events stream."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from pathlib import Path

from sqlalchemy.orm import Session

from ..api.deps import require_role
from ..core.db import get_db
from ..models.db import Administrator
from ..services import audit, logs
from ..services.auth import client_ip, current_admin
from ..services.config_tx import ConfigTransaction
from ..freeradius import paths

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/logs", tags=["logs"])

POLL_SECONDS = 2.0


@router.get("")
def get_logs(
    limit: int = Query(default=200, ge=1, le=2000),
    result: str | None = Query(default=None, alias="result"),
    username: str | None = Query(default=None, max_length=64),
    nas_ip: str | None = Query(default=None, max_length=64),
    hours: int = Query(default=24, ge=1, le=720),
    admin: Administrator = Depends(current_admin),
) -> dict:
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    data = logs.read_events(
        limit=limit, result_filter=result, username=username, nas_ip=nas_ip, since=since
    )
    data["filters"] = {
        "result": result,
        "username": username,
        "nas_ip": nas_ip,
        "hours": hours,
    }
    return data


@router.get("/capability")
def capability(admin: Administrator = Depends(current_admin)) -> dict:
    return logs.logging_capability()


@router.post("/enable-request-logging")
async def enable_request_logging(
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    """Install the managed request-logging configuration.

    Two files are involved and both go through the same
    BACKUP -> MODIFY -> `freeradius -XC` -> APPLY sequence as any other
    change, so the whole thing is reversible from Backup History:

    * ``sites-available/default`` gains a bare ``linelog`` invocation inside
      ``authenticate`` (unlang invokes a module by name);
    * ``mods-available/linelog`` gains ``auth_goodpass``/``auth_badpass`` so
      each attempt is recorded, including the reject reason.
    """
    site = paths.SITES_AVAILABLE / "default"
    mod = paths.MODS_AVAILABLE / "linelog"
    for path in (site, mod):
        if not path.exists():
            return {"ok": False, "error": f"{path} not found"}

    tx = ConfigTransaction()

    # All-or-nothing: if either file fails, both go back to their original
    # content, so the panel never leaves half of the feature installed.
    results = await tx.apply_group(
        entries=[
            # Module options first: the site reference is useless without them.
            ("mods_linelog", mod, logs.install_linelog_detail_block()),
            ("sites_default", site, logs.install_request_logging_block()),
        ],
        operation="ENABLE_REQUEST_LOGGING",
        administrator=admin.username,
        source_ip=client_ip(request),
        notes="installed managed linelog invocation",
    )
    backup_ids = [r.backup.id for r in results if r.backup]

    audit.record(
        db, "REQUEST_LOGGING_ENABLED", admin.username,
        object_type="config", object_id=str(site),
        source_ip=client_ip(request),
        detail={"backup_ids": backup_ids},
    )
    return {
        "ok": True,
        "message": "Request logging enabled. Reload FreeRADIUS for it to take effect.",
        "backup_id": backup_ids[0] if backup_ids else None,
        "backup_ids": backup_ids,
        "validation": results[-1].validation.as_dict(),
    }


@router.post("/disable-request-logging")
async def disable_request_logging(
    request: Request,
    admin: Administrator = Depends(require_role("operator")),
    db: Session = Depends(get_db),
) -> dict:
    site = paths.SITES_AVAILABLE / "default"
    mod = paths.MODS_AVAILABLE / "linelog"
    tx = ConfigTransaction()

    entries: list[tuple[str, Path, str]] = []
    if mod.exists():
        entries.append(
            ("mods_linelog", mod, logs.remove_linelog_detail_block())
        )
    entries.append(("sites_default", site, logs.remove_request_logging_block()))

    # Same all-or-nothing guarantee as enabling: the site reference must not be
    # removed while the module options remain, or vice versa.
    results = await tx.apply_group(
        entries=entries,
        operation="DISABLE_REQUEST_LOGGING",
        administrator=admin.username,
        source_ip=client_ip(request),
        notes="removed managed linelog invocation",
    )
    backup_ids = [r.backup.id for r in results if r.backup]

    audit.record(
        db, "REQUEST_LOGGING_DISABLED", admin.username,
        object_type="config", object_id=str(site), source_ip=client_ip(request),
        detail={"backup_ids": backup_ids},
    )
    return {
        "ok": True,
        "message": "Request logging disabled.",
        "backup_id": backup_ids[0] if backup_ids else None,
        "backup_ids": backup_ids,
    }


@router.post("/tail")
async def tail(
    limit: int = Query(default=100, ge=1, le=1000),
    admin: Administrator = Depends(current_admin),
) -> dict:
    return await logs.tail_events(limit=limit)


@router.get("/stream")
async def stream(request: Request, admin: Administrator = Depends(current_admin)):
    """Live event stream.

    Polls the log file; it never spawns ``freeradius -X`` and never runs a
    subprocess in a loop.
    """
    path = paths.LOG_DIR / "radius.log"
    linelog = paths.LOG_DIR / "linelog"

    async def generator():
        offset = path.stat().st_size if path.exists() else 0
        linelog_offset = linelog.stat().st_size if linelog.exists() else 0
        yield f"event: ready\ndata: {json.dumps({'streaming': True})}\n\n"

        last_ping = datetime.now(timezone.utc)
        try:
            while True:
                if await request.is_disconnected():
                    break

                for target, attr in ((path, "radius.log"), (linelog, "linelog")):
                    if not target.exists():
                        continue
                    current = await asyncio.to_thread(lambda p=target: p.stat().st_size)
                    prev = offset if attr == "radius.log" else linelog_offset
                    if current > prev:
                        raw = await asyncio.to_thread(
                            lambda p=target, o=prev: _read_from(p, o)
                        )
                        if attr == "radius.log":
                            offset = current
                        else:
                            linelog_offset = current
                        for line in raw:
                            event = logs.parse_log_line(line, source=attr)
                            if event:
                                yield (
                                    "event: log\n"
                                    f"data: {json.dumps(event.as_dict())}\n\n"
                                )

                now = datetime.now(timezone.utc)
                if (now - last_ping).total_seconds() >= 15:
                    last_ping = now
                    yield f"event: ping\ndata: {json.dumps({'t': now.isoformat()})}\n\n"

                await asyncio.sleep(POLL_SECONDS)
        except asyncio.CancelledError:  # pragma: no cover
            raise

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


def _read_from(path, offset: int) -> list[str]:
    from pathlib import Path

    with Path(path).open("r", encoding="utf-8", errors="replace") as fh:
        fh.seek(offset)
        data = fh.read()
    return data.splitlines()