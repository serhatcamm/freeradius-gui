"""Alert rule and alert endpoints.

Reading the rules evaluates them, so a response always carries the current
observed count next to the threshold. Acknowledging and editing are
operator-level; rule creation is admin-only because an alert rule is a standing
instruction to the panel.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from ..api.deps import require_role
from ..core.db import get_db
from ..models.db import Administrator, Alert, AlertRule, as_utc
from ..schemas.api import (
    AlertList,
    AlertRuleCreate,
    AlertRuleOut,
    AlertRuleUpdate,
    OkResponse,
)
from ..services import alerts as alerts_service
from ..services import audit
from ..services.auth import client_ip, current_admin

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/alerts", tags=["alerts"])


def _iso(value) -> str | None:
    return as_utc(value).isoformat() if value else None


def _rule_out(rule: AlertRule, observed: int = 0, would_fire: bool = False) -> AlertRuleOut:
    return AlertRuleOut(
        id=rule.id,
        name=rule.name,
        metric=rule.metric,
        metric_label=alerts_service.METRICS[rule.metric],
        username=rule.username,
        client=rule.client,
        threshold=rule.threshold,
        window_seconds=rule.window_seconds,
        enabled=rule.enabled,
        created_at=_iso(rule.created_at),
        created_by=rule.created_by,
        last_fired_at=_iso(rule.last_fired_at),
        observed=observed,
        would_fire=would_fire,
    )


def _alert_out(alert: Alert) -> dict:
    rule = alert.rule
    return {
        "id": alert.id,
        "raised_at": _iso(alert.raised_at),
        "observed": alert.observed,
        "threshold": rule.threshold,
        "rule_name": rule.name,
        "metric": rule.metric,
        "metric_label": alerts_service.METRICS[rule.metric],
        "username": rule.username,
        "client": rule.client,
        "acknowledged_at": _iso(alert.acknowledged_at),
        "acknowledged_by": alert.acknowledged_by,
    }


def _find_rule(db: Session, rule_id: int) -> AlertRule:
    rule = db.get(AlertRule, rule_id)
    if rule is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No such alert rule: {rule_id}")
    return rule


def _find_alert(db: Session, alert_id: int) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"No such alert: {alert_id}")
    return alert


@router.get("/rules", response_model=list[AlertRuleOut])
def list_rules(
    db: Session = Depends(get_db),
    _: Administrator = Depends(require_role("viewer")),
) -> list[AlertRuleOut]:
    """List rules, evaluating each so the observed count is current."""
    evaluated = alerts_service.evaluate_all(db)
    by_id = {item["rule"].id: item for item in evaluated}
    rules = alerts_service.list_rules(db)
    return [
        _rule_out(
            rule,
            observed=by_id[rule.id]["observed"] if rule.id in by_id else 0,
            would_fire=by_id[rule.id]["would_fire"] if rule.id in by_id else False,
        )
        for rule in rules
    ]


@router.post("/rules", response_model=AlertRuleOut, status_code=status.HTTP_201_CREATED)
def create_rule(
    payload: AlertRuleCreate,
    request: Request,
    db: Session = Depends(get_db),
    actor: Administrator = Depends(require_role("admin")),
) -> AlertRuleOut:
    try:
        rule = alerts_service.create_rule(
            db,
            actor.username,
            payload.name,
            payload.metric,
            payload.threshold,
            payload.window_seconds,
            payload.username,
            payload.client,
        )
    except alerts_service.AlertConfigError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    audit.record(
        db, "ALERT_RULE_CREATED", actor.username, source_ip=client_ip(request),
        object_type="alert_rule", object_id=rule.name,
        detail={
            "metric": rule.metric,
            "threshold": rule.threshold,
            "window_seconds": rule.window_seconds,
            "username": rule.username,
            "client": rule.client,
        },
    )
    return _rule_out(rule)


@router.patch("/rules/{rule_id}", response_model=AlertRuleOut)
def update_rule(
    rule_id: int,
    payload: AlertRuleUpdate,
    request: Request,
    db: Session = Depends(get_db),
    actor: Administrator = Depends(require_role("admin")),
) -> AlertRuleOut:
    rule = _find_rule(db, rule_id)
    before = {
        "metric": rule.metric,
        "threshold": rule.threshold,
        "window_seconds": rule.window_seconds,
        "enabled": rule.enabled,
    }
    try:
        rule = alerts_service.update_rule(
            db,
            rule,
            metric=payload.metric,
            threshold=payload.threshold,
            window_seconds=payload.window_seconds,
            username=payload.username,
            client=payload.client,
            enabled=payload.enabled,
        )
    except alerts_service.AlertConfigError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    audit.record(
        db, "ALERT_RULE_UPDATED", actor.username, source_ip=client_ip(request),
        object_type="alert_rule", object_id=rule.name,
        detail={
            "before": before,
            "after": {
                "metric": rule.metric,
                "threshold": rule.threshold,
                "window_seconds": rule.window_seconds,
                "enabled": rule.enabled,
            },
        },
    )
    return _rule_out(rule)


@router.delete("/rules/{rule_id}", response_model=OkResponse)
def delete_rule(
    rule_id: int,
    request: Request,
    db: Session = Depends(get_db),
    actor: Administrator = Depends(require_role("admin")),
) -> OkResponse:
    rule = _find_rule(db, rule_id)
    name = rule.name
    alerts_service.delete_rule(db, rule)
    audit.record(
        db, "ALERT_RULE_DELETED", actor.username, source_ip=client_ip(request),
        object_type="alert_rule", object_id=name,
    )
    return OkResponse(ok=True, message=f"Alert rule {name} deleted with its alerts.")


@router.get("", response_model=AlertList)
def list_alerts(
    limit: int = Query(default=100, ge=1, le=1000),
    unacknowledged_only: bool = Query(default=False),
    db: Session = Depends(get_db),
    _: Administrator = Depends(require_role("viewer")),
) -> AlertList:
    """Evaluate the rules first, then list.

    Evaluation has to happen here rather than only on the rules endpoint:
    opening the Alerts page is the whole point of the page, and a stored-but-
    never-re-evaluated list would show nothing until someone visited another
    route first.
    """
    alerts_service.evaluate_all(db)
    rows = alerts_service.list_alerts(db, limit=limit, unacknowledged_only=unacknowledged_only)
    return AlertList(alerts=[_alert_out(a) for a in rows], count=len(rows))


@router.post("/{alert_id}/acknowledge", response_model=OkResponse)
def acknowledge_alert(
    alert_id: int,
    request: Request,
    db: Session = Depends(get_db),
    actor: Administrator = Depends(require_role("operator")),
) -> OkResponse:
    alert = _find_alert(db, alert_id)
    alerts_service.acknowledge(db, alert, actor.username)
    audit.record(
        db, "ALERT_ACKNOWLEDGED", actor.username, source_ip=client_ip(request),
        object_type="alert", object_id=str(alert.id),
        detail={"rule": alert.rule.name},
    )
    return OkResponse(ok=True, message="Alert acknowledged.")


@router.post("/evaluate")
def evaluate_now(
    db: Session = Depends(get_db),
    _: Administrator = Depends(require_role("viewer")),
) -> dict:
    """Evaluate every rule and raise alerts.

    The list endpoints already evaluate, so this exists for a client that wants
    to force a fresh pass and read the result without parsing a list.
    """
    evaluated = alerts_service.evaluate_all(db)
    return {
        "evaluated": [
            _rule_out(item["rule"], item["observed"], item["would_fire"]).model_dump()
            for item in evaluated
        ],
        "count": len(evaluated),
    }