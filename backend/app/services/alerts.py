"""Alerting over authentication activity.

Rules are evaluated on read rather than by a background worker: the panel is a
single process that may be restarted at any time, and a timer-based design
would either lose alerts across a restart or need durable scheduling state. On
demand evaluation is honest - an alert is raised when someone asks whether the
system is healthy.

The counts come from the same parsed log events the Logs page shows, so an alert
can never disagree with what the operator can see.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.db import Alert, AlertRule, utcnow
from . import logs

logger = logging.getLogger(__name__)

#: metric -> human label. ``failures`` and ``challenges`` count Access-Reject
#: and Access-Challenge; ``successes`` counts Access-Accept; ``total`` counts
#: every request-level record.
METRICS = {
    "failures": "Failed authentications",
    "successes": "Successful authentications",
    "challenges": "Challenges issued",
    "total": "Authentication attempts",
}

MIN_THRESHOLD = 1
MAX_THRESHOLD = 100_000
MIN_WINDOW_SECONDS = 60
MAX_WINDOW_SECONDS = 7 * 24 * 3600

_RESULT_FOR_METRIC = {
    "failures": "Access-Reject",
    "successes": "Access-Accept",
    "challenges": "Access-Challenge",
}


class AlertConfigError(ValueError):
    """Invalid rule configuration, surfaced to the client as HTTP 400."""


def list_rules(db: Session) -> list[AlertRule]:
    return list(db.execute(select(AlertRule).order_by(AlertRule.name)).scalars())


def _validate(metric, threshold, window_seconds, username, client) -> None:
    if metric not in METRICS:
        raise AlertConfigError(f"Metric must be one of: {', '.join(sorted(METRICS))}.")
    if not MIN_THRESHOLD <= threshold <= MAX_THRESHOLD:
        raise AlertConfigError(
            f"Threshold must be between {MIN_THRESHOLD} and {MAX_THRESHOLD}."
        )
    if not MIN_WINDOW_SECONDS <= window_seconds <= MAX_WINDOW_SECONDS:
        raise AlertConfigError(
            f"Window must be between {MIN_WINDOW_SECONDS} and {MAX_WINDOW_SECONDS} seconds."
        )
    if client is not None and any(ch.isspace() for ch in client):
        raise AlertConfigError("Client name cannot contain whitespace.")
    if username is not None and any(ch.isspace() for ch in username):
        raise AlertConfigError("Username cannot contain whitespace.")


def create_rule(
    db: Session,
    actor: str,
    name: str,
    metric: str,
    threshold: int,
    window_seconds: int,
    username: str | None = None,
    client: str | None = None,
) -> AlertRule:
    name = (name or "").strip()
    if not 1 <= len(name) <= 64:
        raise AlertConfigError("Name must be 1-64 characters.")
    username = username.strip() if username else None
    client = client.strip() if client else None
    _validate(metric, threshold, window_seconds, username, client)

    if db.execute(select(AlertRule).where(AlertRule.name == name)).scalar_one_or_none():
        raise AlertConfigError(f"A rule named {name} already exists.")

    rule = AlertRule(
        name=name,
        metric=metric,
        username=username,
        client=client,
        threshold=threshold,
        window_seconds=window_seconds,
        enabled=True,
        created_by=actor,
    )
    db.add(rule)
    db.commit()
    db.refresh(rule)
    return rule


def update_rule(
    db: Session,
    rule: AlertRule,
    *,
    metric: str | None = None,
    threshold: int | None = None,
    window_seconds: int | None = None,
    username: str | None = None,
    client: str | None = None,
    enabled: bool | None = None,
) -> AlertRule:
    merged_metric = metric if metric is not None else rule.metric
    merged_threshold = threshold if threshold is not None else rule.threshold
    merged_window = window_seconds if window_seconds is not None else rule.window_seconds
    merged_user = (username.strip() if username else None) if username is not None else rule.username
    merged_client = (client.strip() if client else None) if client is not None else rule.client

    _validate(merged_metric, merged_threshold, merged_window, merged_user, merged_client)

    rule.metric = merged_metric
    rule.threshold = merged_threshold
    rule.window_seconds = merged_window
    rule.username = merged_user
    rule.client = merged_client
    if enabled is not None:
        rule.enabled = enabled
    db.commit()
    db.refresh(rule)
    return rule


def delete_rule(db: Session, rule: AlertRule) -> None:
    db.delete(rule)
    db.commit()


def list_alerts(db: Session, limit: int = 100, unacknowledged_only: bool = False) -> list[Alert]:
    stmt = select(Alert).order_by(Alert.raised_at.desc())
    if unacknowledged_only:
        stmt = stmt.where(Alert.acknowledged_at.is_(None))
    return list(db.execute(stmt.limit(limit)).scalars())


def acknowledge(db: Session, alert: Alert, actor: str) -> Alert:
    alert.acknowledged_at = utcnow()
    alert.acknowledged_by = actor
    db.commit()
    db.refresh(alert)
    return alert


def _local_now() -> datetime:
    return datetime.now(logs._local_tz())


def count_events(rule: AlertRule, events: list[logs.LogEvent]) -> int:
    """How many events match the rule's metric, scope and window."""
    window_start = _local_now() - timedelta(seconds=rule.window_seconds)
    observed = 0
    for event in events:
        if event.result is None:
            continue
        # Undated linelog lines cannot be placed in a window; counting them
        # would either invent a time or hide a real spike, so they are excluded.
        if event.timestamp is None or event.timestamp < window_start:
            continue
        if _RESULT_FOR_METRIC.get(rule.metric, None) != event.result:
            continue
        if rule.username and (event.username or "").lower() != rule.username.lower():
            continue
        if rule.client and rule.client not in (event.client or event.nas_ip or ""):
            continue
        observed += 1
    return observed


def read_events(horizon_seconds: int) -> list[logs.LogEvent]:
    """Parsed request events covering the widest window any rule asks for.

    One read serves every rule; reading per rule would re-parse the same tail
    once per row.
    """
    data = logs.read_events(
        limit=2000, since=_local_now() - timedelta(seconds=horizon_seconds)
    )
    return [
        logs.LogEvent(
            timestamp=datetime.fromisoformat(e["timestamp"]) if e["timestamp"] else None,
            severity=e["severity"],
            message=e["message"],
            source=e["source"],
            result=e.get("result"),
            username=e.get("username"),
            nas_ip=e.get("nas_ip"),
            client=e.get("client"),
            calling_station=e.get("calling_station"),
            reply=e.get("reply"),
        )
        for e in data["events"]
    ]


def evaluate(db: Session, rule: AlertRule, events: list[logs.LogEvent] | None = None) -> int:
    """Count the rule's metric over its window and raise an alert if needed.

    Returns the observed value. Only raises when the rule is enabled and the
    last alert is older than the window, which keeps a sustained condition from
    filling the table with duplicates. Passing ``events`` reuses an already-read
    tail instead of hitting the log again.
    """
    if not rule.enabled:
        return 0

    if events is None:
        try:
            events = read_events(rule.window_seconds)
        except OSError:  # pragma: no cover - unreadable log file
            logger.warning("could not read logs to evaluate %s", rule.name, exc_info=True)
            return 0

    observed = count_events(rule, events)
    if observed < rule.threshold:
        return observed

    # Dedupe: only fire again once the window has rolled over. Both sides are
    # naive UTC because the model persists naive timestamps (SQLite drops the
    # offset), so this must not mix an aware value in.
    now = utcnow()
    if rule.last_fired_at is not None:
        fired = rule.last_fired_at
        if fired.tzinfo is not None:
            fired = fired.astimezone(timezone.utc).replace(tzinfo=None)
        if (now - fired).total_seconds() < rule.window_seconds:
            return observed

    db.add(Alert(rule_id=rule.id, observed=observed))
    rule.last_fired_at = now
    db.commit()
    return observed


def evaluate_all(db: Session, persist: bool = True) -> list[dict]:
    """Evaluate every enabled rule.

    ``persist=False`` previews without raising alerts, which is what the UI
    shows before the operator commits a rule.
    """
    rules = [r for r in list_rules(db) if r.enabled]
    if not rules:
        return []

    # One log read serves every rule. The widest window governs the read.
    try:
        events = read_events(max(r.window_seconds for r in rules))
    except OSError:  # pragma: no cover - unreadable log file
        logger.warning("could not read logs for alert evaluation", exc_info=True)
        return []

    results = []
    for rule in rules:
        # Both paths count identically; the difference is only whether an alert
        # row is written, so the preview cannot disagree with the real result.
        observed = evaluate(db, rule, events) if persist else count_events(rule, events)
        results.append(
            {
                "rule": rule,
                "observed": observed,
                "would_fire": observed >= rule.threshold,
            }
        )
    return results