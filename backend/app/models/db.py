"""SQLAlchemy models.

The schema is deliberately portable: SQLite for the lab, PostgreSQL in
production. Only portable column types are used.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    """Naive UTC timestamp.

    SQLite does not store timezone information, so the whole application
    persists naive UTC. Use :func:`as_utc` when handing values to clients.
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


def as_utc(value: datetime | None) -> datetime | None:
    """Tag a naive-UTC value as UTC for JSON serialisation."""
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


class Base(DeclarativeBase):
    pass


class Administrator(Base):
    """A web-panel administrator. Deliberately separate from RADIUS users."""

    __tablename__ = "administrators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    # Argon2id PHC string. Plaintext passwords are never stored.
    password_hash: Mapped[str] = mapped_column(String(512))
    full_name: Mapped[str | None] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(32), default="admin")
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_ip: Mapped[str | None] = mapped_column(String(64))
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    sessions: Mapped[list["Session"]] = relationship(
        back_populates="administrator", cascade="all, delete-orphan"
    )


class Session(Base):
    """Server-side session. The cookie holds only an opaque identifier."""

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    administrator_id: Mapped[int] = mapped_column(
        ForeignKey("administrators.id", ondelete="CASCADE"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(256))

    administrator: Mapped[Administrator] = relationship(back_populates="sessions")


class AuditLog(Base):
    """Immutable record of administrative actions.

    Never stores passwords or shared secrets - the services layer is
    responsible for passing only safe metadata.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    administrator: Mapped[str] = mapped_column(String(64), index=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    object_type: Mapped[str | None] = mapped_column(String(64))
    object_id: Mapped[str | None] = mapped_column(String(128))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    detail: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (Index("ix_audit_ts_action", "timestamp", "action"),)


class LoginAttempt(Base):
    """Login throttling, keyed by username and by source IP."""

    __tablename__ = "login_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    identifier: Mapped[str] = mapped_column(String(128), index=True)
    attempted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    successful: Mapped[bool] = mapped_column(Boolean, default=False)


class AdSettings(Base):
    """The Active Directory connection this panel manages.

    A single row: there is one domain. The bind password is held here rather
    than re-derived per request because rlm_ldap has to read it from the module
    file, and keeping a second copy in the database lets the panel show whether
    one is configured without ever revealing it.

    ``bind_password`` is the one place a directory credential is stored outside
    FreeRADIUS's root-owned module file, so it is excluded from every audit
    payload - see ``services.audit``'s secret redaction.
    """

    __tablename__ = "ad_settings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    domain: Mapped[str] = mapped_column(String(255))
    base_dn: Mapped[str] = mapped_column(String(512))
    bind_dn: Mapped[str] = mapped_column(String(512))
    #: Comma-separated. A single scalar keeps the schema portable; the service
    #: parses it and the API always presents a list.
    servers: Mapped[str] = mapped_column(String(1024))
    port: Mapped[int] = mapped_column(Integer, default=389)
    use_ldaps: Mapped[bool] = mapped_column(Boolean, default=False)
    start_tls: Mapped[bool] = mapped_column(Boolean, default=True)
    tls_ca: Mapped[str | None] = mapped_column(String(512))
    membership_attribute: Mapped[str] = mapped_column(String(64), default="memberOf")
    membership_delimiter: Mapped[str] = mapped_column(String(8), default=";")
    #: AD group DN -> RADIUS group name, as JSON.
    group_map: Mapped[str] = mapped_column(Text, default="{}")
    bind_password: Mapped[str | None] = mapped_column(String(512))
    #: Whether the managed block is currently installed in the raddb.
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    updated_by: Mapped[str | None] = mapped_column(String(64))


class AlertRule(Base):
    """A threshold over authentication activity.

    ``metric`` selects what is counted; ``threshold`` is the value it must
    reach within ``window_seconds`` to fire. Rules are evaluated on demand
    (see ``services.alerts``), not by a background timer, so the panel stays
    stateless and a restart cannot silently drop alerts.
    """

    __tablename__ = "alert_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    metric: Mapped[str] = mapped_column(String(32))
    #: FreeRADIUS username the rule is scoped to; None means any user.
    username: Mapped[str | None] = mapped_column(String(64))
    #: FreeRADIUS client name the rule is scoped to; None means any client.
    client: Mapped[str | None] = mapped_column(String(64))
    threshold: Mapped[int] = mapped_column(Integer)
    window_seconds: Mapped[int] = mapped_column(Integer)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    created_by: Mapped[str] = mapped_column(String(64))
    last_fired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class Alert(Base):
    """A raised alert.

    Deduped against the rule's ``last_fired_at`` so a sustained condition does
    not produce one row per evaluation.
    """

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    rule_id: Mapped[int] = mapped_column(
        ForeignKey("alert_rules.id", ondelete="CASCADE"), index=True
    )
    raised_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
    #: The observed value that crossed the threshold.
    observed: Mapped[int] = mapped_column(Integer)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    acknowledged_by: Mapped[str | None] = mapped_column(String(64))

    rule: Mapped[AlertRule] = relationship()