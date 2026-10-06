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