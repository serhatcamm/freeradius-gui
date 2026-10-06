"""Database engine and session handling.

SQLite is used for the lab; the same models run unchanged on PostgreSQL by
setting ``FRW_DATABASE_URL``.
"""
from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from ..core.config import Settings, get_settings
from ..models.db import Base

logger = logging.getLogger(__name__)

_engine: Engine | None = None
_SessionLocal: sessionmaker[Session] | None = None


def _configure_sqlite(engine: Engine) -> None:
    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_conn, _record):  # pragma: no cover - driver level
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()


def build_engine(settings: Settings | None = None) -> Engine:
    settings = settings or get_settings()
    url = settings.database_url

    if url.startswith("sqlite"):
        # Make sure the parent directory exists for file-backed databases.
        if "///" in url:
            db_path = Path(url.split("///", 1)[1])
            db_path.parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(
            url,
            future=True,
            connect_args={"check_same_thread": False, "timeout": 30},
        )
        _configure_sqlite(engine)
        return engine

    return create_engine(url, future=True, pool_pre_ping=True, pool_size=10, max_overflow=20)


def get_engine() -> Engine:
    global _engine
    if _engine is None:
        _engine = build_engine()
    return _engine


def get_sessionmaker() -> sessionmaker[Session]:
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(
            bind=get_engine(), expire_on_commit=False, future=True
        )
    return _SessionLocal


def init_db() -> None:
    """Create tables if they do not exist."""
    Base.metadata.create_all(bind=get_engine())
    logger.info("database schema ready")


def reset_engine() -> None:
    """Dispose the engine - used by tests."""
    global _engine, _SessionLocal
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _SessionLocal = None


@contextmanager
def session_scope() -> Iterator[Session]:
    session = get_sessionmaker()()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency."""
    session = get_sessionmaker()()
    try:
        yield session
    finally:
        session.close()