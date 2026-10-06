"""Authentication: sessions, CSRF and login throttling."""
from __future__ import annotations

import hmac
import logging
import secrets
from datetime import timedelta

from fastapi import Depends, HTTPException, Request, Response, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..core.config import Settings, get_settings
from ..core.db import get_db
from ..models.db import Administrator, LoginAttempt, Session as SessionModel, utcnow
from . import audit
from ..security.passwords import verify_password, needs_rehash, hash_password

logger = logging.getLogger(__name__)

COOKIE_SESSION = "frw_session"
COOKIE_CSRF = "frw_csrf"


class AuthError(Exception):
    def __init__(self, message: str, status_code: int = status.HTTP_401_UNAUTHORIZED):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


# -- throttling --------------------------------------------------------
def _attempts_since(db: Session, identifier: str, window_seconds: int) -> int:
    cutoff = utcnow() - timedelta(seconds=window_seconds)
    rows = db.execute(
        select(LoginAttempt).where(
            LoginAttempt.identifier == identifier,
            LoginAttempt.attempted_at >= cutoff,
            LoginAttempt.successful.is_(False),
        )
    ).scalars()
    return sum(1 for _ in rows)


def is_rate_limited(db: Session, identifier: str, settings: Settings) -> bool:
    return _attempts_since(db, identifier, settings.login_attempt_window_seconds) >= (
        settings.login_max_attempts
    )


def _register_attempt(db: Session, identifier: str, successful: bool) -> None:
    db.add(LoginAttempt(identifier=identifier[:128], attempted_at=utcnow(), successful=successful))
    db.commit()


def prune_attempts(db: Session, older_than_seconds: int = 86400) -> None:
    cutoff = utcnow() - timedelta(seconds=older_than_seconds)
    db.execute(delete(LoginAttempt).where(LoginAttempt.attempted_at < cutoff))
    db.commit()


# -- sessions ----------------------------------------------------------
def _public_session(db: Session, request: Request | None, response: Response) -> SessionModel:
    settings = get_settings()
    token = request.cookies.get(COOKIE_SESSION) if request else None
    if not token:
        raise AuthError("Not authenticated")

    sid = hmac.new(
        _signing_key(), token.encode(), "sha256"
    ).hexdigest()[:64]

    row = db.execute(
        select(SessionModel).where(SessionModel.id == sid)
    ).scalar_one_or_none()
    if row is None:
        raise AuthError("Session not found")

    now = utcnow()
    if row.expires_at <= now:
        db.delete(row)
        db.commit()
        raise AuthError("Session expired")

    idle_limit = timedelta(seconds=settings.session_idle_timeout_seconds)
    if now - row.last_seen_at > idle_limit:
        db.delete(row)
        db.commit()
        raise AuthError("Session idle timeout")

    admin = row.administrator
    if not admin or not admin.is_active:
        raise AuthError("Account disabled", status.HTTP_403_FORBIDDEN)

    row.last_seen_at = now
    db.commit()
    return row


def _signing_key() -> bytes:
    from ..core.config import load_secret_key

    return load_secret_key()


def create_session(
    db: Session,
    admin: Administrator,
    response: Response,
    request: Request | None = None,
) -> tuple[SessionModel, str]:
    settings = get_settings()
    raw_token = secrets.token_urlsafe(32)
    sid = hmac.new(_signing_key(), raw_token.encode(), "sha256").hexdigest()[:64]

    row = SessionModel(
        id=sid,
        administrator_id=admin.id,
        created_at=utcnow(),
        expires_at=utcnow() + timedelta(seconds=settings.session_ttl_seconds),
        last_seen_at=utcnow(),
        ip_address=client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:256] if request else None,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    response.set_cookie(
        COOKIE_SESSION,
        raw_token,
        max_age=settings.session_ttl_seconds,
        httponly=True,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )
    csrf = secrets.token_urlsafe(32)
    # CSRF token must be readable by the SPA, so it is not HttpOnly.
    response.set_cookie(
        COOKIE_CSRF,
        csrf,
        max_age=settings.session_ttl_seconds,
        httponly=False,
        secure=settings.cookie_secure,
        samesite=settings.cookie_samesite,
        path="/",
    )
    return row, csrf


def destroy_session(db: Session, request: Request, response: Response) -> None:
    token = request.cookies.get(COOKIE_SESSION)
    if token:
        sid = hmac.new(_signing_key(), token.encode(), "sha256").hexdigest()[:64]
        row = db.get(SessionModel, sid)
        if row is not None:
            db.delete(row)
            db.commit()
    for name in (COOKIE_SESSION, COOKIE_CSRF):
        response.delete_cookie(name, path="/")


# -- CSRF --------------------------------------------------------------
def verify_csrf(request: Request) -> None:
    """Double-submit cookie check for unsafe methods."""
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return
    cookie = request.cookies.get(COOKIE_CSRF)
    header = request.headers.get("x-csrf-token")
    if not cookie or not header or not hmac.compare_digest(cookie, header):
        raise AuthError("CSRF validation failed", status.HTTP_403_FORBIDDEN)


def client_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else None


# -- login -------------------------------------------------------------
def authenticate(
    db: Session,
    username: str,
    password: str,
    settings: Settings,
    source_ip: str | None,
) -> Administrator:
    """Verify credentials, applying throttling and lockout."""
    ip_key = f"ip:{source_ip}" if source_ip else "ip:unknown"
    user_key = f"user:{username.lower()}"

    if is_rate_limited(db, user_key, settings) or is_rate_limited(db, ip_key, settings):
        _register_attempt(db, ip_key, False)
        raise AuthError(
            "Too many login attempts. Try again later.", status.HTTP_429_TOO_MANY_REQUESTS
        )

    admin = db.execute(
        select(Administrator).where(Administrator.username == username)
    ).scalar_one_or_none()

    if admin is None:
        # Constant-ish work regardless of user existence.
        _register_attempt(db, user_key, False)
        _register_attempt(db, ip_key, False)
        audit.record(
            db, audit.LOGIN_FAILURE, username, source_ip=source_ip, success=False,
            detail={"reason": "unknown user"},
        )
        raise AuthError("Invalid username or password")

    if not admin.is_active:
        _register_attempt(db, user_key, False)
        audit.record(
            db, audit.LOGIN_FAILURE, username, source_ip=source_ip, success=False,
            detail={"reason": "account disabled"},
        )
        raise AuthError("Account is disabled", status.HTTP_403_FORBIDDEN)

    if not verify_password(admin.password_hash, password):
        admin.failed_attempts = (admin.failed_attempts or 0) + 1
        db.commit()
        _register_attempt(db, user_key, False)
        _register_attempt(db, ip_key, False)
        audit.record(
            db, audit.LOGIN_FAILURE, admin.username, source_ip=source_ip, success=False,
            detail={"reason": "bad password"},
        )
        raise AuthError("Invalid username or password")

    if needs_rehash(admin.password_hash):
        try:
            admin.password_hash = hash_password(password)
            db.commit()
        except Exception:  # pragma: no cover
            logger.warning("could not upgrade password hash for %s", admin.username)

    admin.failed_attempts = 0
    admin.last_login_at = utcnow()
    admin.last_login_ip = source_ip
    db.commit()

    _register_attempt(db, user_key, True)
    audit.record(db, audit.LOGIN_SUCCESS, admin.username, source_ip=source_ip, success=True)
    return admin


# -- dependencies ------------------------------------------------------
def require_session(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> SessionModel:
    session = _public_session(db, request, response)
    verify_csrf(request)
    return session


def current_admin(session: SessionModel = Depends(require_session)) -> Administrator:
    return session.administrator