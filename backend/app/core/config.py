"""Application settings.

Every value can be overridden by environment variable so the same image can
be used in the lab and in production. Secrets are read from a file that is
not world-readable rather than from the environment where possible.
"""
from __future__ import annotations

import secrets
from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="FRW_",
        env_file="/etc/freeradius-web/app.env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # -- application -----------------------------------------------------
    app_name: str = "FreeRADIUS Web Management Panel"
    environment: str = "production"
    debug: bool = False

    # Bind to loopback only; nginx terminates TLS and proxies in.
    host: str = "127.0.0.1"
    port: int = 8000

    # -- storage ---------------------------------------------------------
    # SQLite by default; set to a PostgreSQL DSN to switch (schema is portable).
    database_url: str = "sqlite:////var/lib/freeradius-web/app.db"

    # -- security --------------------------------------------------------
    secret_key_file: str = "/etc/freeradius-web/secret_key"
    session_cookie_name: str = "frw_session"
    csrf_cookie_name: str = "frw_csrf"
    session_ttl_seconds: int = 3600
    session_idle_timeout_seconds: int = 900
    cookie_secure: bool = True
    cookie_samesite: str = "lax"

    login_max_attempts: int = 5
    login_attempt_window_seconds: int = 300
    login_lockout_seconds: int = 900

    # -- feature toggles -------------------------------------------------
    enable_docs: bool = False
    allow_password_change: bool = True

    # -- FreeRADIUS ------------------------------------------------------
    raddb_dir: str = "/etc/freeradius/3.0"
    freeradius_binary: str = "/usr/sbin/freeradius"
    radtest_binary: str = "/usr/bin/radtest"
    systemd_unit: str = "freeradius"
    backup_dir: str = "/var/lib/freeradius-web/backups"
    log_dir: str = "/var/log/freeradius"

    # Verbose internal errors may be returned to the browser only in debug.
    @field_validator("cookie_samesite")
    @classmethod
    def _samesite(cls, v: str) -> str:
        v = v.lower()
        if v not in {"lax", "strict", "none"}:
            raise ValueError("cookie_samesite must be lax, strict or none")
        return v

    @property
    def is_production(self) -> bool:
        return self.environment.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


def load_secret_key(settings: Settings | None = None) -> bytes:
    """Read the signing key from disk, generating one on first run.

    The key is used to sign session cookies. It is generated with
    ``secrets.token_bytes`` and stored 0600, owned by the service user.
    """
    settings = settings or get_settings()
    path = Path(settings.secret_key_file)
    if path.exists():
        data = path.read_bytes().strip()
        if data:
            return data
    key = secrets.token_bytes(48)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
    try:
        os_chmod_600(path)
    except OSError:
        pass
    return key


def os_chmod_600(path: Path) -> None:
    import os

    os.chmod(path, 0o600)