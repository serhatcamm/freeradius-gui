"""Active Directory settings storage.

Keeps the persisted AD connection (see :mod:`app.services.active_directory`)
and exposes it to the API. Two rules shape this module:

* The bind password is write-only. AD account passwords cannot be read back,
  and exposing a stored copy over HTTP would be a worse leak than the file it
  lives in - the module file is root-owned, the API is not.
* Saving settings and installing them are separate steps. An operator should be
  able to store a configuration without turning AD authentication on, because
  enabling it changes how every RADIUS user is authenticated.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.db import AdSettings as AdSettingsRow
from ..models.db import utcnow
from . import active_directory as ad

logger = logging.getLogger(__name__)


def _loads(value: str | None) -> dict[str, str]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        # A corrupt row must not make the whole page 500. Report it as empty and
        # log: the operator can re-save, and the value is fully recoverable.
        logger.error("ad_settings.group_map is not valid JSON; treating it as empty")
        return {}
    if not isinstance(parsed, dict):
        logger.error("ad_settings.group_map is not an object; treating it as empty")
        return {}
    return {str(k): str(v) for k, v in parsed.items()}


def load(db: Session) -> ad.AdSettings | None:
    """Return the stored settings, or ``None`` if AD has never been configured."""
    row = db.execute(select(AdSettingsRow)).scalars().first()
    if row is None:
        return None
    servers = [s.strip() for s in row.servers.split(",") if s.strip()]
    return ad.AdSettings(
        domain=row.domain,
        base_dn=row.base_dn,
        bind_dn=row.bind_dn,
        servers=servers,
        port=row.port,
        use_ldaps=bool(row.use_ldaps),
        start_tls=bool(row.start_tls),
        tls_ca=row.tls_ca,
        membership_attribute=row.membership_attribute,
        membership_delimiter=row.membership_delimiter,
        group_map=_loads(row.group_map),
        bind_password=row.bind_password,
    )


def _row(db: Session) -> AdSettingsRow | None:
    return db.execute(select(AdSettingsRow)).scalars().first()


def save(
    db: Session,
    settings: ad.AdSettings,
    administrator: str,
    *,
    bind_password: str | None,
    enabled: bool,
) -> ad.AdSettings:
    """Persist the settings, creating or updating the single row.

    ``bind_password=None`` means "keep the stored one". That is the only way a
    caller can save an unrelated change (say, a group mapping) without
    supplying a credential it cannot read back.
    """
    settings.validate()

    row = _row(db)
    if row is None:
        row = AdSettingsRow()
        db.add(row)

    existing_password = row.bind_password
    if bind_password is not None:
        if len(bind_password) < ad._BIND_PASSWORD_MIN_LENGTH:
            raise ad.AdConfigError(
                f"The bind password must be at least {ad._BIND_PASSWORD_MIN_LENGTH} characters."
            )
        row.bind_password = bind_password

    row.domain = settings.domain.strip()
    row.base_dn = settings.base_dn.strip()
    row.bind_dn = settings.bind_dn.strip()
    row.servers = ",".join(s.strip() for s in settings.servers if s.strip())
    row.port = settings.port
    row.use_ldaps = settings.use_ldaps
    row.start_tls = settings.start_tls
    row.tls_ca = (settings.tls_ca or "").strip() or None
    row.membership_attribute = settings.membership_attribute
    row.membership_delimiter = settings.membership_delimiter
    row.group_map = json.dumps(settings.group_map, sort_keys=True)
    row.enabled = enabled
    row.updated_at = utcnow()
    row.updated_by = administrator

    # Settle the "keep existing password" case so the caller gets settings with
    # the effective credential attached for install_ldap_block, which needs it.
    settings.bind_password = bind_password if bind_password is not None else existing_password
    db.commit()
    db.refresh(row)
    return settings


def is_enabled(db: Session) -> bool:
    row = _row(db)
    return bool(row and row.enabled)


def set_enabled(db: Session, enabled: bool) -> None:
    row = _row(db)
    if row is None:
        raise ad.AdConfigError("Active Directory has not been configured yet.")
    row.enabled = enabled
    row.updated_at = utcnow()
    db.commit()


def status(db: Session) -> ad.Status:
    """Report configuration state and the local prerequisites.

    Reads the filesystem rather than trusting the stored ``enabled`` flag: a
    backup restore or a hand edit can change the raddb without going through
    the panel, and showing "Enabled" when the block is not actually installed
    would be the worst possible answer.
    """
    state = ad.Status(
        configured=False,
        ldap_module_installed=ad.ldap_module_exists(),
        ldap_block_installed=ad.ldap_block_installed(),
        ntlm_auth_available=ad.ntlm_auth_available(),
        winbind_installed=ad.winbind_installed(),
        winbind_joined=ad.winbind_joined(),
        prerequisites=ad.probe(),
    )
    row = _row(db)
    if row is None:
        return state

    state.configured = True
    state.domain = row.domain
    state.base_dn = row.base_dn
    state.bind_dn = row.bind_dn
    state.servers = [s.strip() for s in row.servers.split(",") if s.strip()]
    state.port = row.port
    state.group_map = _loads(row.group_map)
    state.bind_password_set = bool(row.bind_password)
    state.use_ldaps = bool(row.use_ldaps)
    state.start_tls = bool(row.start_tls)
    state.tls_ca = row.tls_ca
    state.membership_attribute = row.membership_attribute
    state.membership_delimiter = row.membership_delimiter
    state.enabled = bool(row.enabled)
    return state


def public_view(settings: ad.AdSettings, row_enabled: bool = False) -> dict[str, Any]:
    """Render settings for the API, without the bind password."""
    return {
        "domain": settings.domain,
        "base_dn": settings.base_dn,
        "bind_dn": settings.bind_dn,
        "servers": settings.servers,
        "port": settings.port,
        "use_ldaps": settings.use_ldaps,
        "start_tls": settings.start_tls,
        "tls_ca": settings.tls_ca,
        "membership_attribute": settings.membership_attribute,
        "membership_delimiter": settings.membership_delimiter,
        "group_map": settings.group_map,
        "bind_password_set": bool(settings.bind_password),
        "enabled": row_enabled,
    }


def check_no_duplicate_groups(group_map: dict[str, str]) -> None:
    """Reject two AD groups claiming the same RADIUS group name.

    Last-writer-wins on a duplicate would make the effective mapping depend on
    dictionary order, which is exactly the kind of invisible misconfiguration
    that shows up as one user with the wrong entitlements.
    """
    seen: dict[str, str] = {}
    for ad_dn, radius_group in group_map.items():
        if radius_group in seen:
            raise ad.AdConfigError(
                f"RADIUS group {radius_group!r} is mapped from two AD groups: "
                f"{seen[radius_group]} and {ad_dn}. Each RADIUS group must come "
                "from one AD group."
            )
        seen[radius_group] = ad_dn