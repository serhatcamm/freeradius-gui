"""Active Directory endpoints.

Admin-only, and deliberately split into *store settings* and *install them*.
Enabling AD changes how every RADIUS user authenticates, so it is a separate
action with its own backup and audit entry rather than a side effect of saving
a form.
"""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..api.deps import require_role
from ..core.db import get_db
from ..models.db import Administrator
from ..schemas.api import AdSettingsIn, AdSettingsOut, OkResponse
from ..services import active_directory as ad
from ..services import ad_settings as ad_store
from ..services import audit
from ..services.auth import client_ip

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/active-directory", tags=["active-directory"])


def _settings_from(payload: AdSettingsIn) -> ad.AdSettings:
    return ad.AdSettings(
        domain=payload.domain,
        base_dn=payload.base_dn,
        bind_dn=payload.bind_dn,
        servers=list(payload.servers),
        port=payload.port,
        use_ldaps=payload.use_ldaps,
        start_tls=payload.start_tls,
        tls_ca=payload.tls_ca,
        membership_attribute=payload.membership_attribute,
        membership_delimiter=payload.membership_delimiter,
        group_map=dict(payload.group_map),
        bind_password=payload.bind_password,
    )


def _out(db: Session) -> AdSettingsOut:
    state = ad_store.status(db)
    return AdSettingsOut(
        configured=state.configured,
        domain=state.domain,
        base_dn=state.base_dn,
        bind_dn=state.bind_dn,
        servers=state.servers,
        port=state.port,
        use_ldaps=state.use_ldaps,
        start_tls=state.start_tls,
        tls_ca=state.tls_ca,
        membership_attribute=state.membership_attribute,
        membership_delimiter=state.membership_delimiter,
        group_map=state.group_map,
        bind_password_set=state.bind_password_set,
        enabled=state.enabled,
        ldap_block_installed=state.ldap_block_installed,
        ldap_module_installed=state.ldap_module_installed,
        ntlm_auth_available=state.ntlm_auth_available,
        winbind_installed=state.winbind_installed,
        winbind_joined=state.winbind_joined,
        ready=state.ready,
        prerequisites=[
            {"name": p.name, "ok": p.ok, "detail": p.detail} for p in state.prerequisites
        ],
        blocked_by=state.blocked_by,
    )


@router.get("", response_model=AdSettingsOut)
def get_settings_endpoint(
    db: Session = Depends(get_db),
    _: Administrator = Depends(require_role("admin")),
) -> AdSettingsOut:
    """Report the AD configuration and every unmet prerequisite."""
    return _out(db)


@router.put("", response_model=AdSettingsOut)
async def put_settings(
    payload: AdSettingsIn,
    request: Request,
    db: Session = Depends(get_db),
    actor: Administrator = Depends(require_role("admin")),
) -> AdSettingsOut:
    """Store (and optionally install) the AD connection."""
    settings = _settings_from(payload)
    try:
        ad_store.check_no_duplicate_groups(settings.group_map)
        settings.validate()
    except ad.AdConfigError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    already_enabled = ad_store.is_enabled(db)
    # Re-enabling on an update is idempotent, but only if AD was already on:
    # otherwise `enable` in this request is what turns it on, and the install
    # below is the thing that has to happen.
    want_enabled = payload.enable or already_enabled

    if want_enabled and not state_ready(db):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Active Directory cannot be enabled yet: "
            + ", ".join(ad_store.status(db).blocked_by)
            + ".",
        )

    try:
        stored = ad_store.save(
            db,
            settings,
            actor.username,
            bind_password=payload.bind_password,
            enabled=want_enabled,
        )
    except ad.AdConfigError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc

    audit.record(
        db,
        audit.AD_CONFIGURED,
        actor.username,
        source_ip=client_ip(request),
        object_type="active_directory",
        object_id=settings.domain,
        detail={
            "base_dn": settings.base_dn,
            "bind_dn": settings.bind_dn,
            "servers": settings.servers,
            "port": settings.port,
            "use_ldaps": settings.use_ldaps,
            "start_tls": settings.start_tls,
            "group_map": settings.group_map,
            "password_supplied": payload.bind_password is not None,
        },
    )

    if want_enabled:
        if not stored.bind_password:
            # save() has already created the row so the operator can correct
            # the credential, but it must not leave the database claiming AD
            # is enabled when no module was installed.
            ad_store.set_enabled(db, already_enabled)
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                "A bind password is required before Active Directory can be enabled.",
            )
        try:
            await ad.apply(
                stored,
                operation="AD_UPDATE" if already_enabled else "AD_ENABLE",
                administrator=actor.username,
                source_ip=client_ip(request),
                notes=f"Active Directory configured for {settings.domain}",
            )
        except Exception as exc:
            # ConfigTransaction compensates the files, but the database flag
            # is a separate resource. Keep it truthful if validation, a
            # privileged write, or a customised site definition rejects the
            # install. The prior enabled state is the state of the restored
            # files.
            ad_store.set_enabled(db, already_enabled)
            if isinstance(exc, ad.AdConfigError):
                raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc)) from exc
            raise
        audit.record(
            db,
            # A re-install of an already-enabled configuration is an update, not
            # a fresh enable; recording it as AD_ENABLED would make the audit
            # trail claim AD was switched on again when it never was off.
            audit.AD_CONFIGURED if already_enabled else audit.AD_ENABLED,
            actor.username,
            source_ip=client_ip(request),
            object_type="active_directory",
            object_id=settings.domain,
            detail={"domain": settings.domain, "installed": True},
        )
    elif payload.bind_password is not None:
        audit.record(
            db,
            audit.AD_PASSWORD_ROTATED,
            actor.username,
            source_ip=client_ip(request),
            object_type="active_directory",
            object_id=settings.domain,
            detail={"stored_only": True},
        )

    return _out(db)


def state_ready(db: Session) -> bool:
    """Whether every local prerequisite is currently satisfied.

    Checked before storing rather than after, so an operator who enabled AD
    from a host missing winbind gets an explanation instead of a config file
    that cannot work. winbind being absent means the panel would also refuse to
    write, since the install would fail validation.
    """
    state = ad_store.status(db)
    return all(p.ok for p in state.prerequisites)


@router.post("/disconnect", response_model=OkResponse)
async def disconnect(
    request: Request,
    db: Session = Depends(get_db),
    actor: Administrator = Depends(require_role("admin")),
) -> OkResponse:
    """Remove the managed AD block and restore the shipped behaviour."""
    settings = ad_store.load(db)
    if settings is None:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND, "Active Directory is not configured."
        )

    await ad.remove(
        operation="AD_DISABLE",
        administrator=actor.username,
        source_ip=client_ip(request),
        notes="Active Directory disconnected; local users authenticate again",
    )
    ad_store.set_enabled(db, False)

    audit.record(
        db,
        audit.AD_DISABLED,
        actor.username,
        source_ip=client_ip(request),
        object_type="active_directory",
        object_id=settings.domain,
        detail={"removed": True},
    )
    return OkResponse(
        ok=True,
        message=(
            "Active Directory disconnected. Local users and the users file "
            "authenticate again."
        ),
    )
