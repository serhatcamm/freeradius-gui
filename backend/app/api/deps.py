"""Shared API dependencies and error translation.

Stack traces are never returned to the browser; internal detail is logged
instead.
"""
from __future__ import annotations

import logging

from fastapi import Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..freeradius.runner import CommandFailed, CommandNotAllowed
from ..models.db import Administrator, Session as SessionModel
from ..services.auth import AuthError, client_ip, current_admin
from ..services.config_tx import ConfigValidationError, PermissionDeniedError
from ..services.backups import BackupError

logger = logging.getLogger(__name__)

DbSession = Depends(get_db)
AdminSession = Depends(current_admin)

#: Roles ordered from least to most privileged. "viewer" may read only;
#: "operator" may change users, clients and secrets; "admin" may additionally
#: restart the service and roll back backups.
ROLE_RANK = {"viewer": 0, "operator": 1, "admin": 2}


def require_role(minimum: str):
    """Dependency factory enforcing a minimum role on an endpoint.

    Authentication alone is not enough for privileged actions: any
    authenticated session must not be able to restart FreeRADIUS or restore
    backups.
    """

    async def _guard(
        request: Request,
        admin: Administrator = Depends(current_admin),
    ) -> Administrator:
        have = ROLE_RANK.get((admin.role or "").lower(), -1)
        need = ROLE_RANK.get(minimum, 99)
        if have < need:
            logger.warning(
                "rbac deny: %s (%s) needs %s for %s",
                admin.username,
                admin.role,
                minimum,
                request.url.path,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires the {minimum} role.",
            )
        return admin

    return _guard


#: Convenience dependencies for the two privilege levels the UI cares about.
OperatorSession = Depends(require_role("operator"))
AdminOnlySession = Depends(require_role("admin"))


async def api_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Translate domain exceptions into clean JSON responses."""
    if isinstance(exc, AuthError):
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.message},
        )

    if isinstance(exc, ConfigValidationError):
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Configuration validation failed",
                "detail": exc.validation.summary,
                "rolled_back": exc.rolled_back,
                "issues": [i.as_dict() for i in exc.validation.issues][:20],
            },
        )

    if isinstance(exc, PermissionDeniedError):
        logger.error("permission denied: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "error": "Permission failure",
                "detail": "The application is not permitted to write that file. "
                "Check the freeradius-web service account permissions.",
            },
        )

    if isinstance(exc, CommandNotAllowed):
        logger.error("blocked command: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"error": "Operation not permitted"},
        )

    if isinstance(exc, CommandFailed):
        logger.error("command failed: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_502_BAD_GATEWAY,
            content={
                "error": "FreeRADIUS command failed",
                "detail": (exc.stderr or exc.stdout or str(exc)).strip()[:400],
            },
        )

    if isinstance(exc, BackupError):
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"error": str(exc)},
        )

    if isinstance(exc, ValueError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": str(exc)},
        )

    logger.exception("unhandled error on %s", request.url.path)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "Internal server error"},
    )