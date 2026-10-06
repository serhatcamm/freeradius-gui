"""Pydantic request/response models for the API."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..services.clients import ClientValidationError, validate_address, validate_client_name
from ..services.users import UserValidationError, validate_privilege, validate_username


# -- auth --------------------------------------------------------------
class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class AdministratorOut(BaseModel):
    username: str
    full_name: str | None = None
    role: str
    last_login_at: str | None = None


# -- alerts -------------------------------------------------------------
class AlertRuleCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    metric: str
    threshold: int
    window_seconds: int
    username: str | None = Field(default=None, max_length=64)
    client: str | None = Field(default=None, max_length=64)


class AlertRuleUpdate(BaseModel):
    """Every field optional; omitted fields keep their current value."""

    metric: str | None = None
    threshold: int | None = None
    window_seconds: int | None = None
    username: str | None = Field(default=None, max_length=64)
    client: str | None = Field(default=None, max_length=64)
    enabled: bool | None = None


class AlertRuleOut(BaseModel):
    id: int
    name: str
    metric: str
    metric_label: str
    username: str | None = None
    client: str | None = None
    threshold: int
    window_seconds: int
    enabled: bool
    created_at: str | None = None
    created_by: str | None = None
    last_fired_at: str | None = None
    #: Events counted in the current window when the rule was last evaluated.
    observed: int = 0
    would_fire: bool = False


class AlertOut(BaseModel):
    id: int
    raised_at: str | None = None
    observed: int
    threshold: int
    rule_name: str
    metric: str
    metric_label: str
    username: str | None = None
    client: str | None = None
    acknowledged_at: str | None = None
    acknowledged_by: str | None = None


class AlertList(BaseModel):
    alerts: list[AlertOut]
    count: int


class AdministratorRecord(AdministratorOut):
    """One row in the administrator list.

    ``is_self`` lets the UI disable the actions that would lock the operator
    out of their own session; the server rejects them regardless.
    """

    is_active: bool
    created_at: str | None = None
    last_login_ip: str | None = None
    failed_attempts: int = 0
    locked_until: str | None = None
    session_count: int = 0
    is_self: bool = False


class AdministratorList(BaseModel):
    administrators: list[AdministratorRecord]
    count: int
    active_admin_count: int


class AdministratorCreate(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=12, max_length=1024)
    role: str = Field(default="viewer")
    full_name: str | None = Field(default=None, max_length=128)


class AdministratorUpdate(BaseModel):
    """Every field optional; omitted fields are left untouched."""

    role: str | None = None
    full_name: str | None = Field(default=None, max_length=128)
    is_active: bool | None = None


class AdministratorPasswordReset(BaseModel):
    new_password: str = Field(min_length=12, max_length=1024)


class LoginResponse(BaseModel):
    administrator: AdministratorOut
    csrf_token: str
    session_expires_in: int


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


# -- users -------------------------------------------------------------
class UserCreate(BaseModel):
    username: str
    password: str = Field(min_length=1, max_length=1024)
    cisco_privilege: int | None = 15
    enabled: bool = True
    #: Optional group to attach via "Group = name".
    group: str = Field(default="", max_length=64)

    @field_validator("username")
    @classmethod
    def _u(cls, v: str) -> str:
        return validate_username(v)

    @field_validator("cisco_privilege")
    @classmethod
    def _p(cls, v: int | None) -> int | None:
        return validate_privilege(v)


class UserUpdate(BaseModel):
    password: str | None = Field(default=None, min_length=1, max_length=1024)
    cisco_privilege: int | None = None
    clear_cisco: bool = False
    #: Group name to attach, or "" to remove the user's group.
    group: str | None = Field(default=None, max_length=64)

    @field_validator("cisco_privilege")
    @classmethod
    def _p(cls, v: int | None) -> int | None:
        return validate_privilege(v)


class UserOut(BaseModel):
    model_config = ConfigDict(extra="allow")

    username: str
    auth_method: str
    enabled: bool
    status: str
    cisco_privilege: int | None
    cisco_avpairs: list[str]
    group: str = ""
    has_password: bool
    rejects: bool
    line_number: int
    last_authentication: str | None = None
    duplicate_entries: int | None = None


# -- clients -----------------------------------------------------------
class ClientCreate(BaseModel):
    name: str
    address: str
    secret: str | None = None
    nas_type: str = "other"
    description: str = ""
    ip_version: int = 4
    require_message_authenticator: bool = True

    @field_validator("name")
    @classmethod
    def _n(cls, v: str) -> str:
        return validate_client_name(v)

    @model_validator(mode="after")
    def _validate_ip(self) -> "ClientCreate":
        # Validate against the *declared* family; a v6 client with an IPv4
        # address would be rejected by FreeRADIUS at runtime otherwise.
        validate_address(self.address, self.ip_version)
        return self


class ClientUpdate(BaseModel):
    address: str | None = None
    nas_type: str | None = None
    description: str | None = None
    ip_version: int = 4
    require_message_authenticator: bool | None = None

    @model_validator(mode="after")
    def _validate_ip(self) -> "ClientUpdate":
        if self.address is not None:
            validate_address(self.address, self.ip_version)
        return self


class ClientOut(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    address: str | None
    address_kind: str
    has_secret: bool
    nas_type: str
    description: str
    enabled: bool
    status: str
    require_message_authenticator: bool
    line_number: int
    generated_secret: str | None = None


# -- groups -------------------------------------------------------------
class GroupAttribute(BaseModel):
    """One attribute inside a group definition."""

    model_config = ConfigDict(extra="forbid")

    key: str = Field(min_length=1, max_length=63)
    value: str = Field(min_length=1, max_length=253)
    reply: bool = False


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    attributes: list[GroupAttribute] = Field(default_factory=list, max_length=64)


class GroupUpdate(BaseModel):
    attributes: list[GroupAttribute] = Field(default_factory=list, max_length=64)


class GroupOut(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str
    is_default: bool
    line_number: int
    comment: str
    attributes: list[dict]
    #: Present on GET /api/groups/{name}; members set "Group = name" in authorize.
    members: list[str] = Field(default_factory=list)


class SecretResponse(BaseModel):
    """Returned only immediately after a create or reset."""

    name: str
    secret: str
    warning: str = (
        "This is the only time the secret is shown. Store it somewhere safe."
    )


# -- radius test -------------------------------------------------------
class RadiusTestRequest(BaseModel):
    username: str = Field(min_length=1, max_length=63)
    password: str = Field(min_length=1, max_length=1024)
    server: str = Field(default="127.0.0.1", max_length=253)
    port: int = Field(default=0, ge=0, le=65535)
    # Either supply the shared secret directly, or name a configured client and
    # let the server resolve it. The browser never has to hold a secret, which
    # keeps the "the API never returns client secrets" rule intact.
    secret: str | None = Field(default=None, min_length=1, max_length=128)
    client: str | None = Field(default=None, max_length=64)
    timeout: int = Field(default=15, ge=3, le=60)


class RadiusTestResult(BaseModel):
    result: str
    response_time_ms: float
    username: str
    server: str
    port: int
    returned_attributes: list[dict[str, str]]
    request_attributes: list[dict[str, str]]
    message_authenticator: str | None
    error: str | None


# -- generic -----------------------------------------------------------
class OkResponse(BaseModel):
    ok: bool = True
    message: str | None = None
    detail: dict[str, Any] | None = None


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None
    rolled_back: bool | None = None
    issues: list[dict[str, Any]] | None = None


class ValidationOut(BaseModel):
    ok: bool
    returncode: int
    issues: list[dict[str, Any]]
    summary: str


__all__ = [
    "AdministratorOut",
    "ChangePasswordRequest",
    "ClientCreate",
    "ClientOut",
    "ClientUpdate",
    "ErrorResponse",
    "LoginRequest",
    "LoginResponse",
    "OkResponse",
    "RadiusTestRequest",
    "RadiusTestResult",
    "SecretResponse",
    "UserCreate",
    "UserOut",
    "UserUpdate",
    "ValidationOut",
]