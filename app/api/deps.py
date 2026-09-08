"""FastAPI dependencies.

Real `Depends()` rather than imperative checks in handler bodies, so the auth
requirement shows up in the OpenAPI schema. Broker Tools' FastAPI service does
the imperative version today and its /docs consequently claims every endpoint is
public — worth not repeating.
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app import capabilities
from app.core import security

_bearer = HTTPBearer(auto_error=False, description='Supabase access token')


@dataclass(frozen=True)
class Caller:
    """An authenticated person, resolved entirely from their token."""

    user_id: str
    email: str
    roles: list[str]
    is_active: bool
    full_name: str
    token: str

    @property
    def is_global_admin(self) -> bool:
        return bool(set(self.roles) & {capabilities.ADMIN, capabilities.TECH})


def require_service_key(
    x_allset_service_key: str | None = Header(default=None, alias='X-Allset-Service-Key'),
) -> None:
    """Guard for /v1/introspect. Fails closed when the key is unconfigured."""
    try:
        security.check_service_key(x_allset_service_key)
    except security.ServiceKeyInvalid as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc


def current_caller(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Caller:
    """Verify the bearer token locally and resolve the caller from its claims.

    No database or Supabase round trip: roles arrive in the token via the
    Custom Access Token Hook.
    """
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            'missing bearer token',
            headers={'WWW-Authenticate': 'Bearer'},
        )

    try:
        claims = security.verify_access_token(credentials.credentials)
    except security.TokenInvalid as exc:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            str(exc),
            headers={'WWW-Authenticate': 'Bearer'},
        ) from exc

    user_id, email, roles, is_active, full_name = security.claims_to_identity(claims)

    if not is_active:
        # Covers both a deactivated account and a token minted for a user with
        # no profile row, which the hook reports as inactive.
        raise HTTPException(status.HTTP_403_FORBIDDEN, 'account is not active')

    return Caller(
        user_id=user_id,
        email=email,
        roles=roles,
        is_active=is_active,
        full_name=full_name,
        token=credentials.credentials,
    )


def require_global_admin(caller: Caller = Depends(current_caller)) -> Caller:
    """Guard for /v1/admin/*. Only admin and tech may manage users."""
    if not caller.is_global_admin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, 'admin or tech role required')
    return caller
