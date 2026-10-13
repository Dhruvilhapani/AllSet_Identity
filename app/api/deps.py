"""FastAPI dependencies.

Real `Depends()` rather than imperative checks in handler bodies, so the auth
requirement shows up in the OpenAPI schema. Broker Tools' FastAPI service does
the imperative version today and its /docs consequently claims every endpoint is
public — worth not repeating.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core import security
from app.permissions import cache
from app.permissions.payload import Identity, identity_from_claims

_bearer = HTTPBearer(auto_error=False, description='Supabase access token')


@dataclass(frozen=True)
class Caller:
    """An authenticated person, resolved from their token and the roster."""

    user_id: str
    email: str
    roles: list[str]
    is_active: bool
    full_name: str
    token: str
    phone: str = ''
    attributes: dict = field(default_factory=dict)
    # identity.console.use: who may administer users, roles and permissions.
    can_use_console: bool = False

    @property
    def is_global_admin(self) -> bool:
        return self.can_use_console

    @property
    def identity(self) -> Identity:
        return Identity(user_id=self.user_id, email=self.email, roles=self.roles,
                        is_active=self.is_active, full_name=self.full_name,
                        phone=self.phone, attributes=self.attributes)


def require_service_key(
    x_allset_service_key: str | None = Header(default=None, alias='X-Allset-Service-Key'),
) -> str | None:
    """Guard for service-to-service endpoints. Fails closed when no key is
    configured. Returns the calling service's name, or None for the shared key."""
    try:
        return security.check_service_key(x_allset_service_key)
    except security.ServiceKeyInvalid as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc


def current_caller(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
) -> Caller:
    """Verify the bearer token locally and resolve the caller.

    No per-request database or Supabase round trip: the signature is checked
    against cached JWKS, and roles and status come from the cached roster.
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

    snapshot = cache.current()
    identity = identity_from_claims(snapshot, claims)

    if not identity.is_active:
        # Covers a deactivated account, a deleted one, and a token minted for a
        # user with no profile row, which the hook reports as inactive.
        raise HTTPException(status.HTTP_403_FORBIDDEN, 'account is not active')

    resolved = snapshot.resolve(identity.roles)
    console = resolved.get('identity')
    return Caller(
        user_id=identity.user_id,
        email=identity.email,
        roles=identity.roles,
        is_active=identity.is_active,
        full_name=identity.full_name,
        token=credentials.credentials,
        phone=identity.phone,
        attributes=identity.attributes,
        can_use_console=bool(console and console.has('console', 'use')),
    )


def require_global_admin(caller: Caller = Depends(current_caller)) -> Caller:
    """Guard for /v1/admin/*: the identity.console.use permission, which the
    seed gives admin (as superuser) and tech."""
    if not caller.can_use_console:
        raise HTTPException(status.HTTP_403_FORBIDDEN, 'admin console access required')
    return caller
