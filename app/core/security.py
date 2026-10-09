"""Token verification and service-key checking.

The design goal here is that verifying a token costs no I/O. JWKS is fetched
once and cached; a token's `kid` only triggers a refetch if it is unrecognised
(which happens when Supabase rotates signing keys). Roles arrive in the token
itself via the Custom Access Token Hook, so there is nothing to look up.
"""

from __future__ import annotations

import hmac
import logging
import threading
import time

import httpx
from jose import jwt
from jose.exceptions import JWTError

from app.capabilities import ALL_ROLES
from app.core import config

logger = logging.getLogger(__name__)


class TokenInvalid(Exception):
    """The token is absent, malformed, expired, or not signed by our project."""


class ServiceKeyInvalid(Exception):
    """The caller did not present a valid service key."""


def check_service_key(presented: str | None) -> None:
    """Guard for /v1/introspect and other service-to-service endpoints.

    Fails closed when ALLSET_SERVICE_KEY is unset, so a misconfigured deploy
    refuses traffic instead of accepting anonymous introspection. Same posture
    as Broker Tools' HasLeadsMasterSyncSecret / HasBrokerToolsServiceSecret.
    """
    accepted = [key for key in (config.SERVICE_KEY, *config.SERVICE_KEYS.values()) if key]
    if not accepted:
        logger.error('no service key is configured; refusing service request')
        raise ServiceKeyInvalid('service authentication is not configured')
    if not presented or not any(hmac.compare_digest(presented, key) for key in accepted):
        raise ServiceKeyInvalid('invalid service key')


def bearer_token(authorization: str | None) -> str:
    """Pull the token out of an Authorization header."""
    if not authorization:
        raise TokenInvalid('missing Authorization header')
    scheme, _, token = authorization.partition(' ')
    if scheme.lower() != 'bearer' or not token.strip():
        raise TokenInvalid('Authorization header must be "Bearer <token>"')
    return token.strip()


class _JwksCache:
    """Signing keys, fetched lazily and refreshed only on an unknown kid.

    A short negative-refetch floor stops a stream of tokens carrying a bogus kid
    from turning into a stream of outbound requests.
    """

    _MIN_REFETCH_INTERVAL = 30.0

    def __init__(self) -> None:
        self._keys: dict[str, dict] = {}
        self._last_fetch = 0.0
        self._lock = threading.Lock()

    def _fetch(self) -> None:
        response = httpx.get(config.SUPABASE_JWKS_URL, timeout=config.HTTP_TIMEOUT_SECONDS)
        response.raise_for_status()
        keys = response.json().get('keys', [])
        self._keys = {key['kid']: key for key in keys if 'kid' in key}
        self._last_fetch = time.monotonic()
        logger.info('fetched %d JWKS signing key(s)', len(self._keys))

    def get(self, kid: str) -> dict:
        key = self._keys.get(kid)
        if key is not None:
            return key

        with self._lock:
            # Re-check: another thread may have refreshed while we waited.
            key = self._keys.get(kid)
            if key is not None:
                return key
            if time.monotonic() - self._last_fetch < self._MIN_REFETCH_INTERVAL:
                raise TokenInvalid(f'unknown signing key: {kid}')
            try:
                self._fetch()
            except httpx.HTTPError as exc:
                # Never fall back to skipping verification.
                raise TokenInvalid('signing keys unavailable') from exc

        key = self._keys.get(kid)
        if key is None:
            raise TokenInvalid(f'unknown signing key: {kid}')
        return key

    def clear(self) -> None:
        self._keys = {}
        self._last_fetch = 0.0


_jwks = _JwksCache()


def verify_access_token(token: str) -> dict:
    """Verify a Supabase access token locally and return its claims.

    Handles both signing schemes a Supabase project may be on:
      * asymmetric (RS256/ES256) — verified against JWKS, the current default
      * symmetric (HS256) — verified with the project's legacy JWT secret

    Raises TokenInvalid for anything not provably ours and unexpired.
    """
    try:
        header = jwt.get_unverified_header(token)
    except JWTError as exc:
        raise TokenInvalid('malformed token') from exc

    algorithm = header.get('alg', '')
    kid = header.get('kid')

    if algorithm == 'HS256':
        secret = config.SUPABASE_JWT_SECRET
        if not secret:
            raise TokenInvalid('token is HS256-signed but SUPABASE_JWT_SECRET is not set')
        key: object = secret
    elif algorithm in ('RS256', 'ES256'):
        if not kid:
            raise TokenInvalid('token header is missing kid')
        key = _jwks.get(kid)
    else:
        raise TokenInvalid(f'unsupported token algorithm: {algorithm or "none"}')

    try:
        claims = jwt.decode(
            token,
            key,
            algorithms=[algorithm],
            audience=config.SUPABASE_JWT_AUDIENCE,
            issuer=config.SUPABASE_JWT_ISSUER,
            # python-jose verifies exp/iat/aud/iss by default; named here so a
            # future change to the library's defaults cannot silently weaken us.
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_aud': True,
                'verify_iss': True,
            },
        )
    except JWTError as exc:
        raise TokenInvalid(str(exc)) from exc

    if not claims.get('sub'):
        raise TokenInvalid('token has no subject')

    return claims


def claims_to_identity(claims: dict) -> tuple[str, str, list[str], bool, str]:
    """Extract (user_id, email, roles, is_active, full_name) from verified claims.

    Roles come from app_metadata, written by the Custom Access Token Hook. A
    token with no app_metadata.roles predates the hook or belongs to a user with
    no profile row — either way it resolves to no roles and inactive, which
    denies both apps rather than defaulting to something permissive.

    Roles are filtered against the known vocabulary here, at the boundary where
    token content enters the system. A token can outlive a role being retired
    (a long-lived refresh, or a rename shipped mid-session), and an unrecognised
    role must be ignored rather than propagated — it grants nothing either way,
    but downstream code looks roles up by name.
    """
    app_metadata = claims.get('app_metadata') or {}
    raw_roles = app_metadata.get('roles')

    roles: list[str] = []
    if isinstance(raw_roles, list):
        for role in raw_roles:
            if isinstance(role, str) and role in ALL_ROLES and role not in roles:
                roles.append(role)
        unknown = [
            role for role in raw_roles
            if isinstance(role, str) and role not in ALL_ROLES
        ]
        if unknown:
            logger.info('ignoring %d unrecognised role(s) in token', len(unknown))

    return (
        claims['sub'],
        claims.get('email') or app_metadata.get('email') or '',
        sorted(roles),
        bool(app_metadata.get('is_active', False)),
        app_metadata.get('full_name') or '',
    )
