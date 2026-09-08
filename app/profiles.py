"""public.user_profiles access, via Supabase's REST (PostgREST) API.

Uses the service-role key, which bypasses the RLS that db/001_schema.sql enables
with no policies. Going through REST rather than a direct Postgres connection
keeps this service free of a connection pool — it makes at most one profile call
per request, and only on paths that are not the hot path (login, /auth/me,
admin). Token introspection reads roles from the JWT and touches nothing here.
"""

from __future__ import annotations

import logging

import httpx

from app.capabilities import validate_roles
from app.core import config

logger = logging.getLogger(__name__)

_TABLE = 'user_profiles'


class ProfileError(Exception):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class ProfileNotFound(ProfileError):
    def __init__(self, message: str = 'profile not found'):
        super().__init__(message, status_code=404)


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=f'{config.SUPABASE_URL}/rest/v1',
        timeout=config.HTTP_TIMEOUT_SECONDS,
    )


def _headers(*, prefer: str | None = None) -> dict[str, str]:
    headers = {
        'apikey': config.SUPABASE_SERVICE_ROLE_KEY,
        'Authorization': f'Bearer {config.SUPABASE_SERVICE_ROLE_KEY}',
        'Content-Type': 'application/json',
    }
    if prefer:
        headers['Prefer'] = prefer
    return headers


def _check(response: httpx.Response, action: str) -> None:
    if response.is_success:
        return
    try:
        body = response.json()
    except ValueError:
        body = {}
    code = body.get('code')
    # 23514 is a CHECK violation — roles_valid, roles_one_desk or roles_no_nulls.
    # Reaching it means validate_roles was bypassed, so report it as a client
    # error rather than a server fault.
    if code == '23514':
        raise ProfileError('invalid role set rejected by the database', status_code=400)
    if code == '23505':
        raise ProfileError('a profile with that email already exists', status_code=409)
    logger.warning('profile %s failed: HTTP %s (code=%s)', action, response.status_code, code)
    raise ProfileError(f'{action} failed')


def get_by_user_id(user_id: str) -> dict | None:
    with _client() as client:
        response = client.get(
            f'/{_TABLE}', headers=_headers(), params={'user_id': f'eq.{user_id}', 'limit': 1}
        )
    _check(response, 'lookup')
    rows = response.json()
    return rows[0] if rows else None


def get_by_email(email: str) -> dict | None:
    with _client() as client:
        response = client.get(
            f'/{_TABLE}', headers=_headers(), params={'email': f'eq.{email}', 'limit': 1}
        )
    _check(response, 'lookup')
    rows = response.json()
    return rows[0] if rows else None


def list_all() -> list[dict]:
    with _client() as client:
        response = client.get(
            f'/{_TABLE}', headers=_headers(), params={'order': 'email.asc', 'limit': 500}
        )
    _check(response, 'list')
    return response.json()


def upsert(
    *,
    user_id: str,
    email: str,
    roles: list[str],
    full_name: str = '',
    phone: str = '',
    is_active: bool = True,
    legacy_migrated_at: str | None = None,
) -> dict:
    """Create or replace a profile. Roles are validated here as well as by the
    DB CHECK constraints."""
    payload = {
        'user_id': user_id,
        'email': email,
        'roles': validate_roles(roles),
        'full_name': full_name,
        'phone': phone,
        'is_active': is_active,
    }
    if legacy_migrated_at is not None:
        payload['legacy_migrated_at'] = legacy_migrated_at

    with _client() as client:
        response = client.post(
            f'/{_TABLE}',
            headers=_headers(prefer='return=representation,resolution=merge-duplicates'),
            json=payload,
        )
    _check(response, 'upsert')
    rows = response.json()
    return rows[0] if rows else payload


def update(user_id: str, changes: dict) -> dict:
    if 'roles' in changes:
        changes = {**changes, 'roles': validate_roles(changes['roles'])}

    with _client() as client:
        response = client.patch(
            f'/{_TABLE}',
            headers=_headers(prefer='return=representation'),
            params={'user_id': f'eq.{user_id}'},
            json=changes,
        )
    _check(response, 'update')
    rows = response.json()
    if not rows:
        raise ProfileNotFound()
    return rows[0]


def mark_legacy_migrated(user_id: str) -> None:
    """Stamp legacy_migrated_at. Once non-null for every row, the shadow
    migration path can be switched off and deleted."""
    with _client() as client:
        response = client.patch(
            f'/{_TABLE}',
            headers=_headers(),
            params={'user_id': f'eq.{user_id}'},
            json={'legacy_migrated_at': 'now()'},
        )
    _check(response, 'legacy stamp')
