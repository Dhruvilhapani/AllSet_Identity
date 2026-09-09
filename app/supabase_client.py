"""Thin httpx wrapper over Supabase's Auth (GoTrue) and REST APIs.

Written directly against the HTTP API rather than using supabase-py, for the
same reason Broker Tools keeps its own DB helpers: one dependency fewer, and
every request's auth posture is visible at the call site. Two key tiers are used
deliberately:

  * anon key  — password grant and refresh. These are the calls a browser would
                make; using the anon key means Supabase applies its own rate
                limiting and lockout behaviour.
  * service   — everything administrative. Bypasses RLS and can act as any user,
                so it must never leave this process.
"""

from __future__ import annotations

import logging

import httpx

from app.core import config

logger = logging.getLogger(__name__)


class SupabaseError(Exception):
    """A non-success response from Supabase."""

    def __init__(self, message: str, status_code: int = 502, code: str | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code


class InvalidCredentials(SupabaseError):
    """Wrong email or password. Kept distinct so login can fall through to the
    legacy shadow-migration path without treating an outage as a bad password."""

    def __init__(self, message: str = 'invalid email or password'):
        super().__init__(message, status_code=401, code='invalid_credentials')


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=f'{config.SUPABASE_URL}/auth/v1',
        timeout=config.HTTP_TIMEOUT_SECONDS,
    )


def _anon_headers() -> dict[str, str]:
    return {
        'apikey': config.SUPABASE_ANON_KEY,
        'Authorization': f'Bearer {config.SUPABASE_ANON_KEY}',
        'Content-Type': 'application/json',
    }


def _service_headers() -> dict[str, str]:
    return {
        'apikey': config.SUPABASE_SERVICE_ROLE_KEY,
        'Authorization': f'Bearer {config.SUPABASE_SERVICE_ROLE_KEY}',
        'Content-Type': 'application/json',
    }


# Error codes GoTrue uses for a genuinely wrong email/password. Anything else at
# 400 is a malformed request or a policy rejection, not a credential mismatch —
# the distinction matters because only a real credential failure may fall
# through to the legacy shadow-migration path.
_BAD_CREDENTIAL_CODES = frozenset({
    'invalid_credentials',
    'invalid_grant',
    'email_not_confirmed',
    'user_not_found',
})


def _raise_for_status(response: httpx.Response, action: str) -> None:
    if response.is_success:
        return

    try:
        body = response.json()
    except ValueError:
        body = {}

    code = str(body.get('error_code') or body.get('error') or '').lower()
    status = response.status_code

    if status == 401 or (status == 400 and code in _BAD_CREDENTIAL_CODES):
        raise InvalidCredentials()

    if status == 429:
        raise SupabaseError('too many attempts, try again shortly', status_code=429, code=code)

    # Deliberately not logging the response body: GoTrue echoes the submitted
    # email address in some errors, and this lands in Cloud Logging.
    logger.warning('supabase %s failed: HTTP %s (code=%s)', action, status, code or 'none')
    raise SupabaseError(
        f'{action} failed',
        status_code=502 if status >= 500 else 400,
        code=code or None,
    )


# ── Session endpoints (anon key) ─────────────────────────────────────────────

def sign_in_with_password(email: str, password: str) -> dict:
    """Exchange credentials for a token pair. Raises InvalidCredentials on a
    bad password so the caller can try the legacy path."""
    with _client() as client:
        response = client.post(
            '/token',
            params={'grant_type': 'password'},
            headers=_anon_headers(),
            json={'email': email, 'password': password},
        )
    _raise_for_status(response, 'password sign-in')
    return response.json()


def refresh_session(refresh_token: str) -> dict:
    with _client() as client:
        response = client.post(
            '/token',
            params={'grant_type': 'refresh_token'},
            headers=_anon_headers(),
            json={'refresh_token': refresh_token},
        )
    _raise_for_status(response, 'token refresh')
    return response.json()


def sign_out(access_token: str) -> None:
    """Revoke the caller's own refresh token."""
    with _client() as client:
        response = client.post(
            '/logout',
            headers={**_anon_headers(), 'Authorization': f'Bearer {access_token}'},
        )
    # A already-invalid token is a successful logout from the client's view.
    if response.status_code not in (204, 401, 403):
        _raise_for_status(response, 'sign-out')


# ── Admin endpoints (service-role key) ──────────────────────────────────────

def admin_create_user(email: str, password: str | None, *, full_name: str = '') -> dict:
    """Create a user. email_confirm=True because email confirmation is disabled
    for this project — without it the account would exist but be unusable."""
    payload: dict = {
        'email': email,
        'email_confirm': True,
        'user_metadata': {'full_name': full_name} if full_name else {},
    }
    if password:
        payload['password'] = password

    with _client() as client:
        response = client.post('/admin/users', headers=_service_headers(), json=payload)
    _raise_for_status(response, 'user creation')
    return response.json()


def admin_get_user_by_email(email: str) -> dict | None:
    with _client() as client:
        response = client.get(
            '/admin/users', headers=_service_headers(), params={'filter': email, 'per_page': 1}
        )
    _raise_for_status(response, 'user lookup')
    users = response.json().get('users', [])
    # The filter is a substring match, so confirm an exact hit before trusting it.
    for user in users:
        if (user.get('email') or '').lower() == email.lower():
            return user
    return None


def admin_set_password(user_id: str, password: str) -> dict:
    with _client() as client:
        response = client.put(
            f'/admin/users/{user_id}',
            headers=_service_headers(),
            json={'password': password, 'email_confirm': True},
        )
    _raise_for_status(response, 'password update')
    return response.json()


def admin_sign_out_everywhere(user_id: str) -> None:
    """Kill every session for a user.

    Called on deactivation and on any role change. Roles live in the JWT and
    consumers cache for 60s, so without this a revoked role stays usable until
    the access token expires.

    Goes through the identity_revoke_user_sessions RPC rather than a GoTrue
    endpoint, because GoTrue has none that an admin can use:
    POST /admin/users/{id}/logout does not exist (404 "page not found"), and
    POST /logout?scope=global needs the user's own access token. Both verified
    against a live project. See db/003_revoke_sessions.sql.

    Raises on failure. An earlier version swallowed 404 as acceptable, which
    meant the wrong endpoint reported nothing at all and revocation silently
    did nothing — the caller must be able to tell the difference between "role
    removed and sessions killed" and "role removed, sessions still live".
    """
    with httpx.Client(
        base_url=f'{config.SUPABASE_URL}/rest/v1',
        timeout=config.HTTP_TIMEOUT_SECONDS,
    ) as client:
        response = client.post(
            '/rpc/identity_revoke_user_sessions',
            headers=_service_headers(),
            json={'target_user_id': user_id},
        )

    if response.status_code == 404:
        # The function is missing, not the user — a PostgREST 404 on an RPC
        # path means the migration was never applied.
        logger.error(
            'identity_revoke_user_sessions is missing; apply '
            'db/003_revoke_sessions.sql. Sessions were NOT revoked.'
        )
        raise SupabaseError('session revocation is not configured', status_code=500)

    if not response.is_success:
        logger.error('session revocation failed: HTTP %s', response.status_code)
        raise SupabaseError('session revocation failed', status_code=502)

    logger.info('revoked %s session row(s)', response.text.strip() or '?')


def admin_delete_user(user_id: str) -> None:
    with _client() as client:
        response = client.delete(f'/admin/users/{user_id}', headers=_service_headers())
    if response.status_code not in (200, 204, 404):
        _raise_for_status(response, 'user deletion')


def send_recovery_email(email: str) -> None:
    """Trigger a set-password email. Used for provisioning and for
    /v1/auth/password/reset-request.

    Never surfaces whether the address exists — the caller reports success
    either way so this cannot be used to enumerate the roster.
    """
    with _client() as client:
        response = client.post('/recover', headers=_anon_headers(), json={'email': email})
    if not response.is_success:
        logger.warning('recovery email for a submitted address returned HTTP %s', response.status_code)
