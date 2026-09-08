"""Browser-facing session endpoints.

Both admin UIs call these. Nothing here needs the service-role key except the
shadow-migration upgrade, which is why login is the one endpoint that touches
it — the frontends never do.
"""

from __future__ import annotations

import logging
import threading
import time

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field

from app import capabilities, legacy, profiles, supabase_client
from app.api.deps import Caller, current_caller
from app.core import config

logger = logging.getLogger(__name__)

router = APIRouter(prefix='/auth', tags=['auth'])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=256)


class RefreshRequest(BaseModel):
    refresh_token: str = Field(min_length=1)


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=10, max_length=256)


class PasswordResetRequest(BaseModel):
    email: EmailStr


# ── Login rate limiting ──────────────────────────────────────────────────────
# In-process, per-email. Replaces the CMS's users/throttles.py, which was
# IP-keyed and therefore shared across everyone behind one office NAT. Supabase
# applies its own limits on top; this exists to stop the legacy DB lookup from
# being used as a password oracle at speed.
_attempts: dict[str, list[float]] = {}
_attempts_lock = threading.Lock()


def _rate_limit(email: str) -> None:
    now = time.monotonic()
    window = config.LOGIN_RATE_WINDOW_SECONDS
    key = email.lower()

    with _attempts_lock:
        recent = [stamp for stamp in _attempts.get(key, []) if now - stamp < window]
        if len(recent) >= config.LOGIN_RATE_LIMIT:
            _attempts[key] = recent
            raise HTTPException(
                status.HTTP_429_TOO_MANY_REQUESTS,
                'too many sign-in attempts, try again shortly',
            )
        recent.append(now)
        _attempts[key] = recent

        # Opportunistic sweep so the dict cannot grow without bound.
        if len(_attempts) > 2048:
            for stale_key in [
                candidate for candidate, stamps in _attempts.items()
                if all(now - stamp >= window for stamp in stamps)
            ]:
                del _attempts[stale_key]


def _session_response(session: dict, profile_roles: list[str] | None = None) -> dict:
    """Shape a GoTrue token response for the frontends.

    The `user` block is the same payload /v1/introspect returns, so a client can
    render its UI from the login response without a second call.
    """
    user = session.get('user') or {}
    app_metadata = user.get('app_metadata') or {}

    roles = profile_roles if profile_roles is not None else app_metadata.get('roles') or []
    roles = sorted(role for role in roles if isinstance(role, str))
    is_active = bool(app_metadata.get('is_active', True))

    return {
        'access_token': session.get('access_token'),
        'refresh_token': session.get('refresh_token'),
        'token_type': 'bearer',
        'expires_in': session.get('expires_in', config.ACCESS_TOKEN_TTL_SECONDS),
        'user': capabilities.build_payload(
            user_id=user.get('id', ''),
            email=user.get('email', ''),
            roles=roles,
            is_active=is_active,
            full_name=(user.get('user_metadata') or {}).get('full_name', ''),
        ),
    }


@router.post('/login')
def login(payload: LoginRequest) -> dict:
    """Email + password sign-in.

    On a credential failure, falls through to the legacy CMS password check and
    upgrades the account in place if it matches. See app/legacy.py.
    """
    email = payload.email.strip().lower()
    _rate_limit(email)

    try:
        session = supabase_client.sign_in_with_password(email, payload.password)
    except supabase_client.InvalidCredentials:
        session = _try_legacy_login(email, payload.password)
        if session is None:
            # One generic message for every failure mode, so this cannot be used
            # to work out which addresses exist.
            raise HTTPException(
                status.HTTP_401_UNAUTHORIZED, 'invalid email or password'
            ) from None
    except supabase_client.SupabaseError as exc:
        raise HTTPException(exc.status_code, exc.message) from exc

    response = _session_response(session)

    if not response['user']['is_active']:
        raise HTTPException(status.HTTP_403_FORBIDDEN, 'account is not active')

    return response


def _try_legacy_login(email: str, password: str) -> dict | None:
    """Verify a Django PBKDF2 password, then adopt the account into Supabase."""
    legacy_user = legacy.verify_legacy_password(email, password)
    if legacy_user is None:
        return None

    logger.info('adopting legacy CMS account into Supabase')

    existing = supabase_client.admin_get_user_by_email(email)
    if existing is None:
        created = supabase_client.admin_create_user(
            email, password, full_name=legacy_user.full_name
        )
        user_id = created['id']
    else:
        user_id = existing['id']
        # The account exists in Supabase but the password did not match, so this
        # is a first login after provisioning. Adopt the legacy password.
        supabase_client.admin_set_password(user_id, password)

    profile = profiles.get_by_user_id(user_id)
    if profile is None:
        profiles.upsert(
            user_id=user_id,
            email=email,
            roles=legacy_user.roles,
            full_name=legacy_user.full_name,
            is_active=True,
        )
    profiles.mark_legacy_migrated(user_id)

    # Re-authenticate so the returned token carries claims from the hook, which
    # only now has a profile row to read.
    return supabase_client.sign_in_with_password(email, password)


@router.post('/refresh')
def refresh(payload: RefreshRequest) -> dict:
    try:
        session = supabase_client.refresh_session(payload.refresh_token)
    except supabase_client.InvalidCredentials:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, 'refresh token is invalid or expired'
        ) from None
    except supabase_client.SupabaseError as exc:
        raise HTTPException(exc.status_code, exc.message) from exc

    response = _session_response(session)
    if not response['user']['is_active']:
        # Deactivated mid-session: refuse to extend it.
        raise HTTPException(status.HTTP_403_FORBIDDEN, 'account is not active')
    return response


@router.post('/logout', status_code=status.HTTP_204_NO_CONTENT)
def logout(caller: Caller = Depends(current_caller)) -> None:
    supabase_client.sign_out(caller.token)


@router.get('/me')
def me(caller: Caller = Depends(current_caller)) -> dict:
    """The caller's identity and capabilities.

    Returns exactly what /v1/introspect returns for the same token, so a
    frontend's UI gating and a backend's authorisation cannot drift apart.
    """
    return capabilities.build_payload(
        user_id=caller.user_id,
        email=caller.email,
        roles=caller.roles,
        is_active=caller.is_active,
        full_name=caller.full_name,
    )


@router.post('/password/change', status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: PasswordChangeRequest, caller: Caller = Depends(current_caller)
) -> None:
    """Change your own password. Re-verifies the current one first, so a stolen
    access token alone cannot lock the owner out."""
    try:
        supabase_client.sign_in_with_password(caller.email, payload.current_password)
    except supabase_client.InvalidCredentials:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, 'current password is incorrect'
        ) from None

    supabase_client.admin_set_password(caller.user_id, payload.new_password)
    # Every other session was authenticated with the old password.
    supabase_client.admin_sign_out_everywhere(caller.user_id)


@router.post('/password/reset-request', status_code=status.HTTP_202_ACCEPTED)
def request_password_reset(payload: PasswordResetRequest) -> dict:
    """Send a set-password email.

    Always reports success, whether or not the address exists — otherwise this
    endpoint enumerates the roster.
    """
    supabase_client.send_recovery_email(payload.email.strip().lower())
    return {'detail': 'if that address has an account, a reset email is on its way'}


@router.get('/roles')
def list_roles() -> dict:
    """The role vocabulary, for populating admin UI role pickers.

    Served from app/capabilities.py so the two frontends stop hardcoding their
    own copies of the list — the CMS's admin_ui and Broker Tools' web app each
    had one, and they disagreed with the backends.
    """
    return {
        'roles': [
            {
                'value': role,
                'label': capabilities.ROLE_LABELS[role],
                'apps': [
                    app for app, caps in
                    capabilities.build_capabilities([role]).items() if caps['access']
                ],
                # The full capability payload for this role in isolation. Sent
                # so an admin UI can render a permissions reference table
                # without keeping its own copy of the matrix — both frontends
                # previously did, and both had drifted from their backends.
                # Note a user's actual capabilities are the union across all
                # the roles they hold, not any single entry here.
                'capabilities': capabilities.build_capabilities([role]),
            }
            for role in capabilities.ALL_ROLES
        ],
        'mutually_exclusive': [sorted(capabilities.DESK_ROLES)],
    }
