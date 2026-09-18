"""POST /v1/admin/users/{id}/set-password — admin password reset.

This is the one endpoint that lets somebody choose another person's password,
so the guard on it and the revocation after it are the whole test surface. The
service-role key can already do this; what the endpoint adds is that an
ordinary admin can do it *without* the key, and that the reset is attributable.
"""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from tests.conftest import SUPABASE_URL

ADMIN_USERS_URL = f'{SUPABASE_URL}/auth/v1/admin/users'
PROFILES_URL = f'{SUPABASE_URL}/rest/v1/user_profiles'
REVOKE_URL = f'{SUPABASE_URL}/rest/v1/rpc/identity_revoke_user_sessions'

USER_ID = '11111111-2222-3333-4444-555555555555'
OTHER_ID = '99999999-8888-7777-6666-555555555555'

GOOD_PASSWORD = 'a-long-enough-password'


def profile_row(user_id=OTHER_ID, email='other@allset.in'):
    return {
        'user_id': user_id,
        'email': email,
        'full_name': 'Other Person',
        'phone': '',
        'roles': ['viewer'],
        'is_active': True,
        'legacy_migrated_at': None,
        'created_at': '2026-01-01T00:00:00Z',
    }


def auth_header(token):
    return {'Authorization': f'Bearer {token}'}


def mock_happy_path():
    """Profile lookup, the Supabase password write, and session revocation."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    put = respx.put(f'{ADMIN_USERS_URL}/{OTHER_ID}').mock(
        return_value=Response(200, json={'id': OTHER_ID})
    )
    revoke = respx.post(REVOKE_URL).mock(return_value=Response(200, text='2'))
    return put, revoke


# ── The guard ────────────────────────────────────────────────────────────────

def test_no_token_is_rejected(client):
    response = client.post(
        f'/v1/admin/users/{OTHER_ID}/set-password',
        json={'new_password': GOOD_PASSWORD},
    )
    assert response.status_code == 401


@pytest.mark.parametrize('roles', [
    ['viewer'], ['editor'], ['manager'], ['sales'], ['presales'],
    ['lead_manager'], ['manager', 'sales'], [],
])
@respx.mock
def test_non_admin_roles_cannot_set_a_password(client, make_token, jwks_mock, roles):
    """The worst thing a privilege-escalation bug here could do is let an editor
    take over an admin account, so every non-global role is checked."""
    put = respx.put(f'{ADMIN_USERS_URL}/{OTHER_ID}').mock(
        return_value=Response(200, json={'id': OTHER_ID})
    )
    token = make_token(roles=roles)
    response = client.post(
        f'/v1/admin/users/{OTHER_ID}/set-password',
        json={'new_password': GOOD_PASSWORD},
        headers=auth_header(token),
    )
    assert response.status_code == 403
    assert not put.called, 'a rejected caller must not reach Supabase at all'


@respx.mock
def test_deactivated_admin_cannot_set_a_password(client, make_token, jwks_mock):
    token = make_token(roles=['admin'], is_active=False)
    response = client.post(
        f'/v1/admin/users/{OTHER_ID}/set-password',
        json={'new_password': GOOD_PASSWORD},
        headers=auth_header(token),
    )
    assert response.status_code == 403


# ── The happy path ───────────────────────────────────────────────────────────

@pytest.mark.parametrize('role', ['admin', 'tech'])
@respx.mock
def test_admin_and_tech_can_set_a_password(client, make_token, jwks_mock, role):
    put, _ = mock_happy_path()

    token = make_token(roles=[role])
    response = client.post(
        f'/v1/admin/users/{OTHER_ID}/set-password',
        json={'new_password': GOOD_PASSWORD},
        headers=auth_header(token),
    )
    assert response.status_code == 204
    assert GOOD_PASSWORD in put.calls.last.request.read().decode()


@respx.mock
def test_the_password_is_written_to_the_right_user(client, make_token, jwks_mock):
    """The user id travels in the path. Sending it to the wrong Supabase user
    would set a password on somebody who never asked for one and leave the
    locked-out person still locked out."""
    put, _ = mock_happy_path()

    token = make_token(roles=['admin'], user_id=USER_ID)
    client.post(
        f'/v1/admin/users/{OTHER_ID}/set-password',
        json={'new_password': GOOD_PASSWORD},
        headers=auth_header(token),
    )
    assert put.calls.last.request.url.path.endswith(OTHER_ID)


@respx.mock
def test_setting_a_password_signs_the_user_out_everywhere(client, make_token, jwks_mock):
    """Whoever knew the old password may still hold a live session. With the
    access token now lasting 7 days, a reset that does not revoke has not
    actually recovered the account."""
    _, revoke = mock_happy_path()

    token = make_token(roles=['admin'])
    response = client.post(
        f'/v1/admin/users/{OTHER_ID}/set-password',
        json={'new_password': GOOD_PASSWORD},
        headers=auth_header(token),
    )
    assert response.status_code == 204
    assert revoke.called
    assert OTHER_ID in revoke.calls.last.request.read().decode()


@respx.mock
def test_an_admin_can_reset_their_own_password(client, make_token, jwks_mock):
    """Allowed, unlike removing your own admin role: it cannot lock the
    organisation out, it just signs this admin out along with everyone else's
    view of them."""
    respx.get(PROFILES_URL).mock(
        return_value=Response(200, json=[profile_row(user_id=USER_ID)])
    )
    respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )
    respx.post(REVOKE_URL).mock(return_value=Response(200, text='1'))

    token = make_token(roles=['admin'], user_id=USER_ID)
    response = client.post(
        f'/v1/admin/users/{USER_ID}/set-password',
        json={'new_password': GOOD_PASSWORD},
        headers=auth_header(token),
    )
    assert response.status_code == 204


# ── Validation ───────────────────────────────────────────────────────────────

@respx.mock
def test_a_short_password_is_rejected_before_supabase_is_touched(
    client, make_token, jwks_mock
):
    """The floor matches /v1/auth/password/change, so an admin-set password
    cannot be weaker than one the owner could choose for themselves."""
    put = respx.put(f'{ADMIN_USERS_URL}/{OTHER_ID}').mock(
        return_value=Response(200, json={'id': OTHER_ID})
    )
    token = make_token(roles=['admin'])
    response = client.post(
        f'/v1/admin/users/{OTHER_ID}/set-password',
        json={'new_password': 'short'},
        headers=auth_header(token),
    )
    assert response.status_code == 422
    assert not put.called


@respx.mock
def test_setting_a_password_on_a_missing_user_is_404(client, make_token, jwks_mock):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[]))
    put = respx.put(f'{ADMIN_USERS_URL}/{OTHER_ID}').mock(
        return_value=Response(200, json={'id': OTHER_ID})
    )
    token = make_token(roles=['admin'])
    response = client.post(
        f'/v1/admin/users/{OTHER_ID}/set-password',
        json={'new_password': GOOD_PASSWORD},
        headers=auth_header(token),
    )
    assert response.status_code == 404
    assert not put.called


# ── Failures must not read as success ────────────────────────────────────────

@respx.mock
def test_a_failed_revocation_is_not_swallowed(client, make_token, jwks_mock):
    """Same contract as a role change: reporting success while the old sessions
    stay live is worse than failing loudly, because the admin walks away
    believing the account is recovered."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    respx.put(f'{ADMIN_USERS_URL}/{OTHER_ID}').mock(
        return_value=Response(200, json={'id': OTHER_ID})
    )
    respx.post(REVOKE_URL).mock(return_value=Response(500, text='boom'))

    token = make_token(roles=['admin'])
    response = client.post(
        f'/v1/admin/users/{OTHER_ID}/set-password',
        json={'new_password': GOOD_PASSWORD},
        headers=auth_header(token),
    )
    assert response.status_code >= 500


@respx.mock
def test_a_missing_revocation_function_is_not_swallowed(client, make_token, jwks_mock):
    """PostgREST answers 404 on an RPC path when db/003_revoke_sessions.sql was
    never applied."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    respx.put(f'{ADMIN_USERS_URL}/{OTHER_ID}').mock(
        return_value=Response(200, json={'id': OTHER_ID})
    )
    respx.post(REVOKE_URL).mock(return_value=Response(404, json={'message': 'Not Found'}))

    token = make_token(roles=['admin'])
    response = client.post(
        f'/v1/admin/users/{OTHER_ID}/set-password',
        json={'new_password': GOOD_PASSWORD},
        headers=auth_header(token),
    )
    assert response.status_code >= 500


@respx.mock
def test_a_rejected_password_does_not_revoke_sessions(client, make_token, jwks_mock):
    """Supabase can refuse a password its own policy rejects. Signing the user
    out anyway would leave them worse off than before the attempt."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    respx.put(f'{ADMIN_USERS_URL}/{OTHER_ID}').mock(
        return_value=Response(422, json={'error_code': 'weak_password'})
    )
    revoke = respx.post(REVOKE_URL).mock(return_value=Response(200, text='1'))

    token = make_token(roles=['admin'])
    response = client.post(
        f'/v1/admin/users/{OTHER_ID}/set-password',
        json={'new_password': GOOD_PASSWORD},
        headers=auth_header(token),
    )
    assert response.status_code >= 400
    assert not revoke.called
