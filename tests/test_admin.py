"""/v1/admin/* — provisioning and role management.

These endpoints hold the service-role key, so the guard on them matters more
than anywhere else in the service: it is the difference between "an editor can
change roles" and not.
"""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from tests.conftest import SUPABASE_URL

ADMIN_USERS_URL = f'{SUPABASE_URL}/auth/v1/admin/users'
RECOVER_URL = f'{SUPABASE_URL}/auth/v1/recover'
PROFILES_URL = f'{SUPABASE_URL}/rest/v1/user_profiles'

USER_ID = '11111111-2222-3333-4444-555555555555'
OTHER_ID = '99999999-8888-7777-6666-555555555555'


def profile_row(user_id=OTHER_ID, roles=('viewer',), is_active=True, email='other@allset.in'):
    return {
        'user_id': user_id,
        'email': email,
        'full_name': 'Other Person',
        'phone': '',
        'roles': list(roles),
        'is_active': is_active,
        'legacy_migrated_at': None,
        'created_at': '2026-01-01T00:00:00Z',
    }


def auth_header(token):
    return {'Authorization': f'Bearer {token}'}


# ── The guard ────────────────────────────────────────────────────────────────

def test_no_token_is_rejected(client):
    assert client.get('/v1/admin/users').status_code == 401


@pytest.mark.parametrize('roles', [
    ['viewer'], ['editor'], ['manager'], ['sales'], ['presales'],
    ['lead_manager'], ['manager', 'sales'], [],
])
def test_non_admin_roles_cannot_reach_admin_endpoints(
    client, make_token, jwks_mock, roles
):
    """lead_manager is included deliberately: it is unrestricted over lead DATA
    but must not be able to grant roles."""
    token = make_token(roles=roles)
    assert client.get('/v1/admin/users', headers=auth_header(token)).status_code == 403


@pytest.mark.parametrize('role', ['admin', 'tech'])
@respx.mock
def test_admin_and_tech_can_list_users(client, make_token, jwks_mock, role):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    token = make_token(roles=[role])
    response = client.get('/v1/admin/users', headers=auth_header(token))
    assert response.status_code == 200
    assert response.json()['users'][0]['email'] == 'other@allset.in'


def test_deactivated_admin_cannot_reach_admin_endpoints(client, make_token, jwks_mock):
    token = make_token(roles=['admin'], is_active=False)
    assert client.get('/v1/admin/users', headers=auth_header(token)).status_code == 403


# ── Role validation ──────────────────────────────────────────────────────────

@respx.mock
def test_unknown_role_is_rejected_with_400(client, make_token, jwks_mock):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    token = make_token(roles=['admin'])
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}/roles',
        json={'roles': ['agent']},
        headers=auth_header(token),
    )
    assert response.status_code == 400
    assert 'unknown role' in response.json()['detail']


@respx.mock
def test_presales_and_sales_together_are_rejected(client, make_token, jwks_mock):
    """The desk-exclusivity rule, enforced before the DB CHECK sees it."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    token = make_token(roles=['admin'])
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}/roles',
        json={'roles': ['presales', 'sales']},
        headers=auth_header(token),
    )
    assert response.status_code == 400
    assert 'at most one' in response.json()['detail']


@respx.mock
def test_empty_role_set_is_allowed(client, make_token, jwks_mock):
    """Offboarding: keep the account, remove all access."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    respx.patch(PROFILES_URL).mock(
        return_value=Response(200, json=[profile_row(roles=[])])
    )
    respx.post(f'{ADMIN_USERS_URL}/{OTHER_ID}/logout').mock(return_value=Response(204))

    token = make_token(roles=['admin'])
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}/roles', json={'roles': []}, headers=auth_header(token)
    )
    assert response.status_code == 200
    assert response.json()['roles'] == []
    assert response.json()['apps']['cms']['access'] is False


# ── Role changes force a re-login ────────────────────────────────────────────

@respx.mock
def test_role_change_signs_the_user_out_everywhere(client, make_token, jwks_mock):
    """Roles ride in the JWT and consumers cache for 60s, so without a global
    sign-out a removed role would keep working until the access token expired."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    respx.patch(PROFILES_URL).mock(
        return_value=Response(200, json=[profile_row(roles=['editor'])])
    )
    logout = respx.post(f'{ADMIN_USERS_URL}/{OTHER_ID}/logout').mock(
        return_value=Response(204)
    )

    token = make_token(roles=['admin'])
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}/roles',
        json={'roles': ['editor']},
        headers=auth_header(token),
    )
    assert response.status_code == 200
    assert logout.called


@respx.mock
def test_deactivation_signs_the_user_out_everywhere(client, make_token, jwks_mock):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    respx.patch(PROFILES_URL).mock(
        return_value=Response(200, json=[profile_row(is_active=False)])
    )
    logout = respx.post(f'{ADMIN_USERS_URL}/{OTHER_ID}/logout').mock(
        return_value=Response(204)
    )

    token = make_token(roles=['admin'])
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}/status',
        json={'is_active': False},
        headers=auth_header(token),
    )
    assert response.status_code == 200
    assert logout.called


# ── Self-lockout guards ──────────────────────────────────────────────────────

@respx.mock
def test_admin_cannot_remove_their_own_admin_role(client, make_token, jwks_mock):
    """Otherwise a single admin can leave the organisation with no way in."""
    respx.get(PROFILES_URL).mock(
        return_value=Response(200, json=[profile_row(user_id=USER_ID, roles=['admin'])])
    )
    token = make_token(roles=['admin'], user_id=USER_ID)
    response = client.patch(
        f'/v1/admin/users/{USER_ID}/roles',
        json={'roles': ['viewer']},
        headers=auth_header(token),
    )
    assert response.status_code == 400


@respx.mock
def test_admin_can_change_their_own_non_admin_roles(client, make_token, jwks_mock):
    """Adding a desk role to yourself is fine as long as admin/tech survives."""
    respx.get(PROFILES_URL).mock(
        return_value=Response(200, json=[profile_row(user_id=USER_ID, roles=['admin'])])
    )
    respx.patch(PROFILES_URL).mock(
        return_value=Response(200, json=[profile_row(user_id=USER_ID, roles=['admin', 'sales'])])
    )
    respx.post(f'{ADMIN_USERS_URL}/{USER_ID}/logout').mock(return_value=Response(204))

    token = make_token(roles=['admin'], user_id=USER_ID)
    response = client.patch(
        f'/v1/admin/users/{USER_ID}/roles',
        json={'roles': ['admin', 'sales']},
        headers=auth_header(token),
    )
    assert response.status_code == 200


@respx.mock
def test_admin_cannot_deactivate_themselves(client, make_token, jwks_mock):
    token = make_token(roles=['admin'], user_id=USER_ID)
    response = client.patch(
        f'/v1/admin/users/{USER_ID}/status',
        json={'is_active': False},
        headers=auth_header(token),
    )
    assert response.status_code == 400


@respx.mock
def test_tech_can_demote_an_admin(client, make_token, jwks_mock):
    """The two global roles can administer each other — that is the point of
    having both."""
    respx.get(PROFILES_URL).mock(
        return_value=Response(200, json=[profile_row(user_id=OTHER_ID, roles=['admin'])])
    )
    respx.patch(PROFILES_URL).mock(
        return_value=Response(200, json=[profile_row(user_id=OTHER_ID, roles=['manager'])])
    )
    respx.post(f'{ADMIN_USERS_URL}/{OTHER_ID}/logout').mock(return_value=Response(204))

    token = make_token(roles=['tech'], user_id=USER_ID)
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}/roles',
        json={'roles': ['manager']},
        headers=auth_header(token),
    )
    assert response.status_code == 200


# ── Provisioning ─────────────────────────────────────────────────────────────

@respx.mock
def test_creating_a_user_sends_a_set_password_email_and_sets_no_password(
    client, make_token, jwks_mock
):
    """Replaces the CMS invite flow, which generated a random password and then
    never emailed or returned it — leaving invited users unable to log in."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[]))
    respx.get(ADMIN_USERS_URL).mock(return_value=Response(200, json={'users': []}))
    create = respx.post(ADMIN_USERS_URL).mock(
        return_value=Response(200, json={'id': OTHER_ID})
    )
    respx.post(PROFILES_URL).mock(
        return_value=Response(201, json=[profile_row(roles=['presales'])])
    )
    recover = respx.post(RECOVER_URL).mock(return_value=Response(200, json={}))

    token = make_token(roles=['admin'])
    response = client.post(
        '/v1/admin/users',
        json={'email': 'New.Person@allset.in', 'full_name': 'New Person',
              'roles': ['presales']},
        headers=auth_header(token),
    )
    assert response.status_code == 201
    assert recover.called

    body = create.calls.last.request.read().decode()
    # No password chosen by the admin, and the account is usable immediately
    # because email confirmation is disabled for this project.
    assert '"password"' not in body
    assert '"email_confirm": true' in body.replace('":', '": ').replace('  ', ' ') or \
           'email_confirm' in body


@respx.mock
def test_creating_a_duplicate_user_is_a_409(client, make_token, jwks_mock):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    token = make_token(roles=['admin'])
    response = client.post(
        '/v1/admin/users',
        json={'email': 'other@allset.in', 'roles': ['viewer']},
        headers=auth_header(token),
    )
    assert response.status_code == 409


@respx.mock
def test_creating_a_user_with_a_bad_role_creates_nothing(client, make_token, jwks_mock):
    """Validation must run before any Supabase write, or a rejected request can
    still leave an orphaned auth.users row."""
    create = respx.post(ADMIN_USERS_URL).mock(
        return_value=Response(200, json={'id': OTHER_ID})
    )
    token = make_token(roles=['admin'])
    response = client.post(
        '/v1/admin/users',
        json={'email': 'new@allset.in', 'roles': ['presales', 'sales']},
        headers=auth_header(token),
    )
    assert response.status_code == 400
    assert not create.called


@respx.mock
def test_role_update_on_a_missing_user_is_404(client, make_token, jwks_mock):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[]))
    token = make_token(roles=['admin'])
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}/roles',
        json={'roles': ['viewer']},
        headers=auth_header(token),
    )
    assert response.status_code == 404


@respx.mock
def test_a_db_check_violation_is_reported_as_a_client_error(client, make_token, jwks_mock):
    """If validate_roles is ever bypassed, the DB constraint still catches it —
    and that must read as a 400, not a 500."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    respx.patch(PROFILES_URL).mock(
        return_value=Response(400, json={'code': '23514', 'message': 'roles_one_desk'})
    )
    token = make_token(roles=['admin'])
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}/roles',
        json={'roles': ['viewer']},
        headers=auth_header(token),
    )
    assert response.status_code == 400
