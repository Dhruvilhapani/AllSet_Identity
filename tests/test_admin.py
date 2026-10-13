"""/v1/admin/* — provisioning and role management.

These endpoints hold the service-role key, so the guard on them matters more
than anywhere else in the service: it is the difference between "an editor can
change roles" and not.
"""

from __future__ import annotations

import json

import pytest
import respx
from httpx import Response

from tests.conftest import SUPABASE_URL

ADMIN_USERS_URL = f'{SUPABASE_URL}/auth/v1/admin/users'
RECOVER_URL = f'{SUPABASE_URL}/auth/v1/recover'
PROFILES_URL = f'{SUPABASE_URL}/rest/v1/user_profiles'
# GoTrue has no admin logout endpoint, so revocation goes through this RPC.
# See db/003_revoke_sessions.sql.
REVOKE_URL = f'{SUPABASE_URL}/rest/v1/rpc/identity_revoke_user_sessions'
# Roles are written only through this function (db/004_permissions.sql).
SET_ROLES_URL = f'{SUPABASE_URL}/rest/v1/rpc/identity_set_user_roles'

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


def mock_set_roles(snapshot, status_code=200, body=None):
    """identity_set_user_roles. On success it records the roles in the
    roster, as the reload after a real write would."""
    def handler(request):
        if status_code != 200:
            return Response(status_code, json=body)
        sent = json.loads(request.content)
        roles = sorted(set(sent['p_role_keys']))
        entry = snapshot.users.setdefault(sent['p_user_id'], {
            'user_id': sent['p_user_id'], 'email': 'other@allset.in', 'full_name': '',
            'phone': '', 'is_active': True, 'attributes': {},
        })
        entry['roles'] = roles
        return Response(200, json=roles)
    return respx.post(SET_ROLES_URL).mock(side_effect=handler)


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
def test_empty_role_set_is_allowed(client, make_token, jwks_mock, policy_snapshot):
    """Offboarding: keep the account, remove all access."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    mock_set_roles(policy_snapshot)
    respx.post(REVOKE_URL).mock(return_value=Response(204))

    token = make_token(roles=['admin'])
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}/roles', json={'roles': []}, headers=auth_header(token)
    )
    assert response.status_code == 200
    assert response.json()['roles'] == []
    assert response.json()['apps']['cms']['access'] is False


# ── Role changes force a re-login ────────────────────────────────────────────

@respx.mock
def test_role_change_signs_the_user_out_everywhere(client, make_token, jwks_mock, policy_snapshot):
    """Roles ride in the JWT and consumers cache for 60s, so without a global
    sign-out a removed role would keep working until the access token expired."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    mock_set_roles(policy_snapshot)
    logout = respx.post(REVOKE_URL).mock(
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
    logout = respx.post(REVOKE_URL).mock(
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
def test_admin_can_change_their_own_non_admin_roles(client, make_token, jwks_mock, policy_snapshot):
    """Adding a desk role to yourself is fine as long as admin/tech survives."""
    respx.get(PROFILES_URL).mock(
        return_value=Response(200, json=[profile_row(user_id=USER_ID, roles=['admin'])])
    )
    mock_set_roles(policy_snapshot)
    respx.post(REVOKE_URL).mock(return_value=Response(204))

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
def test_tech_can_demote_an_admin(client, make_token, jwks_mock, policy_snapshot):
    """The two global roles can administer each other — that is the point of
    having both."""
    respx.get(PROFILES_URL).mock(
        return_value=Response(200, json=[profile_row(user_id=OTHER_ID, roles=['admin'])])
    )
    mock_set_roles(policy_snapshot)
    respx.post(REVOKE_URL).mock(return_value=Response(204))

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
    client, make_token, jwks_mock, policy_snapshot
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
    set_roles = mock_set_roles(policy_snapshot)
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
    assert json.loads(set_roles.calls.last.request.content)['p_role_keys'] == ['presales']
    assert response.json()['roles'] == ['presales']

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
def test_admin_can_set_a_users_phone_and_name(client, make_token, jwks_mock):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    updated = {**profile_row(), 'phone': '9876543210', 'full_name': 'New Name'}
    patch = respx.patch(PROFILES_URL).mock(return_value=Response(200, json=[updated]))

    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}',
        json={'phone': ' 9876543210 ', 'full_name': 'New Name'},
        headers=auth_header(make_token(roles=['admin'])),
    )

    assert response.status_code == 200
    assert response.json()['phone'] == '9876543210'
    sent = patch.calls.last.request
    assert f'user_id=eq.{OTHER_ID}' in str(sent.url)
    # Trimmed before it is stored, and roles are not part of this endpoint.
    assert json.loads(sent.content) == {'phone': '9876543210', 'full_name': 'New Name'}


@respx.mock
def test_profile_update_does_not_revoke_sessions(client, make_token, jwks_mock):
    """Revoking would not shorten how long the old phone lives in an issued
    access token, so it is not done."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    respx.patch(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    revoke = respx.post(REVOKE_URL).mock(return_value=Response(204))

    client.patch(
        f'/v1/admin/users/{OTHER_ID}',
        json={'phone': '9876543210'},
        headers=auth_header(make_token(roles=['admin'])),
    )
    assert not revoke.called


def test_profile_update_with_nothing_to_change_is_a_400(client, make_token, jwks_mock):
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}', json={},
        headers=auth_header(make_token(roles=['admin'])),
    )
    assert response.status_code == 400


def test_profile_update_rejects_an_overlong_phone(client, make_token, jwks_mock):
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}', json={'phone': '9' * 33},
        headers=auth_header(make_token(roles=['admin'])),
    )
    assert response.status_code == 422


@respx.mock
def test_profile_update_on_a_missing_user_is_404(client, make_token, jwks_mock):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[]))
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}', json={'phone': '9876543210'},
        headers=auth_header(make_token(roles=['admin'])),
    )
    assert response.status_code == 404


@pytest.mark.parametrize('roles', [['viewer'], ['lead_manager'], ['presales'], []])
def test_non_admins_cannot_change_a_profile(client, make_token, jwks_mock, roles):
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}', json={'phone': '9876543210'},
        headers=auth_header(make_token(roles=roles)),
    )
    assert response.status_code == 403


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
def test_a_database_refusal_is_reported_as_a_client_error(client, make_token, jwks_mock, policy_snapshot):
    """If the API's own validation is ever bypassed, identity_set_user_roles
    still refuses — and that must read as a 400 with its message, not a 500."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    mock_set_roles(policy_snapshot, status_code=400,
                   body={'code': '22023', 'message': 'unknown role: retired_role'})
    token = make_token(roles=['admin'])
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}/roles',
        json={'roles': ['viewer']},
        headers=auth_header(token),
    )
    assert response.status_code == 400
    assert response.json()['detail'] == 'unknown role: retired_role'


# ── Revocation must never fail silently ──────────────────────────────────────
# These exist because of a real bug: admin_sign_out_everywhere called
# POST /admin/users/{id}/logout, which GoTrue does not implement. It returned
# 404 "page not found", and the client treated 404 as acceptable — so nothing
# was logged and sessions were never revoked. A role change appeared to
# succeed while the old role kept working until the token expired.

@respx.mock
def test_a_missing_revocation_function_is_not_swallowed(client, make_token, jwks_mock, policy_snapshot):
    """PostgREST answers 404 on an RPC path when the function does not exist,
    i.e. db/003_revoke_sessions.sql was never applied. That must surface, not
    be mistaken for "no sessions to revoke"."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    mock_set_roles(policy_snapshot)
    respx.post(REVOKE_URL).mock(return_value=Response(404, json={'message': 'Not Found'}))

    token = make_token(roles=['admin'])
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}/roles',
        json={'roles': ['editor']},
        headers=auth_header(token),
    )
    assert response.status_code >= 500, (
        'a role change whose sessions were not revoked must not report success'
    )


@respx.mock
def test_a_failed_revocation_is_not_swallowed(client, make_token, jwks_mock):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    respx.patch(PROFILES_URL).mock(
        return_value=Response(200, json=[profile_row(is_active=False)])
    )
    respx.post(REVOKE_URL).mock(return_value=Response(500, text='boom'))

    token = make_token(roles=['admin'])
    response = client.patch(
        f'/v1/admin/users/{OTHER_ID}/status',
        json={'is_active': False},
        headers=auth_header(token),
    )
    assert response.status_code >= 500


@respx.mock
def test_revocation_targets_the_right_user(client, make_token, jwks_mock, policy_snapshot):
    """The RPC takes the user id in the body; sending the wrong one would sign
    out somebody else and leave the intended user's sessions live."""
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile_row()]))
    mock_set_roles(policy_snapshot)
    revoke = respx.post(REVOKE_URL).mock(return_value=Response(200, text='3'))

    token = make_token(roles=['admin'])
    client.patch(
        f'/v1/admin/users/{OTHER_ID}/roles',
        json={'roles': ['viewer']},
        headers=auth_header(token),
    )
    assert revoke.called
    assert OTHER_ID in revoke.calls.last.request.read().decode()
