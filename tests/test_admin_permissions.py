"""/v1/admin: console access, roles, services, the matrix, keys, attributes, audit.

Writes are SQL functions (db/004), mocked here at the RPC boundary; what they do
inside the database is proven in tests/db/. These tests pin what the API sends
them, what it refuses before calling them, and how it reports their refusals.
"""

from __future__ import annotations

import hashlib
import json

import pytest
import respx
from httpx import Response

from tests.conftest import SUPABASE_URL

RPC = f'{SUPABASE_URL}/rest/v1/rpc'
PROFILES_URL = f'{SUPABASE_URL}/rest/v1/user_profiles'
KEYS_URL = f'{SUPABASE_URL}/rest/v1/identity_service_keys'
AUDIT_URL = f'{SUPABASE_URL}/rest/v1/identity_audit_log'
REVOKE_URL = f'{RPC}/identity_revoke_user_sessions'

ME = '11111111-2222-3333-4444-555555555555'
OTHER = '99999999-8888-7777-6666-555555555555'


def auth(token):
    return {'Authorization': f'Bearer {token}'}


def profile(user_id=OTHER, roles=('viewer',), is_active=True):
    return {'user_id': user_id, 'email': 'other@allset.in', 'full_name': 'Other', 'phone': '',
            'roles': list(roles), 'is_active': is_active, 'legacy_migrated_at': None,
            'created_at': '2026-01-01T00:00:00Z'}


def sent(route):
    return json.loads(route.calls.last.request.content)


# ── Who reaches the console ──────────────────────────────────────────────────

@pytest.mark.parametrize('roles, status', [
    (['admin'], 200), (['tech'], 200),
    (['lead_manager'], 403), (['manager'], 403), (['viewer'], 403), ([], 403),
])
def test_console_access_is_the_identity_console_permission(client, make_token, jwks_mock, roles, status):
    assert client.get('/v1/admin/roles', headers=auth(make_token(roles=roles))).status_code == status


def test_console_access_follows_the_roster_not_the_token(client, make_token, jwks_mock, policy_snapshot):
    token = make_token(roles=['tech'])
    policy_snapshot.users[ME] = {'user_id': ME, 'email': 'me@allset.in', 'is_active': True,
                                 'roles': ['viewer'], 'attributes': {}}
    assert client.get('/v1/admin/roles', headers=auth(token)).status_code == 403


# ── Users ────────────────────────────────────────────────────────────────────

@respx.mock
def test_user_detail_has_effective_access(client, make_token, jwks_mock, policy_snapshot):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile(roles=['presales'])]))
    policy_snapshot.users[OTHER] = {'user_id': OTHER, 'is_active': True, 'roles': ['presales'],
                                    'attributes': {'broker_tools': {'desk': 'presales'}}}
    body = client.get(f'/v1/admin/users/{OTHER}', headers=auth(make_token(roles=['admin']))).json()
    assert body['roles'] == ['presales']
    assert body['attributes'] == {'broker_tools': {'desk': 'presales'}}
    assert body['apps']['broker_tools']['permissions']['lead']['read'] == ['own_presales']


@respx.mock
def test_users_can_be_filtered(client, make_token, jwks_mock):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[
        profile(user_id='a', roles=['presales']), profile(user_id='b', roles=['viewer'], is_active=False),
    ]))
    token = make_token(roles=['admin'])
    by_role = client.get('/v1/admin/users?role=presales', headers=auth(token)).json()['users']
    by_service = client.get('/v1/admin/users?service=cms', headers=auth(token)).json()['users']
    inactive = client.get('/v1/admin/users?active=false', headers=auth(token)).json()['users']
    assert [u['user_id'] for u in by_role] == ['a']
    assert [u['user_id'] for u in by_service] == []   # b has cms via viewer but is inactive
    assert [u['user_id'] for u in inactive] == ['b']


@respx.mock
def test_you_cannot_remove_your_own_console_access(client, make_token, jwks_mock):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile(user_id=ME, roles=['tech'])]))
    response = client.patch(f'/v1/admin/users/{ME}/roles', json={'roles': ['viewer']},
                            headers=auth(make_token(roles=['tech'], user_id=ME)))
    assert response.status_code == 400
    assert 'console access' in response.json()['detail']


@respx.mock
def test_the_last_active_admin_cannot_be_deactivated(client, make_token, jwks_mock, policy_snapshot):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile(roles=['admin'])]))
    policy_snapshot.users[OTHER] = {'user_id': OTHER, 'is_active': True, 'roles': ['admin'], 'attributes': {}}
    response = client.patch(f'/v1/admin/users/{OTHER}/status', json={'is_active': False},
                            headers=auth(make_token(roles=['tech'])))
    assert response.status_code == 400
    assert 'last active admin' in response.json()['detail']


@respx.mock
def test_attributes_are_set_through_the_sql_function(client, make_token, jwks_mock):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile()]))
    route = respx.post(f'{RPC}/identity_set_user_attributes').mock(
        return_value=Response(200, json={'desk': 'sales'}))
    response = client.put(f'/v1/admin/users/{OTHER}/attributes/broker_tools',
                          json={'attributes': {'desk': 'sales'}}, headers=auth(make_token(roles=['admin'])))
    assert response.status_code == 200
    assert sent(route) == {'p_user_id': OTHER, 'p_service': 'broker_tools',
                           'p_values': {'desk': 'sales'}, 'p_actor': ME}


@respx.mock
def test_a_refused_attribute_value_reads_as_400(client, make_token, jwks_mock):
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[profile()]))
    respx.post(f'{RPC}/identity_set_user_attributes').mock(
        return_value=Response(400, json={'code': '22023', 'message': 'value not allowed: desk=manager'}))
    response = client.put(f'/v1/admin/users/{OTHER}/attributes/broker_tools',
                          json={'attributes': {'desk': 'manager'}}, headers=auth(make_token(roles=['admin'])))
    assert (response.status_code, response.json()['detail']) == (400, 'value not allowed: desk=manager')


# ── Roles ────────────────────────────────────────────────────────────────────

def test_roles_list_has_members_and_groups(client, make_token, jwks_mock, policy_snapshot):
    policy_snapshot.users[OTHER] = {'user_id': OTHER, 'is_active': True, 'roles': ['sales'], 'attributes': {}}
    body = client.get('/v1/admin/roles', headers=auth(make_token(roles=['admin']))).json()
    by_key = {r['key']: r for r in body['roles']}
    assert by_key['sales']['members'] == 1
    assert by_key['admin']['is_superuser'] is True
    assert set(by_key['sales']['apps']) == {'broker_tools', 'wa_automation', 'consultation_agent'}
    assert body['exclusive_groups'] == [['presales', 'sales']]


@respx.mock
def test_creating_a_role(client, make_token, jwks_mock, policy_snapshot):
    from app.permissions.snapshot import Role

    def upsert(request):
        body = json.loads(request.content)
        policy_snapshot.roles[body['p_key']] = Role(body['p_key'], body['p_label'], body['p_description'],
                                                    body['p_priority'], False, body['p_exclusive_group'])
        return Response(200, json={})

    route = respx.post(f'{RPC}/identity_upsert_role').mock(side_effect=upsert)
    response = client.post('/v1/admin/roles', headers=auth(make_token(roles=['admin'])),
                           json={'key': 'auditor', 'label': 'Auditor', 'priority': 90})
    assert response.status_code == 201
    assert response.json()['key'] == 'auditor' and response.json()['members'] == 0
    assert sent(route)['p_actor'] == ME


def test_an_existing_role_key_is_a_409(client, make_token, jwks_mock):
    assert client.post('/v1/admin/roles', headers=auth(make_token(roles=['admin'])),
                       json={'key': 'sales', 'label': 'Sales'}).status_code == 409


@pytest.mark.parametrize('key', ['Sales', 'a', '1role', 'has-dash'])
def test_role_keys_must_be_lowercase_tokens(client, make_token, jwks_mock, key):
    assert client.post('/v1/admin/roles', headers=auth(make_token(roles=['admin'])),
                       json={'key': key, 'label': 'X'}).status_code == 422


@respx.mock
def test_updating_a_role_keeps_unsent_fields(client, make_token, jwks_mock):
    route = respx.post(f'{RPC}/identity_upsert_role').mock(return_value=Response(200, json={}))
    client.patch('/v1/admin/roles/sales', headers=auth(make_token(roles=['admin'])),
                 json={'label': 'Sales desk'})
    assert sent(route) == {'p_key': 'sales', 'p_label': 'Sales desk',
                           'p_description': 'Own sales leads in Broker Tools',
                           'p_priority': 80, 'p_exclusive_group': 'desk', 'p_actor': ME}


@respx.mock
def test_deleting_a_role_in_use_reads_as_400(client, make_token, jwks_mock):
    respx.post(f'{RPC}/identity_delete_role').mock(
        return_value=Response(400, json={'code': '22023', 'message': 'role viewer is held by 3 user(s)'}))
    response = client.delete('/v1/admin/roles/viewer', headers=auth(make_token(roles=['admin'])))
    assert response.status_code == 400


# ── The matrix ───────────────────────────────────────────────────────────────

def test_the_matrix_is_returned_with_its_version(client, make_token, jwks_mock):
    response = client.get('/v1/admin/services/broker_tools/grants', headers=auth(make_token(roles=['admin'])))
    body = response.json()
    assert response.headers['ETag'] == '"0"'
    assert body['editable'] is True
    assert body['grants']['presales']['lead']['read'] == ['own_presales']
    assert 'admin' not in body['grants']   # a superuser needs none


def test_the_identity_matrix_is_not_editable(client, make_token, jwks_mock):
    body = client.get('/v1/admin/services/identity/grants', headers=auth(make_token(roles=['admin']))).json()
    assert body['editable'] is False


def test_saving_the_matrix_needs_if_match(client, make_token, jwks_mock):
    response = client.put('/v1/admin/services/cms/grants', headers=auth(make_token(roles=['admin'])),
                          json={'grants': {}})
    assert response.status_code == 428


@respx.mock
def test_saving_the_matrix_sends_the_expected_version(client, make_token, jwks_mock):
    route = respx.post(f'{RPC}/identity_set_service_grants').mock(return_value=Response(200, json=4))
    grants = {'viewer': {'property': {'read': ['all']}}}
    response = client.put('/v1/admin/services/cms/grants', json={'grants': grants},
                          headers={**auth(make_token(roles=['admin'])), 'If-Match': '"3"'})
    assert response.status_code == 200
    assert response.headers['ETag'] == '"4"'
    assert sent(route) == {'p_service': 'cms', 'p_grants': grants, 'p_expected_version': 3,
                           'p_actor': ME, 'p_allow_system': False}


@respx.mock
def test_a_stale_matrix_save_is_a_409(client, make_token, jwks_mock):
    respx.post(f'{RPC}/identity_set_service_grants').mock(return_value=Response(400, json={
        'code': 'PT409', 'message': 'these permissions were changed by someone else; reload and try again'}))
    response = client.put('/v1/admin/services/cms/grants', json={'grants': {}},
                          headers={**auth(make_token(roles=['admin'])), 'If-Match': '"1"'})
    assert response.status_code == 409


# ── Services and keys ────────────────────────────────────────────────────────

def test_services_are_listed_with_counts(client, make_token, jwks_mock):
    listed = client.get('/v1/admin/services', headers=auth(make_token(roles=['admin']))).json()['services']
    services = {s['key']: s for s in listed}
    assert services['identity']['is_system'] is True
    assert services['cms']['resources'] == 4


@respx.mock
def test_a_key_is_shown_once_and_only_its_hash_is_stored(client, make_token, jwks_mock):
    route = respx.post(f'{RPC}/identity_create_service_key').mock(
        return_value=Response(200, json='5f0c6f0e-0000-0000-0000-000000000001'))
    body = client.post('/v1/admin/services/cms/keys', json={'label': 'prod'},
                       headers=auth(make_token(roles=['admin']))).json()
    stored = sent(route)
    assert len(body['key']) >= 40
    assert stored['p_key_hash'] == hashlib.sha256(body['key'].encode()).hexdigest()
    assert stored['p_key_prefix'] == body['key'][:6] == body['prefix']
    assert body['key'] not in json.dumps(stored)


@respx.mock
def test_service_detail_lists_keys_without_secrets(client, make_token, jwks_mock):
    respx.get(KEYS_URL).mock(return_value=Response(200, json=[
        {'id': 'k1', 'key_prefix': 'abcdef', 'label': 'prod', 'created_at': '2026-10-12', 'created_by': ME,
         'revoked_at': None, 'identity_services': {'key': 'cms'}},
    ]))
    body = client.get('/v1/admin/services/cms', headers=auth(make_token(roles=['admin']))).json()
    assert [r['key'] for r in body['resources']][:2] == ['app', 'property']
    assert body['keys'][0]['key_prefix'] == 'abcdef'


def test_an_unknown_service_is_a_404(client, make_token, jwks_mock):
    response = client.get('/v1/admin/services/nope/grants', headers=auth(make_token(roles=['admin'])))
    assert response.status_code == 404


# ── Audit ────────────────────────────────────────────────────────────────────

@respx.mock
def test_audit_filters_reach_the_query(client, make_token, jwks_mock):
    route = respx.get(AUDIT_URL).mock(return_value=Response(200, json=[{'id': 9, 'action': 'user.roles'}]))
    body = client.get('/v1/admin/audit?target_type=user&target_key=abc&before_id=10&limit=20',
                      headers=auth(make_token(roles=['admin']))).json()
    params = route.calls.last.request.url.params
    assert body['entries'] == [{'id': 9, 'action': 'user.roles'}]
    assert (params['target_type'], params['target_key'], params['id'], params['limit']) == \
           ('eq.user', 'eq.abc', 'lt.10', '20')
