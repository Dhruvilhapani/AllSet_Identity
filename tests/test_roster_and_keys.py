"""The roster beats the token, console-issued keys, and failing closed.

Introspect reads roles, status, name and phone from the roster in the policy
snapshot, so a change reaches consumers within a minute instead of when the
7-day token expires. The token's own claims are only for a user created after
the snapshot loaded.
"""

from __future__ import annotations

import hashlib
import time

import pytest
import respx
from httpx import Response

from tests.conftest import SERVICE_KEY, SUPABASE_URL

USER_ID = '11111111-2222-3333-4444-555555555555'


def introspect(client, token, key=SERVICE_KEY):
    return client.post('/v1/introspect', json={'token': token}, headers={'X-Allset-Service-Key': key})


def roster_entry(**overrides):
    return {'user_id': USER_ID, 'email': 'someone@allset.in', 'full_name': 'Some One',
            'phone': '', 'is_active': True, 'roles': [], 'attributes': {}, **overrides}


# ── Roster ───────────────────────────────────────────────────────────────────

def test_a_role_removed_in_the_roster_stops_working_before_the_token_expires(
    client, make_token, jwks_mock, policy_snapshot
):
    token = make_token(roles=['lead_manager'])
    policy_snapshot.users[USER_ID] = roster_entry(roles=['viewer'])

    body = introspect(client, token).json()
    assert body['roles'] == ['viewer']
    assert body['apps']['broker_tools']['access'] is False
    assert body['apps']['cms']['access'] is True


def test_deactivation_in_the_roster_beats_an_active_token(client, make_token, jwks_mock, policy_snapshot):
    token = make_token(roles=['admin'])
    policy_snapshot.users[USER_ID] = roster_entry(roles=['admin'], is_active=False)

    body = introspect(client, token).json()
    assert body['active'] is False
    assert all(not app['access'] for app in body['apps'].values())


def test_name_phone_and_attributes_come_from_the_roster(client, make_token, jwks_mock, policy_snapshot):
    token = make_token(roles=['presales'], phone='0000000000', full_name='Old Name')
    policy_snapshot.users[USER_ID] = roster_entry(
        roles=['presales'], full_name='New Name', phone='+91 98765 43210',
        attributes={'broker_tools': {'desk': 'presales'}},
    )

    body = introspect(client, token).json()
    assert (body['full_name'], body['phone']) == ('New Name', '+91 98765 43210')
    assert body['apps']['broker_tools']['attributes'] == {'desk': 'presales'}
    assert body['apps']['cms']['attributes'] == {}


def test_a_user_missing_from_a_newer_snapshot_has_been_deleted(
    client, make_token, jwks_mock, policy_snapshot
):
    token = make_token(roles=['admin'])
    policy_snapshot.loaded_at = time.time() + 3600   # loaded long after the token was issued
    assert introspect(client, token).json()['active'] is False


def test_a_user_missing_from_an_older_snapshot_falls_back_to_the_token(
    client, make_token, jwks_mock, policy_snapshot
):
    """Created after the last refresh: their freshly minted token is the only
    record this instance has."""
    token = make_token(roles=['presales'])
    policy_snapshot.loaded_at = time.time() - 3600
    body = introspect(client, token).json()
    assert body['active'] is True
    assert body['apps']['broker_tools']['own_presales'] is True


def test_the_payload_carries_permissions_for_every_service(client, make_token, jwks_mock):
    body = introspect(client, make_token(roles=['presales'])).json()
    bt = body['apps']['broker_tools']
    assert bt['permissions']['lead']['read'] == ['own_presales']
    assert bt['permissions']['lead']['create'] == ['all']
    assert 'distribution_settings' not in bt['permissions']
    wa = body['apps']['wa_automation']
    assert wa['access'] is True
    assert wa['permissions']['lead']['read'] == ['assigned_presales', 'own_test_identity']
    assert 'app' not in bt['permissions']   # access says that


def test_admin_holds_everything_as_superuser(client, make_token, jwks_mock):
    bt = introspect(client, make_token(roles=['admin'])).json()['apps']['broker_tools']
    assert bt['permissions']['distribution_settings'] == {'read': ['all'], 'update': ['all']}
    assert bt['permissions']['lead']['read'] == ['all']


def test_tech_is_kept_out_of_distribution_settings(client, make_token, jwks_mock):
    """Broker Tools made lead distribution admin-only on 29 Sep 2026."""
    bt = introspect(client, make_token(roles=['tech'])).json()['apps']['broker_tools']
    assert bt['unrestricted_leads'] is True
    assert 'distribution_settings' not in bt['permissions']


# ── Failing closed ───────────────────────────────────────────────────────────

def test_no_snapshot_at_all_is_a_503_never_an_answer(client, make_token, jwks_mock, monkeypatch):
    from app.permissions import cache

    def unavailable():
        raise cache.PolicyUnavailable('down')

    cache.install(None)
    monkeypatch.setattr(cache, '_fetch', unavailable)
    assert introspect(client, make_token(roles=['admin'])).status_code == 503
    # An invalid token too: without the policy the service cannot answer at all.
    assert introspect(client, 'not-a-token').status_code == 503


# ── Console-issued service keys ──────────────────────────────────────────────

def _with_db_key(snapshot, service='reports', key='console-issued-key'):
    snapshot.service_key_hashes[hashlib.sha256(key.encode()).hexdigest()] = service
    return key


def test_a_console_issued_key_authenticates(client, make_token, jwks_mock, policy_snapshot):
    key = _with_db_key(policy_snapshot)
    assert introspect(client, make_token(roles=['viewer']), key=key).status_code == 200
    health = client.get('/v1/introspect/health', headers={'X-Allset-Service-Key': key}).json()
    assert health['service'] == 'reports' and health['policy_loaded'] is True


def test_an_unknown_key_is_refused(client, make_token, jwks_mock):
    assert introspect(client, make_token(roles=['viewer']), key='never-issued').status_code == 401


def test_the_shared_key_is_reported_as_no_particular_service(client):
    health = client.get('/v1/introspect/health', headers={'X-Allset-Service-Key': SERVICE_KEY}).json()
    assert health['service'] is None


# ── Manifest pushes ──────────────────────────────────────────────────────────

MANIFEST_RPC = f'{SUPABASE_URL}/rest/v1/rpc/identity_apply_manifest'


@respx.mock
def test_a_service_pushes_its_manifest_with_its_own_key(client, policy_snapshot):
    key = _with_db_key(policy_snapshot, service='reports')
    rpc = respx.post(MANIFEST_RPC).mock(return_value=Response(200, json={
        'key': 'reports', 'resources': [
            {'key': 'app', 'retired': False}, {'key': 'dashboard', 'retired': False},
            {'key': 'old', 'retired': True},
        ],
    }))
    response = client.put('/v1/services/manifest', headers={'X-Allset-Service-Key': key}, json={
        'service': 'reports', 'resources': {'dashboard': {'actions': ['read']}},
    })
    assert response.status_code == 200
    assert response.json() == {'service': 'reports', 'resources': ['app', 'dashboard'], 'retired': ['old']}
    sent = rpc.calls.last.request.read().decode()
    assert '"p_service":"reports"' in sent.replace(' ', '') and '"p_actor":null' in sent.replace(' ', '')


def test_the_shared_key_cannot_push_a_manifest(client):
    response = client.put('/v1/services/manifest', headers={'X-Allset-Service-Key': SERVICE_KEY},
                          json={'service': 'cms', 'resources': {}})
    assert response.status_code == 403


def test_a_key_cannot_push_another_services_manifest(client, policy_snapshot):
    key = _with_db_key(policy_snapshot, service='reports')
    response = client.put('/v1/services/manifest', headers={'X-Allset-Service-Key': key},
                          json={'service': 'cms', 'resources': {}})
    assert response.status_code == 403


@pytest.mark.parametrize('manifest', [
    {'service': 'reports', 'resources': {'app': {'actions': ['use']}}},
    {'service': 'reports', 'resources': {'x': {'actions': []}}},
    {'service': 'reports', 'resources': {'x': {'actions': ['read'], 'scopes': {'all': 'All'}}}},
    {'service': 'reports', 'attributes': {'desk': {'kind': 'text'}}},
])
def test_invalid_manifests_are_refused_before_the_database(client, policy_snapshot, manifest):
    key = _with_db_key(policy_snapshot, service='reports')
    assert client.put('/v1/services/manifest', headers={'X-Allset-Service-Key': key},
                      json=manifest).status_code == 400
