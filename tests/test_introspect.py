"""The hot path: POST /v1/introspect.

Every authenticated request in both apps passes through here, so these tests
cover the failure modes as carefully as the success one. The central contract:
an invalid token returns HTTP 200 with active=false (a routine 401 for the end
user), while a broken identity service returns a 5xx that consumers fail closed
on. Confusing those two would either lock everyone out or let anyone in.
"""

from __future__ import annotations

import time

import pytest

from tests.conftest import ISSUER, SERVICE_KEY


def introspect(client, token, headers):
    return client.post('/v1/introspect', json={'token': token}, headers=headers)


# ── Service key ──────────────────────────────────────────────────────────────

def test_missing_service_key_is_rejected(client):
    assert client.post('/v1/introspect', json={'token': 'x'}).status_code == 401


def test_wrong_service_key_is_rejected(client):
    response = client.post(
        '/v1/introspect', json={'token': 'x'}, headers={'X-Allset-Service-Key': 'wrong'}
    )
    assert response.status_code == 401


def test_unset_service_key_fails_closed(client, monkeypatch):
    """A misconfigured deploy must refuse traffic, not accept anonymous
    introspection."""
    from app.core import config

    monkeypatch.setattr(config, 'SERVICE_KEY', '')
    response = client.post(
        '/v1/introspect', json={'token': 'x'}, headers={'X-Allset-Service-Key': ''}
    )
    assert response.status_code == 401


def test_service_key_comparison_is_not_a_prefix_match(client):
    for candidate in (SERVICE_KEY[:-1], SERVICE_KEY + 'x', SERVICE_KEY.upper()):
        response = client.post(
            '/v1/introspect', json={'token': 'x'},
            headers={'X-Allset-Service-Key': candidate},
        )
        assert response.status_code == 401, candidate


# ── Valid tokens ─────────────────────────────────────────────────────────────

def test_valid_token_returns_roles_and_capabilities(
    client, service_headers, make_token, jwks_mock
):
    token = make_token(roles=['manager', 'sales'])
    body = introspect(client, token, service_headers).json()

    assert body['active'] is True
    assert body['roles'] == ['manager', 'sales']
    assert body['email'] == 'someone@allset.in'
    assert body['apps']['cms']['can_publish'] is True
    assert body['apps']['cms']['can_manage_users'] is False
    assert body['apps']['broker_tools']['own_sales'] is True
    assert body['apps']['broker_tools']['unrestricted_leads'] is False


def test_roles_come_from_the_token_not_a_database_read(
    client, service_headers, make_token, jwks_mock
):
    """The whole performance argument for the gateway. If this ever needed a
    lookup, introspection would cost a cross-region round trip per request."""
    token = make_token(roles=['admin'])
    introspect(client, token, service_headers)

    # Only the one JWKS fetch; no REST or auth calls to Supabase.
    called = [str(call.request.url) for call in jwks_mock.calls]
    assert all('.well-known/jwks.json' in url for url in called), called


def test_jwks_is_fetched_once_across_many_tokens(
    client, service_headers, make_token, jwks_mock
):
    for _ in range(5):
        introspect(client, make_token(roles=['viewer']), service_headers)
    assert len(jwks_mock.calls) == 1


def test_hs256_token_is_accepted_for_legacy_projects(client, service_headers, make_token):
    """Projects still on the symmetric signing key must keep working."""
    token = make_token(roles=['editor'], algorithm='HS256')
    body = introspect(client, token, service_headers).json()
    assert body['active'] is True
    assert body['roles'] == ['editor']


# ── Invalid tokens: active=false, never an error status ──────────────────────

@pytest.mark.parametrize('bad', ['', 'not-a-jwt', 'a.b.c', 'Bearer x'])
def test_malformed_tokens_are_inactive_not_errors(client, service_headers, bad):
    response = client.post('/v1/introspect', json={'token': bad or 'x'}, headers=service_headers)
    assert response.status_code == 200
    assert response.json()['active'] is False


def test_expired_token_is_inactive(client, service_headers, make_token, jwks_mock):
    token = make_token(roles=['admin'], expires_in=-60)
    body = introspect(client, token, service_headers).json()
    assert body['active'] is False
    assert body['apps']['cms']['access'] is False


def test_token_signed_by_a_different_key_is_inactive(
    client, service_headers, make_token, jwks_mock
):
    """A token minted by another project must not authenticate here."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = attacker.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    token = make_token(roles=['admin'], key=pem)
    assert introspect(client, token, service_headers).json()['active'] is False


def test_wrong_issuer_is_inactive(client, service_headers, make_token, jwks_mock):
    token = make_token(roles=['admin'], issuer='https://evil.example.com/auth/v1')
    assert introspect(client, token, service_headers).json()['active'] is False


def test_wrong_audience_is_inactive(client, service_headers, make_token, jwks_mock):
    token = make_token(roles=['admin'], audience='anon')
    assert introspect(client, token, service_headers).json()['active'] is False


def test_unsigned_token_is_rejected(client, service_headers):
    """alg=none must never be honoured."""
    import base64
    import json

    def part(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b'=').decode()

    forged = '.'.join([
        part({'alg': 'none', 'typ': 'JWT'}),
        part({
            'sub': '11111111-2222-3333-4444-555555555555',
            'iss': ISSUER, 'aud': 'authenticated',
            'exp': int(time.time()) + 600,
            'app_metadata': {'roles': ['admin'], 'is_active': True},
        }),
        '',
    ])
    assert introspect(client, forged, service_headers).json()['active'] is False


# ── Deactivation and half-provisioned accounts ──────────────────────────────

def test_deactivated_user_gets_no_access_even_as_admin(
    client, service_headers, make_token, jwks_mock
):
    token = make_token(roles=['admin'], is_active=False)
    body = introspect(client, token, service_headers).json()
    assert body['active'] is False
    assert body['apps']['cms']['access'] is False
    assert body['apps']['broker_tools']['access'] is False


def test_token_without_app_metadata_resolves_to_no_access(
    client, service_headers, make_token, jwks_mock
):
    """A token minted before the Custom Access Token Hook was registered, or for
    an auth.users row with no profile. Must fail closed rather than default to
    something permissive."""
    token = make_token(include_app_metadata=False)
    body = introspect(client, token, service_headers).json()
    assert body['active'] is False
    assert body['roles'] == []
    assert body['apps']['cms']['access'] is False


def test_empty_role_set_is_active_but_has_no_app_access(
    client, service_headers, make_token, jwks_mock
):
    """The offboarding state: the account still authenticates, but reaches
    nothing."""
    token = make_token(roles=[], is_active=True)
    body = introspect(client, token, service_headers).json()
    assert body['active'] is True
    assert body['roles'] == []
    assert body['apps']['cms']['access'] is False
    assert body['apps']['broker_tools']['access'] is False


def test_unknown_roles_in_a_token_are_ignored(
    client, service_headers, make_token, jwks_mock
):
    """A retired role from either old vocabulary must not grant anything."""
    token = make_token(roles=['agent', 'broker', 'superuser'])
    body = introspect(client, token, service_headers).json()
    assert body['apps']['cms']['access'] is False
    assert body['apps']['broker_tools']['access'] is False


def test_introspect_and_me_agree_for_the_same_token(
    client, service_headers, make_token, jwks_mock
):
    """The contract that keeps a frontend's UI gating from drifting away from a
    backend's authorisation."""
    token = make_token(roles=['manager', 'presales'])

    introspected = introspect(client, token, service_headers).json()
    me = client.get('/v1/auth/me', headers={'Authorization': f'Bearer {token}'}).json()

    assert introspected['apps'] == me['apps']
    assert introspected['roles'] == me['roles']
    assert introspected['user_id'] == me['user_id']
