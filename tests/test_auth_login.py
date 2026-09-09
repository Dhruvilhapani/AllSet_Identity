"""Login, refresh and the shadow migration of CMS passwords.

Supabase is mocked at the HTTP boundary with respx, so these exercise the real
request shapes and the real error classification. That classification is the
delicate part: a genuine bad password must fall through to the legacy Django
hash check, while a Supabase outage must not.
"""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from app import legacy
from tests.conftest import SUPABASE_URL

TOKEN_URL = f'{SUPABASE_URL}/auth/v1/token'
ADMIN_USERS_URL = f'{SUPABASE_URL}/auth/v1/admin/users'
RECOVER_URL = f'{SUPABASE_URL}/auth/v1/recover'
PROFILES_URL = f'{SUPABASE_URL}/rest/v1/user_profiles'

USER_ID = '11111111-2222-3333-4444-555555555555'


def session_body(token, email='someone@allset.in'):
    """A GoTrue token response, shaped the way GoTrue actually shapes it.

    The critical detail, and the reason a bug shipped past an earlier version of
    this helper: `user.app_metadata` in the response BODY carries only
    {provider, providers}. The Custom Access Token Hook writes roles into the
    JWT it mints, never into auth.users.raw_app_meta_data. A fixture that put
    roles in app_metadata modelled Supabase incorrectly and let
    _session_response read them from a place that is always empty in
    production, so every Broker Tools login failed with "no access".

    `token` must therefore be a real signed JWT — use the make_token fixture.
    Tests using this need jwks_mock too, since the token is now verified.
    """
    return {
        'access_token': token,
        'refresh_token': 'refresh-token-value',
        'expires_in': 1800,
        'user': {
            'id': USER_ID,
            'email': email,
            'app_metadata': {'provider': 'email', 'providers': ['email']},
            'user_metadata': {'full_name': 'Some One'},
        },
    }


@pytest.fixture(autouse=True)
def reset_login_rate_limit():
    """The limiter is process-global; without this, later tests inherit earlier
    tests' attempt counts and start seeing 429s."""
    from app.api.v1 import auth as auth_module

    auth_module._attempts.clear()
    yield
    auth_module._attempts.clear()


# ── Happy path ───────────────────────────────────────────────────────────────

@respx.mock
def test_successful_login_returns_tokens_and_capabilities(client, make_token, jwks_mock):
    respx.post(TOKEN_URL).mock(
        return_value=Response(200, json=session_body(make_token(roles=['manager', 'sales'])))
    )

    response = client.post(
        '/v1/auth/login', json={'email': 'someone@allset.in', 'password': 'correct-horse'}
    )
    assert response.status_code == 200

    body = response.json()
    assert body['refresh_token'] == 'refresh-token-value'
    assert body['token_type'] == 'bearer'
    # The user block matches /v1/introspect, so a client can render from it
    # without a second round trip.
    assert body['user']['roles'] == ['manager', 'sales']
    assert body['user']['apps']['cms']['can_publish'] is True
    assert body['user']['apps']['broker_tools']['own_sales'] is True


@respx.mock
def test_login_normalises_the_email(client, make_token, jwks_mock):
    route = respx.post(TOKEN_URL).mock(
        return_value=Response(200, json=session_body(make_token(roles=['viewer'])))
    )
    client.post('/v1/auth/login', json={'email': '  SomeOne@AllSet.in  ', 'password': 'pw'})
    assert route.calls.last.request.read().decode().count('someone@allset.in') == 1


@respx.mock
def test_login_with_no_roles_succeeds_but_grants_nothing(client, make_token, jwks_mock):
    """The offboarding state must not be an error — the person can still sign in
    and see an empty app list rather than a confusing failure."""
    respx.post(TOKEN_URL).mock(
        return_value=Response(200, json=session_body(make_token(roles=[])))
    )
    body = client.post(
        '/v1/auth/login', json={'email': 'someone@allset.in', 'password': 'pw'}
    ).json()
    assert body['user']['apps']['cms']['access'] is False
    assert body['user']['apps']['broker_tools']['access'] is False


# ── Failures ─────────────────────────────────────────────────────────────────

@respx.mock
def test_bad_password_is_a_generic_401(client):
    respx.post(TOKEN_URL).mock(
        return_value=Response(400, json={'error_code': 'invalid_credentials', 'msg': 'bad'})
    )
    response = client.post(
        '/v1/auth/login', json={'email': 'someone@allset.in', 'password': 'wrong'}
    )
    assert response.status_code == 401
    # One message for every failure mode, so the endpoint cannot be used to
    # discover which addresses have accounts.
    assert response.json()['detail'] == 'invalid email or password'


@respx.mock
def test_unknown_email_gives_the_same_message_as_a_bad_password(client):
    respx.post(TOKEN_URL).mock(
        return_value=Response(400, json={'error_code': 'user_not_found'})
    )
    response = client.post(
        '/v1/auth/login', json={'email': 'nobody@allset.in', 'password': 'pw'}
    )
    assert response.status_code == 401
    assert response.json()['detail'] == 'invalid email or password'


@respx.mock
def test_deactivated_account_is_refused_with_403(client, make_token, jwks_mock):
    respx.post(TOKEN_URL).mock(
        return_value=Response(200, json=session_body(
            make_token(roles=['admin'], is_active=False)))
    )
    response = client.post(
        '/v1/auth/login', json={'email': 'gone@allset.in', 'password': 'pw'}
    )
    assert response.status_code == 403


@respx.mock
def test_supabase_outage_is_a_502_not_a_401(client):
    """A 401 would tell the user their password is wrong and, worse, would send
    login down the legacy path. An outage must be reported as an outage."""
    respx.post(TOKEN_URL).mock(return_value=Response(503, json={'msg': 'unavailable'}))
    response = client.post(
        '/v1/auth/login', json={'email': 'someone@allset.in', 'password': 'pw'}
    )
    assert response.status_code == 502


@respx.mock
def test_rate_limit_kicks_in_after_the_configured_attempts(client):
    respx.post(TOKEN_URL).mock(
        return_value=Response(400, json={'error_code': 'invalid_credentials'})
    )
    from app.core import config

    payload = {'email': 'target@allset.in', 'password': 'guess'}
    for _ in range(config.LOGIN_RATE_LIMIT):
        assert client.post('/v1/auth/login', json=payload).status_code == 401

    assert client.post('/v1/auth/login', json=payload).status_code == 429


@respx.mock
def test_rate_limit_is_per_email(client):
    respx.post(TOKEN_URL).mock(
        return_value=Response(400, json={'error_code': 'invalid_credentials'})
    )
    from app.core import config

    for _ in range(config.LOGIN_RATE_LIMIT):
        client.post('/v1/auth/login', json={'email': 'a@allset.in', 'password': 'x'})

    # A different person behind the same NAT must not be locked out. The CMS's
    # previous throttle was IP-keyed and had exactly this problem.
    assert client.post(
        '/v1/auth/login', json={'email': 'b@allset.in', 'password': 'x'}
    ).status_code == 401


# ── Shadow migration ─────────────────────────────────────────────────────────

@pytest.fixture
def legacy_enabled(monkeypatch):
    from app.core import config

    monkeypatch.setattr(config, 'LEGACY_MIGRATION_ENABLED', True)


@respx.mock
def test_legacy_password_is_adopted_on_first_login(
    client, legacy_enabled, monkeypatch, make_token, jwks_mock
):
    """The point of the shadow migration: an existing CMS user signs in with
    their old Django password and never notices the move."""
    monkeypatch.setattr(
        legacy, 'verify_legacy_password',
        lambda email, password: legacy.LegacyUser(
            email=email, full_name='Old User', roles=['editor'], is_active=True
        ),
    )

    # First call fails (no Supabase password yet), second succeeds after adoption.
    token_route = respx.post(TOKEN_URL).mock(
        side_effect=[
            Response(400, json={'error_code': 'invalid_credentials'}),
            Response(200, json=session_body(make_token(roles=['editor']))),
        ]
    )
    respx.get(ADMIN_USERS_URL).mock(return_value=Response(200, json={'users': []}))
    respx.post(ADMIN_USERS_URL).mock(return_value=Response(200, json={'id': USER_ID}))
    respx.get(PROFILES_URL).mock(return_value=Response(200, json=[]))
    respx.post(PROFILES_URL).mock(
        return_value=Response(201, json=[{'user_id': USER_ID, 'email': 'old@allset.in',
                                          'roles': ['editor'], 'is_active': True}])
    )
    respx.patch(PROFILES_URL).mock(return_value=Response(204))

    response = client.post(
        '/v1/auth/login', json={'email': 'old@allset.in', 'password': 'django-era-password'}
    )
    assert response.status_code == 200
    assert response.json()['user']['roles'] == ['editor']
    # Re-authenticated after adoption so the token carries hook-written claims.
    assert len(token_route.calls) == 2


@respx.mock
def test_legacy_path_is_skipped_when_disabled(client):
    """With the flag off there must be no attempt to reach the CMS database."""
    respx.post(TOKEN_URL).mock(
        return_value=Response(400, json={'error_code': 'invalid_credentials'})
    )
    admin_lookup = respx.get(ADMIN_USERS_URL).mock(return_value=Response(200, json={'users': []}))

    assert client.post(
        '/v1/auth/login', json={'email': 'old@allset.in', 'password': 'pw'}
    ).status_code == 401
    assert not admin_lookup.called


@respx.mock
def test_wrong_legacy_password_does_not_create_an_account(client, legacy_enabled, monkeypatch):
    monkeypatch.setattr(legacy, 'verify_legacy_password', lambda email, password: None)

    respx.post(TOKEN_URL).mock(
        return_value=Response(400, json={'error_code': 'invalid_credentials'})
    )
    create = respx.post(ADMIN_USERS_URL).mock(return_value=Response(200, json={'id': USER_ID}))

    assert client.post(
        '/v1/auth/login', json={'email': 'old@allset.in', 'password': 'wrong'}
    ).status_code == 401
    assert not create.called


@respx.mock
def test_already_provisioned_user_gets_password_set_not_recreated(
    client, legacy_enabled, monkeypatch, make_token, jwks_mock
):
    """Someone provisioned by an admin who then logs in with their legacy CMS
    password: adopt the password onto the existing account."""
    monkeypatch.setattr(
        legacy, 'verify_legacy_password',
        lambda email, password: legacy.LegacyUser(
            email=email, full_name='Old User', roles=['viewer'], is_active=True
        ),
    )

    respx.post(TOKEN_URL).mock(
        side_effect=[
            Response(400, json={'error_code': 'invalid_credentials'}),
            Response(200, json=session_body(make_token(roles=['viewer']))),
        ]
    )
    respx.get(ADMIN_USERS_URL).mock(
        return_value=Response(200, json={'users': [{'id': USER_ID, 'email': 'old@allset.in'}]})
    )
    create = respx.post(ADMIN_USERS_URL).mock(return_value=Response(200, json={'id': USER_ID}))
    set_password = respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )
    respx.get(PROFILES_URL).mock(
        return_value=Response(200, json=[{'user_id': USER_ID, 'email': 'old@allset.in',
                                          'roles': ['viewer'], 'is_active': True}])
    )
    respx.patch(PROFILES_URL).mock(return_value=Response(204))

    assert client.post(
        '/v1/auth/login', json={'email': 'old@allset.in', 'password': 'django-era'}
    ).status_code == 200
    assert set_password.called
    assert not create.called


# ── Legacy role mapping ──────────────────────────────────────────────────────

@pytest.mark.parametrize('legacy_role, expected', [
    ('admin', ['admin']),
    ('editor', ['editor']),
    ('viewer', ['viewer']),
    # 'agent' and 'viewer' were permission-identical in the CMS, so collapsing
    # them loses nothing.
    ('agent', ['viewer']),
    # Anything unrecognised lands on the least privileged role, never a
    # permissive default.
    ('', ['viewer']),
    ('something-else', ['viewer']),
])
def test_legacy_roles_map_to_the_unified_vocabulary(legacy_role, expected):
    assert legacy._LEGACY_ROLE_MAP.get(legacy_role.strip().lower(), ['viewer']) == expected


def test_non_admin_legacy_users_gain_no_broker_tools_access():
    """A migrated CMS editor/viewer must not silently acquire lead access; that
    is granted deliberately by an admin afterwards."""
    from app.capabilities import build_capabilities

    for legacy_role, roles in legacy._LEGACY_ROLE_MAP.items():
        if legacy_role in ('admin', 'tech'):
            continue
        assert build_capabilities(roles)['broker_tools']['access'] is False, legacy_role


def test_legacy_cms_admin_becomes_a_global_admin():
    """Documents a real consequence of the unified vocabulary rather than
    asserting it is desirable.

    A legacy CMS admin maps to the unified `admin`, which is all-access in BOTH
    apps — so on first login they gain visibility of every lead, data they
    previously could not reach. There is no CMS-only administrator role to map
    them to instead: `admin` and `tech` are both global by design, and `manager`
    lacks user management. Narrowing this would leave the CMS with no
    administrator, so it is accepted deliberately.
    """
    from app.capabilities import build_capabilities

    caps = build_capabilities(legacy._LEGACY_ROLE_MAP['admin'])
    assert caps['cms']['can_manage_users'] is True
    assert caps['broker_tools']['unrestricted_leads'] is True


# ── Refresh and logout ───────────────────────────────────────────────────────

@respx.mock
def test_refresh_returns_a_new_pair(client, make_token, jwks_mock):
    respx.post(TOKEN_URL).mock(
        return_value=Response(200, json=session_body(make_token(roles=['admin'])))
    )
    response = client.post('/v1/auth/refresh', json={'refresh_token': 'old-refresh'})
    assert response.status_code == 200
    body = response.json()
    assert body['access_token']
    # Refresh goes through the same _session_response, so the roles must come
    # off the new token rather than the response body's app_metadata.
    assert body['user']['roles'] == ['admin']
    assert body['user']['apps']['broker_tools']['unrestricted_leads'] is True


@respx.mock
def test_refresh_refuses_a_deactivated_account(client, make_token, jwks_mock):
    """Deactivated mid-session: the session must not be extendable."""
    respx.post(TOKEN_URL).mock(
        return_value=Response(200, json=session_body(make_token(roles=['admin'], is_active=False)))
    )
    assert client.post(
        '/v1/auth/refresh', json={'refresh_token': 'old-refresh'}
    ).status_code == 403


@respx.mock
def test_expired_refresh_token_is_401(client):
    respx.post(TOKEN_URL).mock(return_value=Response(401, json={'error_code': 'invalid_grant'}))
    assert client.post(
        '/v1/auth/refresh', json={'refresh_token': 'stale'}
    ).status_code == 401


@respx.mock
def test_revoked_refresh_token_is_401_not_400(client):
    """GoTrue answers a revoked or expired refresh token with HTTP 400 and the
    generic error_code "validation_failed". This must still surface as 401:
    both frontends clear the session and redirect to login on 401 and do
    neither on 400, so a 400 leaves the user on a dead session."""
    respx.post(TOKEN_URL).mock(return_value=Response(400, json={
        'code': 400, 'error_code': 'validation_failed',
        'msg': 'Refresh token is not valid',
    }))
    response = client.post('/v1/auth/refresh', json={'refresh_token': 'revoked'})
    assert response.status_code == 401, (
        'a revoked refresh token must read as 401 so clients re-authenticate'
    )


@respx.mock
def test_a_refresh_server_error_is_not_mistaken_for_a_bad_token(client):
    """A 5xx is an outage, not a verdict on the token — it must not send the
    user to a login screen that also cannot work."""
    respx.post(TOKEN_URL).mock(return_value=Response(503, json={'msg': 'unavailable'}))
    assert client.post(
        '/v1/auth/refresh', json={'refresh_token': 'fine'}
    ).status_code == 502


@respx.mock
def test_password_reset_request_never_reveals_whether_the_account_exists(client):
    respx.post(RECOVER_URL).mock(return_value=Response(404, json={'msg': 'not found'}))
    response = client.post('/v1/auth/password/reset-request', json={'email': 'nobody@allset.in'})
    assert response.status_code == 202


# ── The login response must derive roles from the token ─────────────────────
# Regression tests for a shipped bug: _session_response read roles from the
# GoTrue response body's user.app_metadata. The Custom Access Token Hook writes
# into the JWT it mints, never into auth.users.raw_app_meta_data, so that field
# holds only {provider, providers} and roles came back empty. Broker Tools
# checks data.user.apps.broker_tools.access the moment login returns, so every
# sign-in there failed with "no access". CMS was unaffected only because it
# ignores the block and fetches its own /auth/me/.

@respx.mock
def test_login_roles_come_from_the_token_not_the_response_body(
    client, make_token, jwks_mock
):
    """The body deliberately carries NO roles, exactly as GoTrue sends it."""
    body = session_body(make_token(roles=['lead_manager']))
    assert 'roles' not in body['user']['app_metadata'], 'fixture must model GoTrue'

    respx.post(TOKEN_URL).mock(return_value=Response(200, json=body))
    response = client.post(
        '/v1/auth/login', json={'email': 'someone@allset.in', 'password': 'pw'}
    )
    assert response.status_code == 200

    user = response.json()['user']
    assert user['roles'] == ['lead_manager'], (
        'roles must be read from the access token; the response body never has them'
    )
    assert user['apps']['broker_tools']['access'] is True, (
        'a client that gates on this immediately after login would refuse the user'
    )
    assert user['apps']['broker_tools']['unrestricted_leads'] is True


@respx.mock
def test_login_response_matches_introspect_for_the_same_token(
    client, make_token, jwks_mock, service_headers
):
    """Both must be derived from the same source, since a client renders its UI
    from the login response and the backend authorises from introspect."""
    token = make_token(roles=['manager', 'presales'])
    respx.post(TOKEN_URL).mock(return_value=Response(200, json=session_body(token)))

    login = client.post(
        '/v1/auth/login', json={'email': 'someone@allset.in', 'password': 'pw'}
    ).json()
    introspected = client.post(
        '/v1/introspect', json={'token': token}, headers=service_headers
    ).json()

    assert login['user']['apps'] == introspected['apps']
    assert login['user']['roles'] == introspected['roles']


@respx.mock
def test_an_unverifiable_token_is_a_502_not_an_empty_role_set(
    client, make_token, jwks_mock
):
    """If Supabase hands back a token we cannot verify, the configuration is
    wrong. Saying so beats returning a confidently empty role set that reads as
    a permissions problem."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = other.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    respx.post(TOKEN_URL).mock(
        return_value=Response(200, json=session_body(make_token(roles=['admin'], key=pem)))
    )
    response = client.post(
        '/v1/auth/login', json={'email': 'someone@allset.in', 'password': 'pw'}
    )
    assert response.status_code == 502
