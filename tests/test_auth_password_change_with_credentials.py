"""POST /v1/auth/password/change-with-credentials — the sign-in screen flow.

Changing a password without being signed in. The current password is the proof
of ownership, so no bearer token is involved.

That makes this the second unauthenticated endpoint in the service that accepts
a password, and the tests below are mostly about the two obligations that come
with being one: it must be behind the same per-email throttle as login, and it
must not answer in a way that reveals which addresses have accounts.
"""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from app.api.v1 import auth as auth_module
from tests.conftest import SUPABASE_URL

TOKEN_URL = f'{SUPABASE_URL}/auth/v1/token'
ADMIN_USERS_URL = f'{SUPABASE_URL}/auth/v1/admin/users'
REVOKE_URL = f'{SUPABASE_URL}/rest/v1/rpc/identity_revoke_user_sessions'

PATH = '/v1/auth/password/change-with-credentials'

USER_ID = '11111111-2222-3333-4444-555555555555'
EMAIL = 'someone@allset.in'
CURRENT = 'the-old-password'
NEW = 'a-brand-new-password'


@pytest.fixture(autouse=True)
def reset_rate_limit():
    """The throttle is module-level state and would otherwise leak between
    tests — and between these tests and the login suite, which shares it."""
    auth_module._attempts.clear()
    yield
    auth_module._attempts.clear()


def body(email=EMAIL, current=CURRENT, new=NEW):
    return {'email': email, 'current_password': current, 'new_password': new}


def session_body(token):
    return {
        'access_token': token,
        'refresh_token': 'refresh-token',
        'expires_in': 604800,
        'user': {'id': USER_ID, 'email': EMAIL, 'app_metadata': {'provider': 'email'}},
    }


# ── The happy path ───────────────────────────────────────────────────────────

@respx.mock
def test_a_correct_current_password_changes_it(client, make_token, jwks_mock):
    token = make_token(roles=['sales'], user_id=USER_ID, email=EMAIL)
    verify = respx.post(TOKEN_URL).mock(return_value=Response(200, json=session_body(token)))
    put = respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )
    respx.post(REVOKE_URL).mock(return_value=Response(200, text='1'))

    assert client.post(PATH, json=body()).status_code == 204

    submitted = verify.calls.last.request.read().decode()
    assert EMAIL in submitted and CURRENT in submitted
    assert NEW in put.calls.last.request.read().decode()


@respx.mock
def test_it_works_for_a_user_with_no_broker_tools_access(client, make_token, jwks_mock):
    """The whole reason this endpoint exists. A CMS-only user is refused by
    Broker Tools' own login, so they can never reach the in-app modal — but they
    share one password across both apps and must be able to change it."""
    token = make_token(roles=['editor'], user_id=USER_ID, email=EMAIL)
    respx.post(TOKEN_URL).mock(return_value=Response(200, json=session_body(token)))
    respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )
    respx.post(REVOKE_URL).mock(return_value=Response(200, text='1'))

    assert client.post(PATH, json=body()).status_code == 204


@respx.mock
def test_the_email_is_normalised(client, make_token, jwks_mock):
    """Someone typing their address at a login prompt will capitalise it."""
    token = make_token(roles=['sales'], user_id=USER_ID, email=EMAIL)
    verify = respx.post(TOKEN_URL).mock(return_value=Response(200, json=session_body(token)))
    respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )
    respx.post(REVOKE_URL).mock(return_value=Response(200, text='1'))

    assert client.post(PATH, json=body(email='  SomeOne@AllSet.IN  ')).status_code == 204
    assert EMAIL in verify.calls.last.request.read().decode()


@respx.mock
def test_the_change_revokes_every_session(client, make_token, jwks_mock):
    """Including the one just minted to check the old password."""
    token = make_token(roles=['sales'], user_id=USER_ID, email=EMAIL)
    respx.post(TOKEN_URL).mock(return_value=Response(200, json=session_body(token)))
    respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )
    revoke = respx.post(REVOKE_URL).mock(return_value=Response(200, text='2'))

    assert client.post(PATH, json=body()).status_code == 204
    assert revoke.called
    assert USER_ID in revoke.calls.last.request.read().decode()


# ── Enumeration resistance ───────────────────────────────────────────────────

@respx.mock
def test_a_wrong_password_gives_logins_generic_message(client, jwks_mock):
    """NOT the authenticated endpoint's "that is not your current password".
    This form carries an email field, so a specific message would confirm which
    addresses have accounts — something /v1/auth/login deliberately never
    reveals. The two endpoints must not disagree about that."""
    respx.post(TOKEN_URL).mock(
        return_value=Response(400, json={'error_code': 'invalid_credentials'})
    )
    put = respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )

    response = client.post(PATH, json=body(current='wrong'))
    assert response.status_code == 401
    assert response.json()['detail'] == 'invalid email or password'
    assert not put.called


@respx.mock
def test_an_unknown_address_is_indistinguishable_from_a_wrong_password(
    client, jwks_mock
):
    respx.post(TOKEN_URL).mock(
        return_value=Response(400, json={'error_code': 'user_not_found'})
    )
    unknown = client.post(PATH, json=body(email='nobody@allset.in'))

    respx.post(TOKEN_URL).mock(
        return_value=Response(400, json={'error_code': 'invalid_credentials'})
    )
    auth_module._attempts.clear()
    wrong = client.post(PATH, json=body(current='wrong'))

    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


# ── Rate limiting ────────────────────────────────────────────────────────────

@respx.mock
def test_it_is_throttled_per_email(client, jwks_mock):
    """Unauthenticated and password-accepting, so without this it is a password
    oracle sitting beside the throttled one."""
    respx.post(TOKEN_URL).mock(
        return_value=Response(400, json={'error_code': 'invalid_credentials'})
    )

    from app.core import config
    for _ in range(config.LOGIN_RATE_LIMIT):
        assert client.post(PATH, json=body(current='wrong')).status_code == 401

    assert client.post(PATH, json=body(current='wrong')).status_code == 429


@respx.mock
def test_the_throttle_is_shared_with_login(client, jwks_mock):
    """One budget per email across both endpoints. Separate buckets would double
    an attacker's allowance for free."""
    respx.post(TOKEN_URL).mock(
        return_value=Response(400, json={'error_code': 'invalid_credentials'})
    )

    from app.core import config
    for _ in range(config.LOGIN_RATE_LIMIT):
        client.post('/v1/auth/login', json={'email': EMAIL, 'password': 'wrong'})

    assert client.post(PATH, json=body(current='wrong')).status_code == 429


@respx.mock
def test_the_throttle_is_keyed_per_email_not_globally(client, jwks_mock):
    """Everyone in the office shares one NAT address; they must not share one
    another's lockout."""
    respx.post(TOKEN_URL).mock(
        return_value=Response(400, json={'error_code': 'invalid_credentials'})
    )

    from app.core import config
    for _ in range(config.LOGIN_RATE_LIMIT + 1):
        client.post(PATH, json=body(current='wrong'))

    assert client.post(PATH, json=body(email='other@allset.in')).status_code == 401


# ── Other failure modes ──────────────────────────────────────────────────────

@respx.mock
def test_a_deactivated_account_cannot_change_its_password(client, make_token, jwks_mock):
    """Matches login. A deactivated account cannot sign in, so letting it change
    its password would only keep the credential warm."""
    token = make_token(roles=['sales'], user_id=USER_ID, email=EMAIL, is_active=False)
    respx.post(TOKEN_URL).mock(return_value=Response(200, json=session_body(token)))
    put = respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )

    assert client.post(PATH, json=body()).status_code == 403
    assert not put.called


@respx.mock
def test_a_short_new_password_is_rejected_before_supabase_is_touched(client, jwks_mock):
    verify = respx.post(TOKEN_URL).mock(return_value=Response(200, json={}))
    assert client.post(PATH, json=body(new='short')).status_code == 422
    assert not verify.called


@respx.mock
def test_a_supabase_outage_is_not_reported_as_a_wrong_password(client, jwks_mock):
    respx.post(TOKEN_URL).mock(return_value=Response(500, text='boom'))
    put = respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )

    response = client.post(PATH, json=body())
    assert response.status_code >= 500
    assert not put.called


@respx.mock
def test_a_failed_revocation_is_not_swallowed(client, make_token, jwks_mock):
    token = make_token(roles=['sales'], user_id=USER_ID, email=EMAIL)
    respx.post(TOKEN_URL).mock(return_value=Response(200, json=session_body(token)))
    respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )
    respx.post(REVOKE_URL).mock(return_value=Response(500, text='boom'))

    assert client.post(PATH, json=body()).status_code >= 500
