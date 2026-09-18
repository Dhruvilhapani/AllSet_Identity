"""POST /v1/auth/password/change — changing your own password.

Old password in, new password out. No email, no OTP: the current password is
the proof of ownership, which is why it is re-verified against Supabase rather
than trusted from the access token.

The status codes here are load-bearing for the Broker Tools UI, which shows a
different message for each and clears the session on some but not others. A 403
that turned into a 401 would bounce someone to the login screen for a typo.
"""

from __future__ import annotations

import respx
from httpx import Response

from tests.conftest import SUPABASE_URL

TOKEN_URL = f'{SUPABASE_URL}/auth/v1/token'
ADMIN_USERS_URL = f'{SUPABASE_URL}/auth/v1/admin/users'
REVOKE_URL = f'{SUPABASE_URL}/rest/v1/rpc/identity_revoke_user_sessions'

USER_ID = '11111111-2222-3333-4444-555555555555'
EMAIL = 'someone@allset.in'

CURRENT = 'the-old-password'
NEW = 'a-brand-new-password'


def auth_header(token):
    return {'Authorization': f'Bearer {token}'}


def body(current=CURRENT, new=NEW):
    return {'current_password': current, 'new_password': new}


def change(client, token, **kwargs):
    return client.post(
        '/v1/auth/password/change', json=body(**kwargs), headers=auth_header(token)
    )


# ── The guard ────────────────────────────────────────────────────────────────

def test_no_token_is_rejected(client):
    assert client.post('/v1/auth/password/change', json=body()).status_code == 401


@respx.mock
def test_a_deactivated_account_cannot_change_its_password(client, make_token, jwks_mock):
    token = make_token(roles=['sales'], is_active=False)
    assert change(client, token).status_code == 403


# ── The happy path ───────────────────────────────────────────────────────────

@respx.mock
def test_a_correct_current_password_changes_it(client, make_token, jwks_mock):
    verify = respx.post(TOKEN_URL).mock(
        return_value=Response(200, json={'access_token': 'x', 'refresh_token': 'y'})
    )
    put = respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )
    respx.post(REVOKE_URL).mock(return_value=Response(200, text='1'))

    token = make_token(roles=['sales'], user_id=USER_ID, email=EMAIL)
    assert change(client, token).status_code == 204

    # The current password is checked against the email in the TOKEN, not one
    # supplied in the body — otherwise this endpoint would let anyone with a
    # valid session change somebody else's password.
    verified = verify.calls.last.request.read().decode()
    assert EMAIL in verified
    assert CURRENT in verified
    assert NEW in put.calls.last.request.read().decode()


@respx.mock
def test_the_new_password_goes_to_the_caller_and_nobody_else(client, make_token, jwks_mock):
    respx.post(TOKEN_URL).mock(
        return_value=Response(200, json={'access_token': 'x', 'refresh_token': 'y'})
    )
    put = respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )
    respx.post(REVOKE_URL).mock(return_value=Response(200, text='1'))

    token = make_token(roles=['sales'], user_id=USER_ID)
    change(client, token)
    assert put.calls.last.request.url.path.endswith(USER_ID)


@respx.mock
def test_changing_your_password_revokes_your_sessions(client, make_token, jwks_mock):
    """Anyone who knew the old password may still hold a live session. The
    access token in the caller's own browser is a JWT and survives until it
    expires, which is what lets the UI leave them signed in — but their refresh
    tokens, and everyone else's, die here."""
    respx.post(TOKEN_URL).mock(
        return_value=Response(200, json={'access_token': 'x', 'refresh_token': 'y'})
    )
    respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )
    revoke = respx.post(REVOKE_URL).mock(return_value=Response(200, text='2'))

    token = make_token(roles=['sales'], user_id=USER_ID)
    assert change(client, token).status_code == 204
    assert revoke.called
    assert USER_ID in revoke.calls.last.request.read().decode()


# ── Failure modes the UI distinguishes ───────────────────────────────────────

@respx.mock
def test_a_wrong_current_password_is_403_not_401(client, make_token, jwks_mock):
    """403, deliberately. The Broker Tools client clears the session and
    redirects on a 401, so reporting a mistyped current password that way would
    sign the user out instead of telling them to try again."""
    respx.post(TOKEN_URL).mock(
        return_value=Response(400, json={'error_code': 'invalid_credentials'})
    )
    put = respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )

    token = make_token(roles=['sales'], user_id=USER_ID)
    response = change(client, token)
    assert response.status_code == 403
    assert not put.called, 'a failed check must not reach the password write'


@respx.mock
def test_a_short_new_password_is_rejected_before_supabase_is_touched(
    client, make_token, jwks_mock
):
    verify = respx.post(TOKEN_URL).mock(
        return_value=Response(200, json={'access_token': 'x'})
    )
    token = make_token(roles=['sales'], user_id=USER_ID)
    response = change(client, token, new='short')
    assert response.status_code == 422
    assert not verify.called


@respx.mock
def test_a_supabase_outage_is_not_reported_as_a_wrong_password(
    client, make_token, jwks_mock
):
    """Telling someone their password is wrong when the auth provider is simply
    down sends them off to reset a password that was fine all along."""
    respx.post(TOKEN_URL).mock(return_value=Response(500, text='boom'))
    put = respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )

    token = make_token(roles=['sales'], user_id=USER_ID)
    response = change(client, token)
    assert response.status_code not in (401, 403)
    assert response.status_code >= 500
    assert not put.called


@respx.mock
def test_rate_limiting_from_supabase_surfaces_as_429(client, make_token, jwks_mock):
    """Verifying the current password spends a real sign-in attempt, so a user
    guessing at their own old password can hit Supabase's limiter."""
    respx.post(TOKEN_URL).mock(
        return_value=Response(429, json={'error_code': 'over_request_rate_limit'})
    )
    token = make_token(roles=['sales'], user_id=USER_ID)
    assert change(client, token).status_code == 429


@respx.mock
def test_a_failed_revocation_is_not_swallowed(client, make_token, jwks_mock):
    """The password is already changed at this point, so this reports an error
    on a partially applied operation — which is right: the user needs to know
    the old sessions may still be live."""
    respx.post(TOKEN_URL).mock(
        return_value=Response(200, json={'access_token': 'x', 'refresh_token': 'y'})
    )
    respx.put(f'{ADMIN_USERS_URL}/{USER_ID}').mock(
        return_value=Response(200, json={'id': USER_ID})
    )
    respx.post(REVOKE_URL).mock(return_value=Response(500, text='boom'))

    token = make_token(roles=['sales'], user_id=USER_ID)
    assert change(client, token).status_code >= 500
