"""Shared fixtures.

Environment variables are set before app modules import, because app.core.config
reads os.environ at import time and app.main calls config.validate().
"""

from __future__ import annotations

import base64
import os
import time

import pytest

SUPABASE_URL = 'https://identity.test.supabase.co'
ISSUER = f'{SUPABASE_URL}/auth/v1'
SERVICE_KEY = 'test-service-shared-secret'
JWT_SECRET = 'test-hs256-secret-value'

os.environ.update({
    'SUPABASE_URL': SUPABASE_URL,
    'SUPABASE_ANON_KEY': 'test-anon-key',
    'SUPABASE_SERVICE_ROLE_KEY': 'test-service-role-key',
    'ALLSET_SERVICE_KEY': SERVICE_KEY,
    'SUPABASE_JWT_SECRET': JWT_SECRET,
    'LEGACY_MIGRATION_ENABLED': 'false',
    'IDENTITY_DEBUG': 'false',
})


def _b64url_uint(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode()


@pytest.fixture(scope='session')
def rsa_keypair():
    """An RSA key plus the JWKS entry describing its public half.

    Production signs asymmetrically and the gateway verifies against JWKS, so
    that path needs real keys rather than a shared secret.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    numbers = private_key.public_key().public_numbers()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()

    kid = 'test-key-1'
    jwk = {
        'kty': 'RSA',
        'kid': kid,
        'use': 'sig',
        'alg': 'RS256',
        'n': _b64url_uint(numbers.n),
        'e': _b64url_uint(numbers.e),
    }
    return {'pem': pem, 'jwk': jwk, 'kid': kid, 'jwks': {'keys': [jwk]}}


@pytest.fixture
def make_token(rsa_keypair):
    """Mint an access token shaped exactly like Supabase's, including the
    app_metadata claim our Custom Access Token Hook writes."""
    from jose import jwt

    def _make(
        *,
        roles=None,
        is_active=True,
        user_id='11111111-2222-3333-4444-555555555555',
        email='someone@allset.in',
        full_name='Some One',
        expires_in=1800,
        algorithm='RS256',
        issuer=ISSUER,
        audience='authenticated',
        include_app_metadata=True,
        key=None,
    ):
        now = int(time.time())
        claims = {
            'sub': user_id,
            'email': email,
            'iss': issuer,
            'aud': audience,
            'iat': now,
            'exp': now + expires_in,
            'role': 'authenticated',
        }
        if include_app_metadata:
            claims['app_metadata'] = {
                'roles': roles if roles is not None else [],
                'is_active': is_active,
                'full_name': full_name,
            }

        if algorithm == 'HS256':
            signing_key = key or JWT_SECRET
            headers = None
        else:
            signing_key = key or rsa_keypair['pem']
            headers = {'kid': rsa_keypair['kid']}

        return jwt.encode(claims, signing_key, algorithm=algorithm, headers=headers)

    return _make


@pytest.fixture
def jwks_mock(rsa_keypair):
    """Serve the JWKS document and reset the in-process key cache.

    The cache is module-level and would otherwise leak between tests.
    """
    import respx

    from app.core import security

    security._jwks.clear()
    with respx.mock(assert_all_called=False) as router:
        router.get(f'{SUPABASE_URL}/auth/v1/.well-known/jwks.json').respond(
            json=rsa_keypair['jwks']
        )
        yield router
    security._jwks.clear()


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app)


@pytest.fixture
def service_headers():
    return {'X-Allset-Service-Key': SERVICE_KEY}
