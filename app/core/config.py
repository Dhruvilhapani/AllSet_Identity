"""Configuration, read from the environment once at import.

Deliberately mirrors the shape of AllSet_Broker_Tools' services/*/core config
modules — plain module-level constants read with os.environ, a _find_dotenv that
walks up to the repo root, and real environment variables winning over the file.
On Cloud Run there is no .env; these arrive as service environment variables.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv


def _find_dotenv() -> Path | None:
    for directory in [Path(__file__).resolve(), *Path(__file__).resolve().parents]:
        candidate = directory / '.env'
        if candidate.is_file():
            return candidate
    return None


_dotenv = _find_dotenv()
if _dotenv is not None:
    # No override: a real environment variable always beats the file.
    load_dotenv(_dotenv)


def _require(name: str) -> str:
    value = os.environ.get(name, '').strip()
    if not value:
        raise RuntimeError(
            f'{name} is required. Set it as a Cloud Run environment variable '
            f'or in .env for local development.'
        )
    return value


def _flag(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, '').strip().lower()
    if not raw:
        return default
    return raw in ('1', 'true', 'yes', 'on')


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, '').strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise RuntimeError(f'{name} must be an integer, got {raw!r}') from None


DEBUG = _flag('IDENTITY_DEBUG')

# ── Supabase (the call_logs project) ─────────────────────────────────────────
# Shared with Broker Tools' leads schema rather than dedicated, because the
# free tier allows only two projects.
#
# SERVICE_ROLE_KEY bypasses RLS and can mint sessions for any user. It must
# never reach a browser — that is the whole reason this service exists rather
# than each frontend talking to Supabase directly. Sharing the project widens
# what the key reaches to every lead and call record in it, which is another
# reason it lives in exactly one process.
SUPABASE_URL = os.environ.get('SUPABASE_URL', '').rstrip('/')
SUPABASE_ANON_KEY = os.environ.get('SUPABASE_ANON_KEY', '')
SUPABASE_SERVICE_ROLE_KEY = os.environ.get('SUPABASE_SERVICE_ROLE_KEY', '')

# JWKS endpoint for local signature verification. Cached in memory and refetched
# only on an unrecognised `kid`, so token verification costs no network call.
SUPABASE_JWKS_URL = os.environ.get(
    'SUPABASE_JWKS_URL',
    f'{SUPABASE_URL}/auth/v1/.well-known/jwks.json' if SUPABASE_URL else '',
)
SUPABASE_JWT_ISSUER = os.environ.get(
    'SUPABASE_JWT_ISSUER',
    f'{SUPABASE_URL}/auth/v1' if SUPABASE_URL else '',
)
# Supabase signs access tokens with `aud: authenticated`.
SUPABASE_JWT_AUDIENCE = os.environ.get('SUPABASE_JWT_AUDIENCE', 'authenticated')

# Only needed if the project is still on the legacy symmetric (HS256) signing
# key. New projects issue asymmetric tokens verified via JWKS, and this stays
# empty. security.py picks the scheme from the token header rather than assuming.
SUPABASE_JWT_SECRET = os.environ.get('SUPABASE_JWT_SECRET', '')

# ── Service-to-service ───────────────────────────────────────────────────────
# Shared secret guarding /v1/introspect, compared with hmac.compare_digest.
# Fails closed when unset, matching Broker Tools' HasLeadsMasterSyncSecret.
SERVICE_KEY = os.environ.get('ALLSET_SERVICE_KEY', '')


def _named_keys(name: str) -> dict[str, str]:
    """Parse `consumer:key,consumer:key` into {consumer: key}."""
    keys: dict[str, str] = {}
    for entry in os.environ.get(name, '').split(','):
        if not entry.strip():
            continue
        consumer, _, key = entry.strip().partition(':')
        if not consumer.strip() or not key.strip():
            # The entry is not echoed: without a colon it is likely a bare key.
            raise RuntimeError(f'{name} entries must be "consumer:key"')
        keys[consumer.strip()] = key.strip()
    return keys


# Per-consumer keys, accepted on the same header as ALLSET_SERVICE_KEY. A
# consumer given one of these can be revoked alone, and its key unlocks only
# introspection — ALLSET_SERVICE_KEY is shared with ai_service and the CMS
# backend's internal endpoints, so handing it out grants those too. The name
# before the colon only identifies the key for whoever rotates it.
SERVICE_KEYS = _named_keys('ALLSET_SERVICE_KEYS')

# ── Shadow migration (CMS legacy passwords) ──────────────────────────────────
# Read-only connection to the CMS's Supabase project so a user's existing Django
# PBKDF2 password keeps working once, then gets upgraded to Supabase. Only the
# CMS has a durable legacy user store; Broker Tools' was ephemeral SQLite.
LEGACY_MIGRATION_ENABLED = _flag('LEGACY_MIGRATION_ENABLED')
LEGACY_CMS_DB_HOST = os.environ.get('LEGACY_CMS_DB_HOST', '')
LEGACY_CMS_DB_PORT = _int('LEGACY_CMS_DB_PORT', 5432)
LEGACY_CMS_DB_NAME = os.environ.get('LEGACY_CMS_DB_NAME', 'postgres')
LEGACY_CMS_DB_USER = os.environ.get('LEGACY_CMS_DB_USER', '')
LEGACY_CMS_DB_PASSWORD = os.environ.get('LEGACY_CMS_DB_PASSWORD', '')
LEGACY_CMS_DB_SSLMODE = os.environ.get('LEGACY_CMS_DB_SSLMODE', 'require')

# ── CORS ─────────────────────────────────────────────────────────────────────
# Both admin UIs are same-origin under dev.allset.in in production; the extra
# localhost entries cover the two Vite dev servers (5173 CMS, 5173 Broker Tools).
CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        'CORS_ORIGINS', 'http://localhost:5173,http://localhost:3000'
    ).split(',')
    if origin.strip()
]

# ── Tunables ─────────────────────────────────────────────────────────────────
# 7 days, up from 30 minutes, so nobody has to sign in twice a day. 604800 is
# Supabase's ceiling for this setting — 10 days was asked for and cannot be
# configured. Set on the Supabase project (Authentication → Sessions), not here;
# this value only mirrors it so clients can report the expiry and schedule
# refreshes. Changing it here alone changes nothing.
#
# The cost is revocation latency, and it is not small. Both `roles` and
# `is_active` are read from the token's claims — /v1/introspect does no I/O by
# design — so an access token already in a browser keeps the roles it was minted
# with until it expires. Revoking sessions kills refresh tokens at once, but
# nothing here can recall an issued JWT: not a role change, not deactivation,
# not a password reset. At 30 minutes that window was a nuisance. At 7 days,
# offboarding is not immediate and should not be assumed to be.
#
# The only way to invalidate live access tokens is to rotate the Supabase
# project's JWT signing key, which signs everyone out at once. If eviction ever
# needs to be quicker than this without that hammer, the fix is a short access
# token plus a client refresh loop — see the revocation section in README.md.
ACCESS_TOKEN_TTL_SECONDS = _int('ACCESS_TOKEN_TTL_SECONDS', 604800)

HTTP_TIMEOUT_SECONDS = _int('HTTP_TIMEOUT_SECONDS', 10)

# Login attempts per email per window, enforced in-process. Replaces the
# per-project throttles that lived in the CMS's users/throttles.py.
LOGIN_RATE_LIMIT = _int('LOGIN_RATE_LIMIT', 10)
LOGIN_RATE_WINDOW_SECONDS = _int('LOGIN_RATE_WINDOW_SECONDS', 60)


def validate() -> None:
    """Fail fast at startup rather than on the first request.

    Called from main.py. Kept separate from import so tests can import the
    module without a full environment.
    """
    _require('SUPABASE_URL')
    _require('SUPABASE_ANON_KEY')
    _require('SUPABASE_SERVICE_ROLE_KEY')
    _require('ALLSET_SERVICE_KEY')

    if LEGACY_MIGRATION_ENABLED:
        for name in ('LEGACY_CMS_DB_HOST', 'LEGACY_CMS_DB_USER', 'LEGACY_CMS_DB_PASSWORD'):
            _require(name)

    if not SUPABASE_JWKS_URL or not SUPABASE_JWT_ISSUER:
        raise RuntimeError('SUPABASE_JWKS_URL and SUPABASE_JWT_ISSUER could not be derived')
