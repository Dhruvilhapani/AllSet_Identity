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
# 30 minutes, down from the 8 hours both projects used. Roles ride in the JWT and
# consumers cache for 60s, so a short access token is what bounds how long a
# revoked role stays usable. Set on the Supabase project, not here; this value is
# reported to clients so they can schedule refreshes.
ACCESS_TOKEN_TTL_SECONDS = _int('ACCESS_TOKEN_TTL_SECONDS', 1800)

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
