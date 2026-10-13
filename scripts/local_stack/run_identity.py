"""Run Identity against the local stack from up.sh, with Supabase Auth stubbed.

Everything is the real code except Supabase Auth (GoTrue): sign-in accepts any
seeded user with the password below and mints an HS256 token whose claims come
from the REAL custom_access_token_hook in the local Postgres. PostgREST, the SQL
functions, the policy cache, the admin API and the console are what run.

    pip install -r requirements-dev.txt -r requirements-legacy.txt   # psycopg2
    scripts/local_stack/up.sh
    (cd admin && npm ci && npm run build)       # so /admin has something to serve
    python scripts/local_stack/run_identity.py  # then open http://127.0.0.1:8100/admin/

Seeded users (tests/db/existing_roster.sql): admin@allset.in, tech@allset.in,
presales@allset.in, sales@allset.in, viewer@allset.in. For local use only:
never point this at a real project.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SECRET = 'local-stack-jwt-secret-at-least-32-characters'
PASSWORD = 'local-dev-password'
SUPABASE = 'http://localhost:54321'

sys.path.insert(0, str(REPO))
os.chdir(REPO)

from jose import jwt  # noqa: E402


def _sign(claims: dict) -> str:
    return jwt.encode(claims, SECRET, algorithm='HS256')


os.environ.update({
    'SUPABASE_URL': SUPABASE,
    'SUPABASE_ANON_KEY': _sign({'role': 'anon', 'iss': 'supabase'}),
    'SUPABASE_SERVICE_ROLE_KEY': _sign({'role': 'service_role', 'iss': 'supabase'}),
    'SUPABASE_JWT_SECRET': SECRET,
    'ALLSET_SERVICE_KEY': 'local-shared-service-key',
    'LEGACY_MIGRATION_ENABLED': 'false',
    'CORS_ORIGINS': 'http://localhost:5174',
    'POLICY_CACHE_TTL_SECONDS': '5',
})

import psycopg2  # noqa: E402

from app import supabase_client  # noqa: E402
from app.core import config  # noqa: E402

db = psycopg2.connect(host='localhost', port=55433, user='postgres', password='local', dbname='postgres')
db.autocommit = True


def _query(sql: str, *args):
    with db.cursor() as cur:
        cur.execute(sql, args)
        return cur.fetchall() if cur.description else None


def _session(user_id: str, email: str) -> dict:
    now = int(time.time())
    claims = {'sub': user_id, 'email': email, 'aud': 'authenticated', 'role': 'authenticated',
              'iss': config.SUPABASE_JWT_ISSUER, 'iat': now, 'exp': now + 3600}
    event = _query('select public.custom_access_token_hook(%s::jsonb)',
                   json.dumps({'user_id': user_id, 'claims': claims}))[0][0]
    return {'access_token': _sign(event['claims']), 'refresh_token': f'refresh:{user_id}',
            'token_type': 'bearer', 'expires_in': 3600, 'user': {'id': user_id, 'email': email}}


def sign_in_with_password(email: str, password: str) -> dict:
    rows = _query('select id::text from auth.users where lower(email) = lower(%s)', email)
    if not rows or password != PASSWORD:
        raise supabase_client.InvalidCredentials('invalid email or password', status_code=401)
    return _session(rows[0][0], email)


def refresh_session(refresh_token: str) -> dict:
    user_id = refresh_token.removeprefix('refresh:')
    rows = _query('select email from auth.users where id = %s::uuid', user_id)
    if not rows:
        raise supabase_client.InvalidCredentials('invalid refresh token', status_code=401)
    return _session(user_id, rows[0][0])


def admin_create_user(email: str, password: str | None, *, full_name: str = '') -> dict:
    user_id = str(uuid.uuid4())
    _query('insert into auth.users (id, email) values (%s::uuid, %s)', user_id, email)
    return {'id': user_id, 'email': email}


def admin_get_user_by_email(email: str) -> dict | None:
    rows = _query('select id::text, email from auth.users where lower(email) = lower(%s)', email)
    return {'id': rows[0][0], 'email': rows[0][1]} if rows else None


supabase_client.sign_in_with_password = sign_in_with_password
supabase_client.refresh_session = refresh_session
supabase_client.sign_out = lambda token: None
supabase_client.admin_create_user = admin_create_user
supabase_client.admin_get_user_by_email = admin_get_user_by_email
supabase_client.admin_set_password = lambda user_id, password: {'id': user_id}
supabase_client.send_recovery_email = lambda email: print(f'[local] would email a reset link to {email}')

if __name__ == '__main__':
    import uvicorn

    from app.main import app

    print(f'[local] console: http://127.0.0.1:8100/admin/  (password for every seeded user: {PASSWORD})')
    uvicorn.run(app, host='127.0.0.1', port=8100, log_level='warning')
