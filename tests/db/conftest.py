"""Run db/001-005 against a real Postgres.

Skipped unless IDENTITY_TEST_DATABASE_URL points at a Postgres server the tests
may create a scratch database on, and psycopg2 is installed (it is in
requirements-legacy.txt, deliberately not in requirements-dev.txt). For example:

    docker run -d --name identity-pgtest -e POSTGRES_PASSWORD=pgtest -p 55432:5432 postgres:15
    pip install -r requirements-legacy.txt
    IDENTITY_TEST_DATABASE_URL=postgresql://postgres:pgtest@localhost:55432/postgres pytest tests/db

A fresh database is built for the session from tests/db/supabase_stub.sql (the
Supabase roles and auth tables the migrations expect), db/001-003, a roster
shaped like production before 004 (tests/db/existing_roster.sql), then db/004
and db/005. Each test runs in a transaction that is rolled back.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent

MIGRATIONS = [
    HERE / 'supabase_stub.sql',
    ROOT / 'db' / '001_schema.sql',
    ROOT / 'db' / '002_access_token_hook.sql',
    ROOT / 'db' / '003_revoke_sessions.sql',
    HERE / 'existing_roster.sql',
    ROOT / 'db' / '004_permissions.sql',
    ROOT / 'db' / '005_seed_permissions.sql',
]


@pytest.fixture(scope='session')
def database_url():
    server_url = os.environ.get('IDENTITY_TEST_DATABASE_URL')
    if not server_url:
        pytest.skip('IDENTITY_TEST_DATABASE_URL is not set')
    psycopg2 = pytest.importorskip('psycopg2')

    name = f'identity_sqltest_{uuid.uuid4().hex[:8]}'
    admin = psycopg2.connect(server_url)
    admin.autocommit = True
    with admin.cursor() as cur:
        cur.execute(f'create database {name}')

    parts = urlsplit(server_url)
    url = urlunsplit(parts._replace(path=f'/{name}'))
    try:
        conn = psycopg2.connect(url)
        conn.autocommit = True
        with conn.cursor() as cur:
            for path in MIGRATIONS:
                cur.execute(path.read_text(encoding='utf-8'))
        conn.close()
        yield url
    finally:
        with admin.cursor() as cur:
            cur.execute(f'drop database if exists {name} with (force)')
        admin.close()


@pytest.fixture
def db(database_url):
    import psycopg2

    conn = psycopg2.connect(database_url)
    try:
        yield conn
    finally:
        conn.rollback()
        conn.close()
