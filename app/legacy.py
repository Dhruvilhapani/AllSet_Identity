"""Shadow migration of CMS passwords.

The CMS has real users whose passwords are Django PBKDF2 hashes. Supabase stores
bcrypt, so the hashes cannot be imported. Rather than force a reset on everyone,
the first successful login with a legacy password transparently upgrades the
account: verify against the Django hash, then set the same password in Supabase.

This covers the CMS only. Broker Tools had no durable user store to migrate from
— its AUTH_USER_MODEL lived on an ephemeral SQLite file that was re-seeded from
hardcoded passwords on every container start — so its accounts are provisioned
directly and get set-password emails.

The whole module is gated behind LEGACY_MIGRATION_ENABLED. Once every profile
has legacy_migrated_at set, turn the flag off and delete this file.
"""

from __future__ import annotations

import logging

from passlib.hash import django_pbkdf2_sha256

from app.capabilities import ADMIN, EDITOR, MANAGER, TECH, VIEWER
from app.core import config

logger = logging.getLogger(__name__)


def _psycopg2():
    """Imported on demand, not at module load.

    psycopg2 is a native dependency needed only while LEGACY_MIGRATION_ENABLED
    is on, and this whole module is deleted once every profile has been
    migrated. Importing lazily means the service — and its test suite — runs
    without it, which is why it is not in requirements.txt.
    """
    try:
        import psycopg2
        import psycopg2.extras
    except ImportError as exc:
        # Without this, enabling the flag produces a bare ImportError from
        # inside a login attempt, which reads as a service bug rather than a
        # missing optional dependency.
        raise RuntimeError(
            'LEGACY_MIGRATION_ENABLED is on but psycopg2 is not installed. '
            'Run: pip install -r requirements-legacy.txt  '
            '(or set LEGACY_MIGRATION_ENABLED=false)'
        ) from exc

    return psycopg2


# The CMS's retired vocabulary mapped onto the unified one. 'agent' and 'viewer'
# were permission-identical in the CMS (both resolved to zero can_* flags), so
# collapsing them loses nothing. Legacy users get CMS roles only — Broker Tools
# access is granted deliberately by an admin afterwards, never inferred.
_LEGACY_ROLE_MAP = {
    'admin': [ADMIN],
    'editor': [EDITOR],
    'agent': [VIEWER],
    'viewer': [VIEWER],
    # Not a legacy CMS value, but tolerated in case the column was hand-edited.
    'manager': [MANAGER],
    'tech': [TECH],
}


class LegacyUser:
    __slots__ = ('email', 'full_name', 'roles', 'is_active')

    def __init__(self, email: str, full_name: str, roles: list[str], is_active: bool):
        self.email = email
        self.full_name = full_name
        self.roles = roles
        self.is_active = is_active


def _connect():
    psycopg2 = _psycopg2()
    return psycopg2.connect(
        host=config.LEGACY_CMS_DB_HOST,
        port=config.LEGACY_CMS_DB_PORT,
        dbname=config.LEGACY_CMS_DB_NAME,
        user=config.LEGACY_CMS_DB_USER,
        password=config.LEGACY_CMS_DB_PASSWORD,
        sslmode=config.LEGACY_CMS_DB_SSLMODE,
        connect_timeout=5,
        # Read-only at the session level as well as by grant, so a bug here can
        # never write to the CMS's production database.
        options='-c default_transaction_read_only=on',
    )


def verify_legacy_password(email: str, password: str) -> LegacyUser | None:
    """Return the legacy user if the password matches their Django hash.

    Returns None for every failure mode — unknown email, wrong password,
    unsupported hash format, or the feature being disabled. The caller reports a
    generic invalid-credentials error either way, so this cannot be used to
    discover which addresses exist.
    """
    if not config.LEGACY_MIGRATION_ENABLED:
        return None

    psycopg2 = _psycopg2()
    try:
        with _connect() as connection:
            with connection.cursor(cursor_factory=psycopg2.extras.DictCursor) as cursor:
                cursor.execute(
                    """
                    SELECT email, password, is_active, role, first_name, last_name
                    FROM users_teammember
                    WHERE lower(email) = lower(%s)
                    LIMIT 1
                    """,
                    (email,),
                )
                row = cursor.fetchone()
    except psycopg2.Error:
        # An outage must not read as a wrong password, but it also must not let
        # anyone in. Deny and let the operator see it in the logs.
        logger.exception('legacy CMS lookup failed')
        return None

    if row is None:
        return None

    stored = row['password'] or ''
    # Django marks unusable passwords with a leading '!'. Those accounts were
    # created by the invite flow that never emailed a password, so they could
    # never log in anyway.
    if not stored or stored.startswith('!'):
        return None

    try:
        if not django_pbkdf2_sha256.verify(password, stored):
            return None
    except ValueError:
        # A hash in some other Django scheme (argon2, bcrypt_sha256). Not
        # supported; the user goes through password reset instead.
        logger.info('legacy hash for a submitted address uses an unsupported scheme')
        return None

    if not row['is_active']:
        return None

    full_name = ' '.join(part for part in (row['first_name'], row['last_name']) if part).strip()
    roles = _LEGACY_ROLE_MAP.get((row['role'] or '').strip().lower(), [VIEWER])

    return LegacyUser(
        email=row['email'],
        full_name=full_name,
        roles=list(roles),
        is_active=True,
    )
