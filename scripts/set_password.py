"""Set a password directly, for bootstrap and lockout recovery.

The normal path is the set-password email from `manage_users.py create`. This
exists for the two cases where that path cannot work:

  * the very first admin account, before anyone can log in to anything
  * a lockout when the email never arrives — Supabase's built-in mail service
    is rate-limited to a handful of messages an hour and is not intended for
    production, so a burst of invites silently stops being delivered

Uses the service-role key, so it needs no existing session.

    python scripts/set_password.py krips@allset.in

The password is prompted for twice and never echoed, never passed as an
argument, and never written anywhere — not to the terminal, not to shell
history. Run it yourself; do not have someone else set your password and send
it to you.
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

import httpx

# Resolved from this file's location, not the working directory, so the script
# runs the same from the repo root and from inside scripts/. `sys.path.insert('.')`
# only worked from the root and failed with ModuleNotFoundError anywhere else.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.core import config  # noqa: E402

MIN_LENGTH = 10


def die(message: str) -> None:
    print(f'error: {message}', file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)

    email = sys.argv[1].strip().lower()
    svc = {
        'apikey': config.SUPABASE_SERVICE_ROLE_KEY,
        'Authorization': f'Bearer {config.SUPABASE_SERVICE_ROLE_KEY}',
        'Content-Type': 'application/json',
    }
    base = config.SUPABASE_URL

    r = httpx.get(f'{base}/auth/v1/admin/users', headers=svc, timeout=30,
                  params={'filter': email, 'per_page': 50})
    if not r.is_success:
        die(f'could not list users: HTTP {r.status_code}')
    match = [u for u in r.json().get('users', []) if u['email'].lower() == email]
    if not match:
        die(f'no Supabase user with email {email} - create one first with '
            f'manage_users.py create')
    user_id = match[0]['id']

    if not sys.stdin.isatty():
        die('refusing to read a password from a pipe - run this interactively')

    password = getpass.getpass(f'new password for {email}: ')
    if len(password) < MIN_LENGTH:
        die(f'too short - use at least {MIN_LENGTH} characters')
    if password != getpass.getpass('confirm: '):
        die('passwords do not match')

    r = httpx.put(f'{base}/auth/v1/admin/users/{user_id}', headers=svc, timeout=30,
                  json={'password': password, 'email_confirm': True})
    if not r.is_success:
        die(f'could not set the password: HTTP {r.status_code} {r.text[:200]}')
    print('password set')

    # Prove it works rather than assuming. A password that sets but does not
    # authenticate is the failure mode worth catching here, not at the login
    # screen.
    anon = {'apikey': config.SUPABASE_ANON_KEY,
            'Authorization': f'Bearer {config.SUPABASE_ANON_KEY}',
            'Content-Type': 'application/json'}
    r = httpx.post(f'{base}/auth/v1/token', headers=anon, timeout=30,
                   params={'grant_type': 'password'},
                   json={'email': email, 'password': password})
    del password

    if not r.is_success:
        die(f'the password was set but sign-in failed: HTTP {r.status_code} '
            f'{r.text[:200]}')

    print('sign-in verified')

    # Roles live in the JWT, not in this response body, so read them from the
    # profile table instead of app_metadata (which only has provider info).
    p = httpx.get(f'{base}/rest/v1/user_profiles', headers=svc, timeout=30,
                  params={'user_id': f'eq.{user_id}', 'select': 'roles,is_active'})
    if p.is_success and p.json():
        row = p.json()[0]
        print(f'roles: {row["roles"] or "none"}   active: {row["is_active"]}')
        if not row['roles']:
            print('note: no roles, so this account currently reaches neither app')
    else:
        print('note: no user_profiles row - this account has no roles yet. '
              'Add one with manage_users.py roles')


if __name__ == '__main__':
    main()
