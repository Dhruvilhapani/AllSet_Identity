"""Create users and set their roles from the command line.

The admin UIs are the normal way to do this, but they need their whole stack up
first — and the very first accounts have to exist before anyone can log in to
either one. This talks to the identity service directly.

    python scripts/manage_users.py list
    python scripts/manage_users.py create jinal@allset.in "Jinal Jadeja" presales
    python scripts/manage_users.py create khush@allset.in "Khush Anada" lead_manager viewer
    python scripts/manage_users.py roles darshil@allset.in sales viewer
    python scripts/manage_users.py status bhavin@allset.in off
    python scripts/manage_users.py roles someone@allset.in          # no roles = no access

Authenticates as you. The password is prompted for when interactive and read
from stdin when piped, so it is never passed as an argument — an argument would
land in your shell history. Set ALLSET_ADMIN_EMAIL to avoid retyping your
address.

To add several people at once, read the password once and pipe it per call:

    read -rs PASS
    while IFS='|' read -r mail name role; do
      echo "$PASS" | python scripts/manage_users.py create "$mail" "$name" "$role"
    done <<'ROSTER'
    jinal@allset.in|Jinal Jadeja|presales
    darshil@allset.in|Darshil Rathod|sales
    ROSTER

New users are emailed a set-password link and choose their own; this never sets
a password on someone's behalf.
"""

from __future__ import annotations

import getpass
import os
import sys

import httpx

IDENTITY = os.environ.get('IDENTITY_URL', 'http://127.0.0.1:8100').rstrip('/')
TIMEOUT = 30


def die(message: str) -> None:
    print(f'error: {message}', file=sys.stderr)
    sys.exit(1)


def read_password(email: str) -> str:
    """Prompt when interactive, read stdin when piped.

    getpass reads the console directly rather than stdin — on Windows via
    msvcrt — so a piped password does not reach it and the script just hangs.
    Falling back to stdin when it is not a TTY makes the script usable in a
    loop (adding a roster, say) without putting the password in argv, where it
    would land in shell history.
    """
    if sys.stdin.isatty():
        return getpass.getpass(f'password for {email}: ')

    password = sys.stdin.readline().rstrip('\n')
    if not password:
        die('no password on stdin')
    return password


def login() -> str:
    email = os.environ.get('ALLSET_ADMIN_EMAIL') or input('admin email: ').strip()
    password = read_password(email)

    try:
        r = httpx.post(f'{IDENTITY}/v1/auth/login', timeout=TIMEOUT,
                       json={'email': email, 'password': password})
    except httpx.HTTPError as exc:
        die(f'cannot reach the identity service at {IDENTITY} ({exc.__class__.__name__})')

    if r.status_code == 401:
        die('invalid email or password')
    if r.status_code == 403:
        die('that account is not active')
    if r.status_code == 429:
        die('too many attempts - wait a minute')
    if r.status_code != 200:
        die(f'login failed: HTTP {r.status_code} {r.text[:200]}')

    body = r.json()
    roles = body['user']['roles']
    if not ({'admin', 'tech'} & set(roles)):
        die(f'you hold {roles or "no roles"}; managing users needs admin or tech')
    return body['access_token']


def api(token: str, method: str, path: str, payload: dict | None = None) -> dict:
    r = httpx.request(method, f'{IDENTITY}{path}', timeout=TIMEOUT,
                      headers={'Authorization': f'Bearer {token}'}, json=payload)
    if r.status_code >= 400:
        try:
            detail = r.json().get('detail', r.text)
        except ValueError:
            detail = r.text
        die(f'HTTP {r.status_code}: {detail}')
    return r.json() if r.content else {}


def find(token: str, email: str) -> dict:
    users = api(token, 'GET', '/v1/admin/users')['users']
    for u in users:
        if u['email'].lower() == email.lower():
            return u
    die(f'no user with email {email}')


def show(users: list[dict]) -> None:
    if not users:
        print('(no users)')
        return
    width = max(len(u['email']) for u in users)
    for u in sorted(users, key=lambda x: x['email']):
        cms = 'cms' if u['apps']['cms']['access'] else '---'
        bt = 'broker_tools' if u['apps']['broker_tools']['access'] else '------------'
        state = '' if u['is_active'] else '  [INACTIVE]'
        roles = ', '.join(u['roles']) or 'no roles'
        print(f'  {u["email"]:<{width}}  {cms:3} {bt:12}  {roles}{state}')


def main() -> None:
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)

    action, args = sys.argv[1], sys.argv[2:]
    token = login()
    print()

    if action == 'list':
        show(api(token, 'GET', '/v1/admin/users')['users'])

    elif action == 'create':
        if len(args) < 2:
            die('usage: create <email> "<full name>" [role ...]')
        email, full_name, roles = args[0], args[1], args[2:]
        created = api(token, 'POST', '/v1/admin/users',
                      {'email': email, 'full_name': full_name, 'roles': roles})
        print(f'created {created["email"]} with {created["roles"] or "no roles"}')
        print('a set-password email has been sent; they choose their own password')

    elif action == 'roles':
        if not args:
            die('usage: roles <email> [role ...]')
        email, roles = args[0], args[1:]
        user = find(token, email)
        updated = api(token, 'PATCH', f'/v1/admin/users/{user["user_id"]}/roles',
                      {'roles': roles})
        print(f'{email}: {user["roles"] or "no roles"} -> {updated["roles"] or "no roles"}')
        print('they must sign in again for it to take effect (sessions were revoked)')

    elif action == 'status':
        if len(args) != 2 or args[1] not in ('on', 'off'):
            die('usage: status <email> on|off')
        email, active = args[0], args[1] == 'on'
        user = find(token, email)
        api(token, 'PATCH', f'/v1/admin/users/{user["user_id"]}/status',
            {'is_active': active})
        print(f'{email} is now {"active" if active else "INACTIVE"}')

    else:
        die(f'unknown action {action!r} - try list, create, roles or status')


if __name__ == '__main__':
    main()
