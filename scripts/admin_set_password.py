"""Reset someone else's password, as an admin.

For when a colleague has forgotten their password and cannot get in. You do not
need their old password; you do need to be signed in as admin or tech.

    python scripts/admin_set_password.py darshil@allset.in

You are prompted for your own password first, then twice for theirs. Neither is
echoed and neither is passed as an argument, so nothing lands in shell history.
Set ALLSET_ADMIN_EMAIL to avoid retyping your own address.

The reset signs the target out of every session — including any the person who
knew the old password still holds, which is the point. Tell them the new
password over something better than chat, and have them change it themselves
afterwards from the Broker Tools account menu.

There are two other scripts nearby and they are not interchangeable:

  * manage_users.py create — the normal path for a NEW person. Emails them a
    link and lets them choose their own password; you never see it.
  * set_password.py — the same job as this script but straight against Supabase
    with the service-role key, so it needs no session and works when this
    service is down. Use it for the very first admin account, or when you
    cannot log in yourself. It leaves no record of who ran it.

Prefer this one otherwise: it runs as you, so the reset is attributable in the
service logs, and it does not require the service-role key on your machine.
"""

from __future__ import annotations

import getpass
import sys
from pathlib import Path

# scripts/ is not a package, so make this directory importable and reuse the
# login/lookup flow rather than keeping a second copy of it in step with the
# first. set_password.py does the same thing to reach app.core.config.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from manage_users import IDENTITY, api, die, find, login  # noqa: E402

MIN_LENGTH = 10


def read_new_password(email: str) -> str:
    """Prompt twice, echo nothing.

    Interactive only. getpass reads the console directly rather than stdin, so a
    piped password would not reach it and the script would just hang — and a
    password someone else chose is not something to accept from a pipe anyway.
    """
    if not sys.stdin.isatty():
        die('refusing to read a password from a pipe - run this interactively')

    password = getpass.getpass(f'new password for {email}: ')
    if len(password) < MIN_LENGTH:
        # Checked here as well as server-side so a typo costs a prompt rather
        # than a round trip and a 422.
        die(f'too short - use at least {MIN_LENGTH} characters')
    if password != getpass.getpass('confirm: '):
        die('passwords do not match')
    return password


def main() -> None:
    if len(sys.argv) != 2:
        print(__doc__)
        sys.exit(2)

    email = sys.argv[1].strip().lower()

    print(f'identity service: {IDENTITY}')
    token = login()

    user = find(token, email)
    if not user['is_active']:
        # Not fatal: the password is worth setting before reactivating them.
        # But it is worth saying, because they still will not be able to log in.
        print(f'note: {email} is INACTIVE and cannot sign in until reactivated '
              f'(manage_users.py status {email} on)')

    print(f'resetting the password for {user["full_name"] or email} '
          f'({", ".join(user["roles"]) or "no roles"})')
    password = read_new_password(email)

    api(token, 'POST', f'/v1/admin/users/{user["user_id"]}/set-password',
        {'new_password': password})
    del password

    print('password set; all their sessions were revoked')
    print('give it to them over something private, and ask them to change it '
          'themselves from the account menu')


if __name__ == '__main__':
    main()
