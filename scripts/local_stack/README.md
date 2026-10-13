# Local stack

Runs Identity and the admin console on your machine without Supabase
credentials, against the real SQL:

- `up.sh` starts Postgres 15 with `db/001`-`005` and five test users, and
  PostgREST behind `/rest/v1` on `localhost:54321`, as Supabase serves it.
- `run_identity.py` runs the real Identity app against it on port 8100, with
  only Supabase Auth stubbed. Sign-in accepts any seeded user with the password
  printed at startup; the token's claims come from the real access-token hook.
- `down.sh` removes it.

```bash
pip install -r requirements-dev.txt -r requirements-legacy.txt   # psycopg2
scripts/local_stack/up.sh
(cd admin && npm ci && npm run build)
python scripts/local_stack/run_identity.py
# http://127.0.0.1:8100/admin/  as admin@allset.in
scripts/local_stack/down.sh
```

Needs Docker. Uses ports 55433, 54321 and 8100. For local use only; it has no
security of its own.

Seeded users, from `tests/db/existing_roster.sql`:

| Email | Roles |
| --- | --- |
| `admin@allset.in` | admin |
| `tech@allset.in` | tech |
| `presales@allset.in` | presales, viewer (desk: presales) |
| `sales@allset.in` | sales (desk: sales) |
| `viewer@allset.in` | viewer |
