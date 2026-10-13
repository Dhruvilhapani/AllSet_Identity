# AllSet Identity

Unified authentication and permissions for every AllSet service: the CMS,
Broker Tools, WhatsApp Automation and Consultation Agent. One identity per
person, one password, one role set, and one place — the admin console at
`/admin` — to decide who may do what in each service.

Before this service, each app ran its own Django SimpleJWT auth with its own
role vocabulary (`admin/editor/agent/viewer` vs `admin/manager/presales/sales`),
so anyone working in both had two accounts. Broker Tools was worse off: its user
table lived on an ephemeral SQLite file that was re-seeded from hardcoded
passwords on every container start, so password changes never persisted and the
seeded defaults were effectively permanent.

The permission model, the admin console and every decision behind them are in
[`docs/ARCHITECTURE_ADMIN.md`](docs/ARCHITECTURE_ADMIN.md). Services integrate
with [`docs/INTEGRATION.md`](docs/INTEGRATION.md).

## Roles and permissions

A user holds a **set** of roles, and their permissions are the **union** of
what those roles are granted. A grant says: this role may perform this action on
this resource of this service, limited to this scope (which rows). Each service
declares its resources, actions and scopes in a manifest; admins create roles,
grant them in a per-service matrix, and assign them, all in the console. None of
it is code any more: it lives in the `identity_*` tables (`db/004_permissions.sql`).

The roles seeded on day one, and what they grant, reproduce exactly what the
services enforced before (`db/005_seed_permissions.sql`, generated from
`app/permissions/seed/`):

| Role | Label | CMS | Broker Tools |
|---|---|---|---|
| `admin` | Admin | Everything (superuser: every action in every service) | Everything |
| `tech` | Tech | Full, incl. delete | All leads; not lead-distribution settings |
| `manager` | Manager | Add/edit/publish/upload/SEO | — |
| `editor` | Editor | Same as manager | — |
| `viewer` | Viewer | Read-only | — |
| `lead_manager` | Lead Manager | — | All leads |
| `presales` | Pre-sales | — | Own leads (`fk_presales_owner`) |
| `sales` | Sales | — | Own leads (`fk_sales_owner`) |

So `{sales, viewer}` means own-leads in Broker Tools plus read-only CMS, and
`{manager, sales}` means CMS editor-level plus own-leads. WA Automation and
Consultation Agent are granted to the Broker Tools roles; the console shows the
full matrix for each service.

Rules the database enforces, because the role set must never be wrong:

- a role must exist to be assigned (foreign key)
- **at most one role per exclusive group**: `presales` and `sales` share the
  group `desk`
- the last active `admin` cannot lose the role or be deactivated

An **empty** role set is legal and means "the account exists but reaches
nothing" — the clean offboarding state, distinct from `is_active = false`, which
blocks login outright.

Broker Tools' **desk** (presales or sales) is a per-service user attribute set
in the console, separate from the role, because Broker Tools' auto-assignment,
distribution pool and team reports select people by it.

## How it fits together

```
  admin console (/admin) · CMS admin_ui · Broker Tools web · WA console
        │                        │
        └──── POST /v1/auth/login ────┐
                                      ▼
                            ┌──────────────────┐
                            │ AllSet Identity  │──── Supabase Auth + identity_* tables
                            │    (this repo)   │     (call_logs project)
                            └──────────────────┘
                                      ▲
        ┌────── POST /v1/introspect ───┘
        │
  CMS backend · ai_service · Broker Tools API + FastAPI · WA Automation · Consultation Agent
```

`/v1/introspect` sits on the hot path — every authenticated request in every
service goes through it — so it does **no I/O per request**:

1. This service verifies the token's signature against an **in-memory JWKS
   cache**, refetched only when a `kid` is unrecognised.
2. It looks the user up in the **policy snapshot**: every service, resource,
   role and grant, plus the roster (each user's roles, status, name, phone and
   attributes), held in memory and refreshed in the background every 30 s
   (`app/permissions/cache.py`). An instance that cannot load a snapshot at all
   answers 503, which consumers fail closed on.
3. It resolves the user's roles into `permissions` per service, memoised per
   role set, and keeps emitting the old capability flags beside them until every
   consumer has migrated.
4. Consumers cache the response for 60s keyed on a hash of the token.

A Supabase **Custom Access Token Hook** (`db/002_access_token_hook.sql`) still
stamps roles, status, name and phone into every token. Those claims are used
only for a user created after the last snapshot refresh.

**Revocation.** Because roles and status come from the roster rather than the
token, removing a role or deactivating someone reaches every consumer in about
90 s (the 30 s refresh plus their 60 s cache), even though access tokens live for
**7 days**. Every role change, deactivation and admin password reset also revokes
the user's sessions, which kills their refresh tokens at once.

That revocation goes through the `identity_revoke_user_sessions` RPC, not a
GoTrue endpoint. GoTrue has no admin logout: `POST /admin/users/{id}/logout`
does not exist, and `POST /logout?scope=global` needs the user's own access
token. Both verified against a live project. If `db/003_revoke_sessions.sql`
has not been applied, role changes fail loudly rather than reporting success
while the old sessions stay alive.

What still cannot be recalled is the token itself: after a password reset, a
token already in someone's browser keeps passing introspect until it expires —
with whatever roles the roster gives its user now. Deactivate the account if
that matters. 7 days is Supabase's ceiling for the access-token lifetime
(604800 seconds), set so people are not signed out several times a day.

## Endpoints

**Browser-facing** — called by the admin console and every app's frontend:

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/auth/login` | Email + password. Returns tokens plus the same payload `/v1/introspect` gives, so a client can render without a second call. |
| POST | `/v1/auth/refresh` | Refuses a deactivated account. |
| POST | `/v1/auth/logout` | |
| GET | `/v1/auth/me` | |
| POST | `/v1/auth/password/change` | Self-service, signed in. Re-verifies the current password first, then revokes the user's other sessions. |
| POST | `/v1/auth/password/change-with-credentials` | Self-service, **not** signed in — email + current password + new. Behind login's per-email throttle, and answers with login's generic message. |
| POST | `/v1/auth/password/reset-request` | Always reports success, so it cannot enumerate the roster. Nothing handles the emailed link yet — see below. |
| GET | `/v1/auth/roles` | The roles admins have defined, with labels and exclusive groups, for role pickers. |

**Service-facing** — requires `X-Allset-Service-Key`:

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/introspect` | Always HTTP 200 for any token. An invalid one is `{"active": false}`, never an error status — see below. 503 when no policy snapshot can be loaded. |
| GET | `/v1/introspect/health` | Checks a service key without a user token; says which service the key belongs to and whether the policy is loaded. |
| PUT | `/v1/services/manifest` | A service pushes its catalogue on deploy, with its own key (the shared key is refused). |

Keys are accepted from `ALLSET_SERVICE_KEY` (shared, identifies no service),
`ALLSET_SERVICE_KEYS` (named) and keys generated in the console (stored hashed).

**Admin** — requires the `identity.console.use` permission (`admin` and `tech`
in the seed). The console at `/admin` is the main client:

| Method | Path | Notes |
|---|---|---|
| GET, POST | `/v1/admin/users` | List (filters `role`, `service`, `active`); invite. |
| GET, PATCH | `/v1/admin/users/{id}` | Detail with effective access per service; edit name and phone. |
| PATCH | `/v1/admin/users/{id}/roles` | Replace roles. Revokes the target's sessions. You cannot remove your own console access. |
| PUT | `/v1/admin/users/{id}/attributes/{service}` | Per-service attributes, such as Broker Tools' desk. |
| PATCH | `/v1/admin/users/{id}/status` | Revokes the target's sessions on deactivation. The last active admin cannot be deactivated. |
| POST | `/v1/admin/users/{id}/reset-password` | Emails a set-password link. |
| POST | `/v1/admin/users/{id}/set-password` | Sets a password outright, no old password needed. Revokes the target's sessions. |
| GET, POST | `/v1/admin/roles` | List with member counts; create. |
| PATCH, DELETE | `/v1/admin/roles/{key}` | Edit (the key never changes); delete is refused while anyone holds the role. |
| GET, POST | `/v1/admin/services` | List; register a service. |
| GET, PATCH | `/v1/admin/services/{key}` | Catalogue with retired items, and keys; rename, deactivate. |
| DELETE | `/v1/admin/services/{key}/resources/{resource}` | Remove a retired resource and its grants. |
| GET, PUT | `/v1/admin/services/{key}/grants` | The matrix. PUT needs `If-Match` with the version from GET; 409 if someone else saved first. |
| POST, DELETE | `/v1/admin/services/{key}/keys[/{id}]` | Generate (plaintext shown once) or revoke a service key. |
| GET | `/v1/admin/audit` | Every change, newest first. |

Every write goes through a SQL function in `db/004_permissions.sql` that records
an audit row in the same transaction.

### The introspect status-code contract

`/v1/introspect` returns **200 with `active: false`** for a token that is
invalid, expired or deactivated, and a **5xx** only when the service itself is
broken. Consumers must treat these differently: the first is a routine 401 for
the end user, the second must fail closed. Collapsing them would either lock
everyone out during a blip or let anyone in.

## Local development

```bash
python -m venv .venv
. .venv/Scripts/activate          # Windows; source .venv/bin/activate elsewhere
python -m pip install -r requirements-dev.txt
cp .env.example .env              # then fill in the Supabase values
uvicorn app.main:app --reload --port 8100
```

```bash
pytest -q          # no network access needed; tests/db is skipped (see below)
ruff check .
```

The admin console lives in `admin/` (React + Vite); see
[`admin/README.md`](admin/README.md) to run it against this service. To run
Identity and the console without Supabase credentials, against the real SQL,
use [`scripts/local_stack/`](scripts/local_stack/README.md).

**The SQL itself** is tested against a real Postgres in `tests/db/`, skipped
unless you point it at a server it may create a scratch database on:

```bash
docker run -d --name identity-pgtest -e POSTGRES_PASSWORD=pgtest -p 55432:5432 postgres:15
pip install -r requirements-legacy.txt            # psycopg2
IDENTITY_TEST_DATABASE_URL=postgresql://postgres:pgtest@localhost:55432/postgres pytest tests/db
```

It applies `db/001`-`005` to a fresh database with stand-ins for Supabase's
roles and auth tables, checks the seeded policy resolves exactly like the seed
JSON, and exercises every SQL function's guards and audit rows.

**Changing the seed.** `app/permissions/seed/` holds the initial roles, each
service's manifest and the grants. After editing it, run
`python scripts/build_seed_sql.py` to regenerate `db/005_seed_permissions.sql`;
`tests/test_seed_sql.py` fails until you do, and
`tests/test_permissions_equivalence.py` fails if the grants no longer reproduce
the legacy capability flags.

Everything in `requirements.txt` ships wheels, so the install needs no compiler
and no Postgres headers. If `uvicorn` comes back as *not recognized*, the
install failed and put **nothing** in the venv — `pip install` aborts entirely
when any one package fails to build, so a single unbuildable dependency takes
uvicorn down with it. Check that you activated the venv (`where uvicorn` should
point inside `.venv`), then re-read the install output for the first error
rather than the last.

`psycopg2` is deliberately **not** a runtime dependency. It is used only by
`app/legacy.py` for the shadow migration, which is off by default and imports
it lazily. Install it only if you turn that on:

```bash
pip install -r requirements-legacy.txt
```

Tests mock Supabase at the HTTP boundary with `respx` and mint real RS256 tokens
against a generated keypair, so the JWKS verification path is exercised for real
rather than stubbed.

## First-time setup

1. **Use the existing `call_logs` project** — `qizrtmvgcwxuycbpkeua`,
   ap-northeast-2. Auth shares it with Broker Tools' leads schema because the
   Supabase free tier allows only two projects. No new project is created.

   Nothing needs enabling first: the `auth` schema is provisioned in every
   Supabase project from creation, so `auth.users`, `auth.sessions` and the
   rest already exist there, empty. They are visible under **Authentication →
   Users**, not in the Table Editor.

   Being in Seoul rather than Mumbai costs less than it looks. `/v1/introspect`
   verifies locally against cached JWKS and reads everything else from the
   in-memory policy snapshot, so the per-request hot path never crosses
   regions. Only login, refresh, the snapshot refresh every 30 s and the admin
   endpoints pay the hop, and the access-token hook runs inside Postgres.

2. **Apply the SQL**, in order:
   ```
   db/000_preflight.sql        (read-only check -- expect all zeros)
   db/001_schema.sql
   db/002_access_token_hook.sql
   db/003_revoke_sessions.sql
   db/004_permissions.sql      (the identity_* permission tables and functions)
   db/005_seed_permissions.sql (initial roles, catalogues and grants)
   ```
   `001`-`003` add `user_profiles`, alongside the 14 tables the leads schema
   already has, plus `identity_set_updated_at()`, `custom_access_token_hook()`
   and the `citext` extension. `004` adds the `identity_*` tables, the
   `identity_user_attribute_values` view Broker Tools reads desks from, and the
   SQL functions every admin write goes through. `005` seeds them so that, on
   day one, everyone has exactly the access they had before; it also copies
   existing role assignments and Broker Tools desks.

   All of these are safe to re-run. `005` never overwrites a catalogue a
   service has pushed or grants an admin has edited.

   **On an existing project** (dev or prod, which have separate Supabase
   projects): apply `004`, then `005`, then re-apply `002` (it now stamps the
   phone), then deploy. Applying them before the deploy is safe: the running
   version does not read the new tables.

   Both function names are deliberately checked against the live database
   rather than assumed. `call_logs` already has a `public.set_updated_at()`
   with three triggers on it, so the generic name would have been replaced
   underneath them; the `identity_` prefix is why. Before applying to any new
   database, re-run the pre-flight in `db/000_preflight.sql` — a collision is
   silent, not an error.

3. **Register the hook**: Authentication → Hooks → *Customize Access Token (JWT)
   Claims* → Postgres → `public.custom_access_token_hook`.
   Without this step tokens carry no roles, and every user resolves to no
   access — the service fails closed rather than open, but nobody can log in.

4. **Disable email confirmation**: Authentication → Sign In / Providers →
   *Confirm email: off*. Email + password is the only enabled method.

5. **Set the access token lifetime** to 604800 seconds (7 days):
   Authentication → Sessions. This is the authoritative setting;
   `ACCESS_TOKEN_TTL_SECONDS` only mirrors it for reporting. 604800 is the
   maximum the dashboard accepts. Read the revocation note above before
   changing it — it is what bounds how long a removed role stays usable.

6. **Configure the environment** — see `.env.example`. `ALLSET_SERVICE_KEY` must
   match the value set on every consuming service that still uses the shared
   key. Give each service its own key from the console instead (Services →
   Generate key).

7. **Provision the roster.** The nine people in Broker Tools'
   `db/call_logs/002_reference_data.sql` need accounts. Use the admin console
   at `/admin` (sign in as an admin), or `scripts/manage_users.py`, which needs
   only this service running:

   ```bash
   python scripts/manage_users.py list
   python scripts/manage_users.py create jinal@allset.in "Jinal Jadeja" presales
   python scripts/manage_users.py roles khush@allset.in lead_manager viewer
   python scripts/manage_users.py status bhavin@allset.in off
   python scripts/manage_users.py phone jinal@allset.in 9876543210
   ```

   Set a phone for everyone who uses Consultation Agent: it finds each
   person's broker profile by the phone in their token. To fill them in bulk
   from Broker Tools' `team_members`, review and run
   `scripts/backfill_profile_phone.sql` in the SQL editor.

   Each new account is emailed a set-password link and chooses its own
   password. This retires the hardcoded `Allset@2024` seeds.

   **Known gap:** there is still no page for that emailed link to land on.
   Neither admin UI has a `/reset-password` route and this service has no
   `/password/reset-confirm`, so the link redirects to the project's Site URL
   and nothing completes the flow. Supabase's built-in mailer is also
   rate-limited to a few messages an hour and is not meant for production, so a
   burst of invites stops being delivered without reporting an error. Treat the
   invite email as unreliable and set the password yourself.

## Passwords

Three paths, for three different situations:

| Situation | Use |
|---|---|
| You know your password and want a new one | Broker Tools, either the **key icon in the sidebar** once signed in, or **Change your password** on the sign-in screen. Both ask for the current password; no email or OTP involved. |
| Someone has forgotten theirs entirely | `scripts/admin_set_password.py` — runs as you, needs admin or tech, no service-role key. |
| Nobody can log in at all | `scripts/set_password.py` — straight to Supabase with the service-role key. The bootstrap path for the first admin, and the one that still works when this service is down. |

**Password UI lives only in Broker Tools.** The CMS admin panel signs in with the
same unified credentials and has no password screen, deliberately — one place to
change a password rather than two that can drift. That is also why the sign-in
screen carries a change-password flow at all: Broker Tools' own login refuses
anyone without a `broker_tools` role, so a CMS-only user (`editor`, `viewer`,
`manager`) can never reach the in-app version. They open Broker Tools' sign-in
page, change the password there, and go back to the CMS to use it.

The signed-out endpoint is unauthenticated and accepts a password, which buys it
two obligations it must never lose:

- the **same per-email throttle as login**, sharing one budget rather than
  handing an attacker a second allowance for free
- **login's generic failure message**. The form carries an email field, so a
  message specific to the current password would confirm which addresses have
  accounts — something `/v1/auth/login` deliberately never reveals

It grants nobody a capability they lacked: anyone who knows the email and
password can already sign in and change it from inside the app.

```bash
# as an admin, for a colleague who forgot theirs
python scripts/admin_set_password.py darshil@allset.in

# bootstrap, or when you cannot log in yourself
python scripts/set_password.py krips@allset.in
```

Both prompt twice, echo nothing, and never take the password as an argument, so
it stays out of shell history. `admin_set_password.py` goes through
`/v1/admin/users/{id}/set-password`, so the reset is attributable to you in the
service logs; `set_password.py` bypasses the service entirely and leaves no such
record, which is the reason to prefer the first where both would work.

Either way the target is signed out of every session, deliberately — with a
7-day access token, a reset that left the old sessions alive would not have
recovered the account. Hand the new password over privately and have them change
it themselves afterwards.

Changing your own password via `/v1/auth/password/change` re-verifies the
current one first, so a stolen access token on its own cannot lock the owner
out, and it revokes your other sessions on the way through.

## Shadow migration of CMS passwords

The CMS has real users whose passwords are Django PBKDF2 hashes. Supabase stores
bcrypt, so they cannot be imported. Rather than force a reset on everyone,
`app/legacy.py` upgrades accounts on first login: verify against the Django hash
over a **read-only** connection to the CMS's project, then set the same password
in Supabase and stamp `legacy_migrated_at`.

This covers **the CMS only** — Broker Tools had no durable password store to
migrate from.

Gated behind `LEGACY_MIGRATION_ENABLED`. Once every profile row has
`legacy_migrated_at` set, turn the flag off and delete `app/legacy.py`, its
tests, and the `psycopg2-binary` dependency.

Rehearse it against a *copy* of the CMS user table before enabling in production.

One consequence worth knowing: a legacy CMS `admin` maps to the unified `admin`,
which is all-access in **both** apps — so on first login they gain visibility of
every lead. There is no CMS-only administrator role to map them to instead
(`admin` and `tech` are both global; `manager` lacks user management), and
narrowing it would leave the CMS with no administrator.

## Deployment

Cloud Run `asia-south1`, same shape as Broker Tools' FastAPI service. The image
builds the admin console in a Node stage and serves it at `/admin` (and
`/identity/admin` through the Firebase rewrite):

```bash
gcloud run deploy allset-identity \
  --source . --region asia-south1 --project allset-491218 \
  --timeout 60 --concurrency 40 --memory 512Mi
```

Note that Broker Tools' `infra/scripts/deploy.sh` only ever *adds* environment
variables that are missing and never overwrites, so new auth variables must
either be added to its `candidate_keys` list or set by hand in the console.

## Security notes

- `SUPABASE_SERVICE_ROLE_KEY` bypasses RLS and can mint a session for any user.
  It lives only in this service — that is the main reason this is a separate
  deployable rather than a library in each repo.
- `ALLSET_SERVICE_KEY` is compared with `hmac.compare_digest` and **fails closed
  when unset**, so a misconfigured deploy refuses introspection rather than
  accepting anonymous callers.
- Each consumer should have its own key, generated in the console (stored as
  a SHA-256 hash, shown once) or listed in `ALLSET_SERVICE_KEYS`, rather than
  `ALLSET_SERVICE_KEY`, which is shared with ai_service and the CMS backend's
  internal endpoints. A per-consumer key unlocks introspection and its own
  manifest push, and can be revoked alone; a revoked console key stops working
  within 30 s. Onboarding steps are in [`docs/INTEGRATION.md`](docs/INTEGRATION.md).
- The `identity_*` tables, like `user_profiles`, have RLS on with no policies
  and are revoked from `anon` and `authenticated`. `identity_audit_log` is
  append-only even for the service role.
- The admin console sends a strict Content-Security-Policy (`script-src 'self'`,
  `frame-ancestors 'none'`) and keeps tokens out of cookies.
- `user_profiles` has RLS enabled with no policies. Only the service-role key
  reads it, so a leaked anon key reads nothing rather than the whole roster.
- Login reports one generic message for every failure mode, and password reset
  always reports success, so neither endpoint enumerates accounts.
- Login is rate-limited per **email**, not per IP. The CMS's previous throttle
  was IP-keyed, which locked out everyone behind one office NAT together.
