# AllSet Identity

Unified authentication and role-based access control for **AllSet_CMS** and
**AllSet_Broker_Tools**. One identity per person, one password, one role set
spanning both apps, and one place to grant or revoke access.

Before this service, each app ran its own Django SimpleJWT auth with its own
role vocabulary (`admin/editor/agent/viewer` vs `admin/manager/presales/sales`),
so anyone working in both had two accounts. Broker Tools was worse off: its user
table lived on an ephemeral SQLite file that was re-seeded from hardcoded
passwords on every container start, so password changes never persisted and the
seeded defaults were effectively permanent.

## Roles

A user holds a **set** of roles, and capabilities are the **union** across them.
Every role is single-app except `admin` and `tech`, which are deliberately
permission-identical global roles — the distinction is organisational and shows
up in audit trails.

| Role | Label | CMS | Broker Tools |
|---|---|---|---|
| `admin` | Admin | Full, incl. delete + user management | All leads |
| `tech` | Tech | Full — identical to admin | All leads |
| `manager` | Manager | Add/edit/publish/upload/SEO | — |
| `editor` | Editor | Same as manager | — |
| `viewer` | Viewer | Read-only | — |
| `lead_manager` | Lead Manager | — | All leads |
| `presales` | Pre-sales | — | Own leads (`fk_presales_owner`) |
| `sales` | Sales | — | Own leads (`fk_sales_owner`) |

So `{sales, viewer}` means own-leads in Broker Tools plus read-only CMS, and
`{manager, sales}` means CMS editor-level plus own-leads — not all leads, which
is why `manager` and `lead_manager` are separate roles.

Consultation Agent has its own `consultation_agent` capability block, carrying
only `access` and `primary_role`. It is granted to exactly the Broker Tools
roles, and is a separate block so the two can diverge later without a code
change in Consultation Agent. It has no roles of its own.

Two rules are enforced both here and as Postgres CHECK constraints, because the
role set is the one piece of state that must never be wrong:

- every role must be in the vocabulary above
- **at most one of `presales`/`sales`** — `team_members.role` over in `call_logs`
  is single-valued and drives `call_sync.py`'s lead-owner auto-assignment

An **empty** role set is legal and means "the account exists but reaches
nothing" — the clean offboarding state, distinct from `is_active = false`, which
blocks login outright.

[`app/capabilities.py`](app/capabilities.py) is the single source of truth for
all of the above. Nothing else should encode role rules.

## How it fits together

```
  admin_ui (CMS)          web (Broker Tools)
        │                        │
        └──── POST /v1/auth/login ────┐
                                      ▼
                            ┌──────────────────┐
                            │ AllSet Identity  │──── Supabase Auth
                            │    (this repo)   │     (call_logs project)
                            └──────────────────┘
                                      ▲
        ┌────── POST /v1/introspect ───┘
        │
  CMS backend · Broker Tools API · Broker Tools FastAPI · ai_service
```

`/v1/introspect` sits on the hot path — every authenticated request in both apps
goes through it — so it is built to do **no I/O at all**:

1. A Supabase **Custom Access Token Hook** (`db/002_access_token_hook.sql`)
   stamps the user's roles into every JWT it issues.
2. This service verifies the signature against an **in-memory JWKS cache**,
   refetched only when a `kid` is unrecognised.
3. Roles are read from the token's claim. No database query, no Supabase call.
4. Consumers cache the response for 60s keyed on a hash of the token.

Broker Tools' FastAPI service actually gets *faster*: it currently forwards every
request to Django's `/api/auth/verify/`, and that hop is replaced, not added to.

**Revocation.** Because roles ride in the JWT and are cached for 60s, a role
change takes up to 60s plus the remaining access-token lifetime to bite. Every
role change, deactivation and admin password reset revokes the user's sessions,
which kills their refresh tokens immediately — but it cannot recall an access
token already sitting in a browser.

That revocation goes through the `identity_revoke_user_sessions` RPC, not a
GoTrue endpoint. GoTrue has no admin logout: `POST /admin/users/{id}/logout`
does not exist, and `POST /logout?scope=global` needs the user's own access
token. Both verified against a live project. If `db/003_revoke_sessions.sql`
has not been applied, role changes fail loudly rather than reporting success
while the old role keeps working.

That last point — an issued access token cannot be recalled — now matters a great
deal more than it used to. The access-token lifetime was raised from 30 minutes
to **7 days** so people stop being signed out several times a day, and the
consequence is that **a removed role or a deactivated account can keep working
for up to 7 days**.

Be precise about why, because it is easy to assume otherwise: both `roles` and
`is_active` are read from the token's claims, since `/v1/introspect` does no I/O
by design. So nothing in this service can recall an access token that has already
been issued — not a role change, not deactivation, and not a password reset.
Those all revoke *sessions*, which stops the holder getting a **new** token; the
one already in their browser keeps working until it expires.

**Offboarding is therefore not immediate.** Clear their roles and deactivate them
as usual, and understand that it takes effect when their current access token
expires. The only way to invalidate live tokens sooner is to rotate the Supabase
project's JWT signing key, which signs every user out at once.

7 days is Supabase's ceiling for this setting, not a chosen number — 604800
seconds is the maximum the dashboard accepts. The alternative that avoids the
tradeoff entirely is a short access token plus a refresh loop in the clients;
the CMS admin panel already has one (`src/api/client.ts` retries on 401), Broker
Tools' web app does not. If the revocation window ever becomes a problem, wiring
refresh into Broker Tools and dropping this back to an hour is the fix.

## Endpoints

**Browser-facing** — called by both admin UIs:

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/auth/login` | Email + password. Returns tokens plus the same payload `/v1/introspect` gives, so a client can render without a second call. |
| POST | `/v1/auth/refresh` | Refuses a deactivated account. |
| POST | `/v1/auth/logout` | |
| GET | `/v1/auth/me` | |
| POST | `/v1/auth/password/change` | Self-service, signed in. Re-verifies the current password first, then revokes the user's other sessions. |
| POST | `/v1/auth/password/change-with-credentials` | Self-service, **not** signed in — email + current password + new. Behind login's per-email throttle, and answers with login's generic message. |
| POST | `/v1/auth/password/reset-request` | Always reports success, so it cannot enumerate the roster. Nothing handles the emailed link yet — see below. |
| GET | `/v1/auth/roles` | The role vocabulary, for populating role pickers. |

**Service-facing** — requires `X-Allset-Service-Key`:

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/introspect` | Always HTTP 200. An invalid token is `{"active": false}`, never an error status — see below. |
| GET | `/v1/introspect/health` | Lets a consumer check its service key without a user token. |

**Admin** — requires `admin` or `tech`:

| Method | Path | Notes |
|---|---|---|
| GET, POST | `/v1/admin/users` | |
| PATCH | `/v1/admin/users/{id}/roles` | Revokes the target's sessions. |
| PATCH | `/v1/admin/users/{id}/status` | Revokes the target's sessions on deactivation. |
| POST | `/v1/admin/users/{id}/reset-password` | Emails a set-password link. |
| POST | `/v1/admin/users/{id}/set-password` | Sets a password outright, no old password needed. Revokes the target's sessions. |

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
pytest -q          # 206 tests, no network access needed
ruff check .
```

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
   verifies locally against cached JWKS and reads roles from the token, so the
   per-request hot path never crosses regions. Only login, refresh and the
   admin endpoints pay the hop, and the access-token hook runs inside Postgres.

2. **Apply the SQL**, in order:
   ```
   db/000_preflight.sql        (read-only check -- expect all zeros)
   db/001_schema.sql
   db/002_access_token_hook.sql
   db/003_revoke_sessions.sql
   ```
   This adds exactly one table to `public` — `user_profiles`, alongside the 14
   the leads schema already has — plus `identity_set_updated_at()`,
   `custom_access_token_hook()` and the `citext` extension.

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
   match the value set on every consuming service.

7. **Provision the roster.** The nine people in Broker Tools'
   `db/call_logs/002_reference_data.sql` need accounts. Either use Users &
   Roles in the CMS admin panel, or `scripts/manage_users.py`, which needs only
   this service running:

   ```bash
   python scripts/manage_users.py list
   python scripts/manage_users.py create jinal@allset.in "Jinal Jadeja" presales
   python scripts/manage_users.py roles khush@allset.in lead_manager viewer
   python scripts/manage_users.py status bhavin@allset.in off
   ```

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

Cloud Run `asia-south1`, same shape as Broker Tools' FastAPI service:

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
- New consumers get their own key in `ALLSET_SERVICE_KEYS` rather than
  `ALLSET_SERVICE_KEY`, which is shared with ai_service and the CMS backend's
  internal endpoints. A per-consumer key unlocks only introspection and can be
  revoked alone.
- `user_profiles` has RLS enabled with no policies. Only the service-role key
  reads it, so a leaked anon key reads nothing rather than the whole roster.
- Login reports one generic message for every failure mode, and password reset
  always reports success, so neither endpoint enumerates accounts.
- Login is rate-limited per **email**, not per IP. The CMS's previous throttle
  was IP-keyed, which locked out everyone behind one office NAT together.
