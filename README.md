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
                            │    (this repo)   │     (identity project)
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
change takes up to 60s plus the remaining access-token lifetime to bite. Two
mitigations: access tokens are 30 minutes (down from 8 hours in both projects),
and every role change or deactivation calls Supabase's global sign-out so
refresh tokens die immediately.

## Endpoints

**Browser-facing** — called by both admin UIs:

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/auth/login` | Email + password. Returns tokens plus the same payload `/v1/introspect` gives, so a client can render without a second call. |
| POST | `/v1/auth/refresh` | Refuses a deactivated account. |
| POST | `/v1/auth/logout` | |
| GET | `/v1/auth/me` | |
| POST | `/v1/auth/password/change` | Re-verifies the current password first. |
| POST | `/v1/auth/password/reset-request` | Always reports success, so it cannot enumerate the roster. |
| GET | `/v1/auth/roles` | The role vocabulary, for populating role pickers. |

**Service-facing** — requires `X-Allset-Service-Key`:

| Method | Path | Notes |
|---|---|---|
| POST | `/v1/introspect` | Always HTTP 200. An invalid token is `{"active": false}`, never an error status — see below. |
| GET | `/v1/introspect/health` | Lets a consumer check its service key without a user token. |

**Admin** — requires `admin` or `tech`:

| Method | Path |
|---|---|
| GET, POST | `/v1/admin/users` |
| PATCH | `/v1/admin/users/{id}/roles` |
| PATCH | `/v1/admin/users/{id}/status` |
| POST | `/v1/admin/users/{id}/reset-password` |

### The introspect status-code contract

`/v1/introspect` returns **200 with `active: false`** for a token that is
invalid, expired or deactivated, and a **5xx** only when the service itself is
broken. Consumers must treat these differently: the first is a routine 401 for
the end user, the second must fail closed. Collapsing them would either lock
everyone out during a blip or let anyone in.

## Local development

```bash
python -m venv .venv && . .venv/Scripts/activate   # Windows
pip install -r requirements-dev.txt
cp .env.example .env        # then fill in the Supabase values
uvicorn app.main:app --reload --port 8100
```

The pinned versions target **Python 3.11**, matching the Docker image and Broker
Tools' services. On a newer interpreter some pins have no wheels — install
unpinned for local work, or use a 3.11 venv.

```bash
pytest -q          # 154 tests, no network access needed
ruff check .
```

Tests mock Supabase at the HTTP boundary with `respx` and mint real RS256 tokens
against a generated keypair, so the JWKS verification path is exercised for real
rather than stubbed.

## First-time setup

1. **Create the Supabase project.** A *new, dedicated* project — not the CMS's
   analytics project and not `call_logs`. Provision it in **ap-south-1
   (Mumbai)** so it is colocated with Cloud Run `asia-south1`; Broker Tools
   currently pays ~120ms per round trip reaching Seoul.

2. **Apply the SQL**, in order:
   ```
   db/001_schema.sql
   db/002_access_token_hook.sql
   ```

3. **Register the hook**: Authentication → Hooks → *Customize Access Token (JWT)
   Claims* → Postgres → `public.custom_access_token_hook`.
   Without this step tokens carry no roles, and every user resolves to no
   access — the service fails closed rather than open, but nobody can log in.

4. **Disable email confirmation**: Authentication → Sign In / Providers →
   *Confirm email: off*. Email + password is the only enabled method.

5. **Set the access token lifetime** to 30 minutes: Authentication → Sessions.

6. **Configure the environment** — see `.env.example`. `ALLSET_SERVICE_KEY` must
   match the value set on every consuming service.

7. **Provision the roster.** The nine people in Broker Tools'
   `db/call_logs/002_reference_data.sql` get accounts via
   `POST /v1/admin/users`, which emails each a set-password link. This retires
   the hardcoded `Allset@2024` seeds.

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
- `user_profiles` has RLS enabled with no policies. Only the service-role key
  reads it, so a leaked anon key reads nothing rather than the whole roster.
- Login reports one generic message for every failure mode, and password reset
  always reports success, so neither endpoint enumerates accounts.
- Login is rate-limited per **email**, not per IP. The CMS's previous throttle
  was IP-keyed, which locked out everyone behind one office NAT together.
