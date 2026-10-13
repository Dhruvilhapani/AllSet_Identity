# Integrating a backend service with AllSet Identity

Your backend never stores passwords or verifies tokens itself. It forwards each
caller's bearer token to AllSet Identity's `POST /v1/introspect`. That call
returns who the user is and what they may do. Your service then allows the
request or answers 401, 403 or 503.

This guide is written for **Consultation Agent**, a backend API. It has its own
capability block, `apps.consultation_agent`, granted to exactly the Broker Tools
roles: anyone who can use Broker Tools can use Consultation Agent. It is a
separate block so the two can diverge later without a change in its code.

## Overview

AllSet Identity is a FastAPI service on Cloud Run (`asia-south1`). It is the
single sign-in for AllSet CMS, Broker Tools and WhatsApp Automation, backed by
Supabase Auth. A person signs in once, and the same access token works across
every AllSet app. Their roles travel inside that token.

```mermaid
sequenceDiagram
    participant F as Frontend
    participant S as Your service (backend API you build)
    participant I as AllSet Identity
    F->>I: 1. Sign in through Identity (directly or via your backend)
    I-->>F: access token, valid 7 days
    F->>S: 2. Your API, Authorization: Bearer <token>
    S->>I: 3. POST /v1/introspect + your key (skipped on a 60 s cache hit)
    I-->>S: active + apps.consultation_agent
    S-->>F: 4. 200, or 401 / 403 / 503
```

Step 1 goes straight to Identity or through your backend; see
[Signing users in](#signing-users-in). Steps 2 to 4 are what you build.

| Responsibility | Owned by |
| --- | --- |
| Sign-in, passwords, sessions, token signing | Identity |
| Roles and what each role grants | Identity admins, in the admin console's permission matrix |
| Declaring what your service protects (`identity-manifest.json`) | Your service, pushed on deploy |
| Creating users, changing roles, deactivating | Identity admins (admin console or CLI) |
| Reading the `Authorization` header and calling introspect | Your service |
| Caching introspect results for 60 seconds | Your service |
| Mapping results to 401 / 403 / 503 | Your service |
| Applying lead-ownership rules to your own data | Your service |

The frontend that calls your API must send the user's Identity access token as
`Authorization: Bearer <token>`. That token comes from signing in through
Identity.

## Before you start: access you receive

You need three things from the Identity owner: the service URL, your own service
key, and test accounts. You need no Supabase credentials, no GCP access to the
Identity project and no admin role.

| You receive | Per environment | How it reaches you |
| --- | --- | --- |
| `IDENTITY_SERVICE_URL` | Yes, dev and prod differ | Message; it is not a secret |
| Your service key | Yes, a different key per environment | A Secret Manager secret in your service's GCP project, readable by your Cloud Run runtime service account |
| Test accounts in dev | Dev only | Email plus a password handed over privately |

Known URL: `https://allset-identity-gefxdgwgyq-el.a.run.app`, taken from
WhatsApp Automation's config. Confirm with the Identity owner which environment
it is, and get the prod URL.

Your key is yours alone. It unlocks only `/v1/introspect`,
`/v1/introspect/health` and pushing your own service's manifest, and it can be
revoked without touching any other service. Never paste it in chat, email, a
ticket or a commit.

**Do not ask for, and do not accept:**

- `SUPABASE_SERVICE_ROLE_KEY` or `SUPABASE_ANON_KEY`. The service-role key can
  act as any user and reads every lead in the shared project.
- The shared `ALLSET_SERVICE_KEY`. It also unlocks ai_service and the CMS
  backend's internal endpoints. If your config holds it today under another
  name, swap it for your own key when that arrives.
- An `admin` or `tech` role just to test. Use the dev test accounts.

### What the Identity owner does

- [ ] In the admin console (`/admin` on each environment), register your
      service under Services if it is new, and grant its permissions to the
      right roles under Permissions. Until a role holds your `app.use`, every
      sign-in to your service fails with "no access"
- [ ] Generate a key for your service on its Services page, once per
      environment. The console shows it once; it is stored only as a hash
- [ ] (Older alternative: add `<service>:<key>` to `ALLSET_SERVICE_KEYS` in
      `.env.dev` / `.env.prod`, run `./scripts/setup_gcp_secrets.sh`, redeploy.)
- [ ] Store the same key as a secret in your service's GCP project; grant your
      runtime service account `roles/secretmanager.secretAccessor` on it
- [ ] If your browser calls Identity directly, add your frontend's origin to
      Identity's `CORS_ORIGINS` and redeploy (see Signing users in)
- [ ] Create dev test accounts (see Testing) with `scripts/manage_users.py`
- [ ] Send you the URL for each environment

CORS matters only if your frontend calls Identity straight from the browser;
server-to-server calls are not subject to it. Identity's Cloud Run service is
public (`--allow-unauthenticated`), so no IAM invoker grant is needed either way.

## Configuration

Your service needs four environment variables. The first two are required, and
your service must refuse to authenticate anyone when either is missing.

| Variable | Required | Default | Notes |
| --- | --- | --- | --- |
| `IDENTITY_SERVICE_URL` | Yes | none | Origin only, e.g. `https://allset-identity-….run.app`. No trailing slash, no `/v1`. |
| `IDENTITY_SERVICE_KEY` | Yes | none | Your own key. Bind it from Secret Manager, never from a plain env file in the repo. |
| `IDENTITY_TIMEOUT_SECONDS` | No | `2` | Introspect does no I/O and answers in milliseconds; 2 s matches CMS and Broker Tools. |
| `IDENTITY_CACHE_TTL` | No | `60` | Seconds to cache an introspect result. Lower means revocations bite sooner but more calls. |

Use the name `IDENTITY_SERVICE_KEY`, not `ALLSET_SERVICE_KEY`. Other repos use
`ALLSET_SERVICE_KEY` for the shared key, and reusing the name invites someone to
paste the wrong value.

On Cloud Run, bind the key with
`--set-secrets=IDENTITY_SERVICE_KEY=<secret-name>:latest`.

For local development, point `IDENTITY_SERVICE_URL` at the dev Identity URL with
your dev key. Running Identity locally needs Supabase credentials you will not
have.

## The introspect contract

Introspect always answers HTTP 200 for any token, good or bad. A non-200 means
Identity or your key is broken, never that the user is. Keep those two apart:
confusing them either locks everyone out during a blip or lets anyone in.

### Request

```http
POST {IDENTITY_SERVICE_URL}/v1/introspect
X-Allset-Service-Key: <IDENTITY_SERVICE_KEY>
Content-Type: application/json

{"token": "<the user's access token, without the 'Bearer ' prefix>"}
```

### Response for a valid token

```json
{
  "active": true,
  "user_id": "6f1c2a9e-0b7d-4c3e-9a51-2d8e7f4b1c06",
  "email": "someone@allset.in",
  "full_name": "Some One",
  "phone": "+91 98765 43210",
  "roles": ["presales", "viewer"],
  "role_labels": ["Pre-sales", "Viewer"],
  "is_active": true,
  "apps": {
    "broker_tools": {
      "access": true,
      "primary_role": "presales",
      "permissions": {
        "lead": {"create": ["all"], "read": ["own_presales"], "update": ["own_presales"]},
        "lead_note": {"create": ["via_lead"], "read": ["via_lead"], "update": ["via_lead"]},
        "report": {"read": ["own", "own_team_aggregate"]}
      },
      "attributes": {"desk": "presales"},
      "unrestricted_leads": false,
      "own_presales": true,
      "own_sales": false
    },
    "consultation_agent": {
      "access": true,
      "primary_role": "presales",
      "permissions": {
        "consultation_session": {"create": ["all"], "read": ["own"], "update": ["own"], "analyze": ["all"]},
        "buyer": {"create": ["all"], "read": ["all"], "update": ["all"]}
      },
      "attributes": {}
    },
    "cms": {"access": true, "primary_role": "viewer", "permissions": {"property": {"read": ["all"]}}, "…": "…"},
    "wa_automation": {"access": true, "…": "…"},
    "identity": {"access": false, "…": "…"}
  }
}
```

The `permissions` lists are shortened here. There is one block per registered
service, and each block's `permissions` lists every action that user may take
in that service. The `unrestricted_leads` / `own_*` and CMS `can_*` flags are
**legacy**: Identity keeps emitting them until every service has moved to
`permissions`, then removes them. Do not start reading them.

`user_id` is the stable Supabase UUID. Key your own records on it rather than on
email.

### Response for an invalid, expired or deactivated token

```json
{"active": false, "reason": "Signature has expired.", "roles": [], "apps": {"cms": {"access": false, "…": "…"}, "broker_tools": {"access": false, "…": "…"}, "consultation_agent": {"access": false, "primary_role": null}}}
```

`reason` is for your logs only. Do not branch on it or show it to users; its
wording is not part of the contract. A deactivated user's response may also
carry `user_id` and `email`, so check `active` first, always.

### What each outcome means for your service

| Identity returns | Meaning | Your service answers |
| --- | --- | --- |
| 200, `active: true`, `apps.consultation_agent.access: true` | Allowed | Handle the request |
| 200, `active: true`, `apps.consultation_agent.access: false` | Signed in, but no Broker Tools role (e.g. a CMS-only `editor`) | **403** |
| 200, `active: false` | Token invalid, expired, or account deactivated | **401** |
| 401 | Your service key is wrong or missing: a deploy problem, not the user's | **503**, and log an error |
| Any other status, timeout, connection error, bad JSON | Identity is down or broken | **503**. Never let the request through |

No `Authorization` header, or not `Bearer <token>`: answer 401 yourself without
calling Identity.

### Health check

`GET {IDENTITY_SERVICE_URL}/v1/introspect/health` with your key header returns
`{"status": "ok"}` and 200, or 401 if the key is wrong. Call it at startup or in
a deploy smoke test to catch a bad key before users do.

Use the `/v1/...` paths. The same routes also answer under `/identity/v1/...`
for browsers going through Firebase Hosting; backends do not need that prefix.

## Implementation

One module talks to Identity, and one dependency guards every route. The
reference below is Python (FastAPI with httpx), like the other AllSet services.
It was run against the real Identity app for all eight outcomes in the contract
table. On another stack, port the same behaviour.

1. Add the four environment variables from Configuration.
2. Copy `identity_client.py` below into your service.
3. Put `Depends(current_user)` on every route that needs a signed-in user.
4. Apply the Broker Tools lead flags to your own queries (see Authorisation).
5. Call the health endpoint in your deploy smoke test.

### identity_client.py

```python
"""AllSet Identity client: the one place this service talks to Identity."""

from __future__ import annotations

import hashlib
import logging
import os
import time

import httpx
from fastapi import Header, HTTPException

log = logging.getLogger(__name__)

IDENTITY_SERVICE_URL = os.environ.get("IDENTITY_SERVICE_URL", "").rstrip("/")
IDENTITY_SERVICE_KEY = os.environ.get("IDENTITY_SERVICE_KEY", "")
IDENTITY_TIMEOUT_SECONDS = float(os.environ.get("IDENTITY_TIMEOUT_SECONDS", "2"))
IDENTITY_CACHE_TTL = int(os.environ.get("IDENTITY_CACHE_TTL", "60"))
_CACHE_MAX_ENTRIES = 1024

_client = httpx.AsyncClient(timeout=IDENTITY_TIMEOUT_SECONDS)
_cache: dict[str, tuple[dict, float]] = {}  # sha256(token) -> (payload, expires_at)


class IdentityUnavailable(Exception):
    """Identity could not give an answer. Callers must fail closed (503)."""


async def introspect(token: str) -> dict:
    # The token is a credential: hash it rather than using it as a cache key.
    key = hashlib.sha256(token.encode()).hexdigest()
    hit = _cache.get(key)
    if hit and hit[1] > time.monotonic():
        return hit[0]

    if not IDENTITY_SERVICE_URL or not IDENTITY_SERVICE_KEY:
        raise IdentityUnavailable("identity is not configured")
    try:
        resp = await _client.post(
            f"{IDENTITY_SERVICE_URL}/v1/introspect",
            json={"token": token},
            headers={"X-Allset-Service-Key": IDENTITY_SERVICE_KEY},
        )
    except httpx.HTTPError as exc:
        raise IdentityUnavailable("identity unreachable") from exc
    if resp.status_code == 401:
        log.error("identity rejected our service key")  # a deploy problem, not the user's
        raise IdentityUnavailable("service key rejected")
    if resp.status_code != 200:
        raise IdentityUnavailable(f"identity returned {resp.status_code}")
    try:
        payload = resp.json()
    except ValueError as exc:
        raise IdentityUnavailable("identity returned invalid JSON") from exc

    if len(_cache) >= _CACHE_MAX_ENTRIES:
        _cache.clear()
    _cache[key] = (payload, time.monotonic() + IDENTITY_CACHE_TTL)
    return payload


async def current_user(authorization: str | None = Header(default=None)) -> dict:
    """FastAPI dependency: the introspect payload of a caller allowed in."""
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(401, "Missing or invalid Authorization header.",
                            headers={"WWW-Authenticate": "Bearer"})
    try:
        payload = await introspect(token.strip())
    except IdentityUnavailable:
        log.exception("identity unavailable; failing closed")
        raise HTTPException(503, "Authentication service unavailable.") from None
    if not payload.get("active"):
        raise HTTPException(401, "Invalid or expired token.",
                            headers={"WWW-Authenticate": "Bearer"})
    if not payload.get("apps", {}).get("consultation_agent", {}).get("access"):
        raise HTTPException(403, "Your account does not have access to this service.")
    return payload
```

### Using it on a route

```python
from fastapi import APIRouter, Depends

from .identity_client import current_user

router = APIRouter()


@router.get("/things")
async def list_things(user: dict = Depends(current_user)):
    bt = user["apps"]["broker_tools"]
    ...  # lead scope from bt, see Authorisation
```

### Why it is built this way

- **The 60 s cache** keeps most requests from leaving your process. It is per
  process, which is fine; use Redis instead if you already run it.
- **The cache key is a SHA-256 of the token**, never the token itself, so a
  cache dump leaks no credentials.
- **Every failure to get an answer becomes 503**, never 401 and never a pass. A
  401 would bounce users to a sign-in that cannot fix an outage.
- **The 403 check is on `apps.consultation_agent.access`**, not on role names,
  so a later change to who may use your service needs no code change here.

## Authorisation

Decide everything from your own block, `apps.<your service>`: `access` for
"may use the service at all", and `permissions` for what they may do and to
which rows. Never decide from role names: roles are admin-editable data, and
what each one grants changes in the admin console without a deploy.

### Permissions and scopes

`permissions` maps a resource to its actions, and each action to the scopes
granted:

- **An action that is absent is denied.** There is no "default allow".
- **`["all"]`** means every row.
- **Named scopes** (`own`, `own_presales`, `assigned`, …) each name a row filter
  your service implements. Several scopes combine with OR.
- **An unknown scope name matches nothing**, and an empty filter is a denial,
  never an unfiltered query.

`admin` is a superuser: every action at `all` in every service. Everyone else
gets exactly what their roles are granted in the matrix.

Copy this helper (adapt it to your stack) rather than writing ad-hoc checks:

```python
def scopes(user: dict, resource: str, action: str) -> list[str]:
    return user["apps"]["consultation_agent"]["permissions"].get(resource, {}).get(action, [])


def require(user: dict, resource: str, action: str) -> list[str]:
    granted = scopes(user, resource, action)
    if not granted:
        raise HTTPException(403, "You do not have permission to do that.")
    return granted


def visible(granted: list[str], row, handlers) -> bool:
    if "all" in granted:
        return True
    return any(handlers[name](row) for name in granted if name in handlers)
```

Add a test that every scope your manifest declares has a handler in your code.

### Telling Identity what you protect: the manifest

Your service declares its resources, actions and scopes in
`identity-manifest.json` at the root of your repo, next to the code that
enforces them. Consultation Agent's (also in Identity's seed,
`app/permissions/seed/services/consultation_agent.json`):

```json
{
  "service": "consultation_agent",
  "resources": {
    "consultation_session": {"label": "Consultation sessions",
                             "actions": ["create", "read", "update", "analyze"],
                             "scopes": {"own": "Their own sessions"}},
    "buyer": {"label": "Buyers", "actions": ["read", "create", "update"]}
  }
}
```

Every resource also gets the scope `all`, and every service the resource `app`
with action `use` (that is `access`); never declare those. Push the file after
each deploy, with your own key:

```http
PUT {IDENTITY_SERVICE_URL}/v1/services/manifest
X-Allset-Service-Key: <IDENTITY_SERVICE_KEY>
Content-Type: application/json

<the contents of identity-manifest.json>
```

A push adds what is new (granted to nobody but `admin` until someone ticks it
in the console), relabels what changed, and **retires** anything missing; it
never grants or removes anyone's access. The shared `ALLSET_SERVICE_KEY` cannot
push, because it identifies no service.

### Matching the person to your own records

Key your records on `user_id`. Consultation Agent is the one exception: it finds
the signed-in person's `brokers` document by `phone` (top level), matched on
the last 10 digits, because it is passed through exactly as an admin typed it
(`+91 98765 43210`, `9876543210`). It is empty when the profile has no phone.
Admins set it in the console or with `scripts/manage_users.py phone`. Identity
reads it from its roster, so a change reaches you within about 90 seconds.

### Attributes

Some services declare per-user attributes in their manifest; admins set the
values in the console, and they arrive in `apps.<service>.attributes`. Broker
Tools' `desk` (presales or sales) is one. Broker Tools also reads every member's
desk in SQL, from the `identity_user_attribute_values` view in the shared
call_logs database.

`GET {IDENTITY_SERVICE_URL}/v1/auth/roles` needs no auth and returns the roles
admins have defined, with what each grants on its own, if you want a reference
in your UI.

## Signing users in

Consultation Agent's backend proxies sign-in (decided 2026-10-12): its
frontend posts email and password to its own backend, which calls Identity
server-to-server, so Identity needs no CORS change. The browser path is
described too, for other services.

| | Your backend proxies sign-in | Your browser calls Identity |
| --- | --- | --- |
| Who calls `/v1/auth/login` | Your backend | Your frontend |
| URL | `{IDENTITY_SERVICE_URL}/v1/auth/login` | `/identity/v1/auth/login` on the same Firebase Hosting site, or Identity's own URL |
| Change on Identity's side | None | Add your frontend's origin to `CORS_ORIGINS` and redeploy, unless it is served from the same Firebase Hosting site, which already routes `/identity/**` to Identity |
| Same pattern as | WhatsApp Automation | CMS admin panel, Broker Tools web |

No service key is needed on these endpoints. Tokens travel in the
`Authorization` header; Identity uses no cookies.

### `POST /v1/auth/login`

Request body: `{"email": "...", "password": "..."}`. The response carries the
tokens plus the same `user` object introspect returns, so you can decide access
without a second call:

```json
{
  "access_token": "<JWT>",
  "refresh_token": "<opaque>",
  "token_type": "bearer",
  "expires_in": 604800,
  "user": {"active": true, "user_id": "…", "roles": ["presales"], "apps": {"consultation_agent": {"access": true, "…": "…"}, "…": "…"}}
}
```

A 200 only proves the password. Check `user.apps.consultation_agent.access`
before treating it as a successful sign-in, and show "no access" when it is
false.

| Identity returns | Meaning | Your service answers |
| --- | --- | --- |
| 200, `consultation_agent.access: false` | Right password, no Broker Tools role | 403, "no access" |
| 401 | Wrong email or password; one message for every case, by design | 401, "Invalid email or password" |
| 403 | Account deactivated | 403 |
| 422 | Malformed email or empty password | 401, same generic message |
| 429 | Over 10 attempts per email per minute, a budget shared by every AllSet app | 429, "try again shortly" |
| 5xx, timeout | Identity is broken | 503 |

### Refresh and logout

- `POST /v1/auth/refresh` with `{"refresh_token": "..."}` returns the same shape
  as login. 401 means the refresh token is invalid or revoked; 403 means the
  account was deactivated.
- `POST /v1/auth/logout` with `Authorization: Bearer <token>` returns 204. It
  ends the session, but the access token keeps passing introspect until it
  expires, so also drop it from your cache.

If your backend proxies sign-in, never log the request body or the tokens in the
response.

## Gotchas

The biggest surprise is that removing someone's access is not immediate. Access
tokens live for 7 days, and an issued token cannot be recalled.

- **Revocation lag of up to 7 days plus your cache TTL.** Roles and active
  status are stamped into the token when it is issued. A role change or
  deactivation stops new tokens, but a token already in a browser keeps its old
  roles until it expires. If your service exposes something that must be cut
  off at once, raise it with the Identity owner before launch.
- **Do not decode or verify the JWT yourself**, even though the claims are
  readable. Their layout is internal to Identity and the capability rules live
  there. Introspect is the contract.
- **Never log the `Authorization` header, the token or your service key.** Log
  `user_id` when you need to trace a user.
- **An expired token gets a 401 from you.** The user then signs in again, or
  your client refreshes if it holds a refresh token.
- **The token goes in the JSON body to Identity**, not in a header. An empty
  `token` gets a 422 from Identity, which `current_user` avoids by rejecting it
  first.
- **Introspect is not rate limited, but cache anyway.** It does no database or
  Supabase call, so it is fast, yet 60 s of caching removes most network hops.

## Testing and go-live

Test every row of the contract table twice: once in unit tests with Identity
stubbed, once in dev against the real Identity.

### Unit tests

Stub Identity at the HTTP boundary (`respx` for httpx), the way CMS, Broker
Tools and WhatsApp Automation do. Cover each outcome:

- `active: true` with `consultation_agent.access: true` returns 200
- `active: true` with `consultation_agent.access: false` returns 403
- `active: false` returns 401
- No or malformed `Authorization` header returns 401 without calling Identity
- Identity answers 401 (bad key) returns 503
- Identity answers 500, times out or is unreachable returns 503
- A second request with the same token inside 60 s makes no Identity call
- If your backend proxies sign-in: each row of the login table above

### Dev test accounts

Ask the Identity owner to create these in dev:

| Account | Roles | Expected in your service |
| --- | --- | --- |
| Lead manager test | `lead_manager` | 200, all leads |
| Pre-sales test | `presales` | 200, only leads where they are presales owner |
| Sales test | `sales` | 200, only leads where they are sales owner |
| CMS-only test | `viewer` | 403 |

A deactivated account cannot sign in to get a fresh token. Test the 401 path
with an expired or garbage token instead.

### Manual checks against dev

Check your key:

```bash
curl -i "$IDENTITY_SERVICE_URL/v1/introspect/health" -H "X-Allset-Service-Key: $IDENTITY_SERVICE_KEY"
```

Get a token for a test account and copy `access_token` from the response.
Sign-in allows 10 attempts per email per minute.

```bash
curl -s -X POST "$IDENTITY_SERVICE_URL/v1/auth/login" -H "Content-Type: application/json" -d '{"email": "<test account>", "password": "<password>"}'
```

Call your own service with it:

```bash
curl -i "$YOUR_SERVICE_URL/things" -H "Authorization: Bearer $TOKEN"
```

### Go-live checklist

- [ ] Identity with the `consultation_agent` block is deployed to prod
- [ ] Prod key created by the Identity owner and bound from Secret Manager as
      `IDENTITY_SERVICE_KEY`; the shared key is gone from your config
- [ ] `IDENTITY_SERVICE_URL` points at prod Identity
- [ ] If your browser calls Identity directly, your prod origin is in Identity's `CORS_ORIGINS`
- [ ] Health check returns 200 with the prod key, in the deploy smoke test
- [ ] Each dev test account gets the expected result
- [ ] With `IDENTITY_SERVICE_URL` pointed at a dead host in dev, your service answers 503, not 200 or 401
- [ ] No token, `Authorization` header, password or key appears in your logs
- [ ] Real users of your service hold a Broker Tools role in prod (Identity owner)
