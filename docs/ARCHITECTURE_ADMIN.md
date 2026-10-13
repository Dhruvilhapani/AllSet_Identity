# Admin console and dynamic permissions

Identity is the one place where admins manage users, roles and what each role
may do in every AllSet service. The rules live in database tables instead of
`app/capabilities.py`, so a new role, permission or service is a data change,
not a deploy. Admins work in a console served by this service at `/admin`.

This document is the design and the record of decisions. Update it in the same
PR as any change to the model.

## Contents

- [Why](#why)
- [Decisions](#decisions)
- [The model](#the-model)
- [Database](#database)
- [Resolving permissions on the hot path](#resolving-permissions-on-the-hot-path)
- [The introspect payload](#the-introspect-payload)
- [Registering a service](#registering-a-service)
- [Record rules: the scope catalogue](#record-rules-the-scope-catalogue)
- [Enforcing scopes in a service](#enforcing-scopes-in-a-service)
- [Admin API](#admin-api)
- [Admin console](#admin-console)
- [Consumer migration](#consumer-migration)
- [Security, audit and revocation](#security-audit-and-revocation)
- [Rollout](#rollout)
- [Known limits](#known-limits)

## Why

| Problem | Where | Effect |
| --- | --- | --- |
| The 8 roles and what they grant were code | `app/capabilities.py`, the `roles_valid` CHECK in `db/001_schema.sql` | Every new role or permission was a code change, a SQL migration and a deploy |
| Capabilities were app-wide flags | `apps.cms.can_*`, `apps.broker_tools.unrestricted_leads` / `own_*` | No way to say "sales may read leads but not delete them" without a new flag |
| Services compared role names | Broker Tools `IsAdminRole`; WA Automation `ADMIN_ROLES`, `FULL_VISIBILITY_ROLES` | The copies disagreed with Identity: WA kept `tech` out of admin routes and expected a `manager` role Broker Tools never reports |
| Row rules lived only in each service | Broker Tools `_own_lead_filter`; WA's lead-visibility helpers | Nobody could see or change who sees which rows without reading code |
| The only admin screen was partial | CMS `admin_ui` Users & Roles | Users and roles only, and it listed the CMS's local rows, not Identity's |
| Service keys were environment variables | `ALLSET_SERVICE_KEY`, `ALLSET_SERVICE_KEYS` | Issuing or revoking a key needed Secret Manager and a redeploy |
| A removed role kept working for up to 7 days | Roles rode in the 7-day access token | Offboarding was not immediate |

## Decisions

All taken by the project owner on 12 Oct 2026.

| Topic | Decision |
| --- | --- |
| Console manages | Identity records (users, roles, services, service keys) and a permission matrix: per role, create/read/update/delete plus named actions on each resource of each service |
| Out of scope | Editing services' business data (leads, properties, chats) from the console; field-level permissions; delegated administration |
| Record rules | Predefined scopes that each service declares per resource. Admins pick scopes per role; the service implements the filter |
| Roles | Admin-editable data. One role may grant permissions in several services. `presales` and `sales` stay roles |
| Console | Standalone app in this repo, served by Identity at `/admin` |
| Who uses it | Global `admin` and `tech` only |
| Services | CMS, Broker Tools, WA Automation, Consultation Agent; this project migrates all four |
| Token lifetime | Stays 7 days |
| Revocation | Identity reads each user's roles and active status from an in-memory roster, not the token |
| Broker Tools desk | A per-service user attribute (`broker_tools.desk`: presales, sales or none) set in the console, stored in an Identity table that Broker Tools' SQL reads |
| Environments | Dev and prod use separate Supabase projects, so the policy tables need no environment column |
| Consultation Agent | Integrates Identity first: staff only, email and password through its backend, every Broker Tools role, brokers matched by the last 10 digits of the phone in the token, broker doc created on first sign-in, `brokers.status` retired |
| Shared client code | Each consumer keeps its own copy of the small scope helper, plus a test that its manifest's scopes all have handlers |
| PRs | One per repo |

## The model

A grant says: a role may perform an action on a resource, limited to a scope.
Each service owns what can be controlled (resources, actions, scopes, user
attributes). Admins own who gets what (roles, grants, assignments, attribute
values).

| Concept | Defined by | Example | Notes |
| --- | --- | --- | --- |
| Service | Admin, in the console | `broker_tools` | Its key is `apps.<key>` in the introspect payload |
| Resource | The service's manifest | `lead` | A thing the service protects |
| Action | The service's manifest | `read`, `assign` | Create/read/update/delete plus named actions |
| Scope | The service's manifest | `own_presales` | Which rows. The service implements the filter; Identity stores only the name |
| Role | Admin | `presales` | Applies across services. Key fixed once created; label editable |
| Grant | Admin | `presales` may `lead.read` at `own_presales` | A (role, action, scope) triple. A role may hold several scopes for one action |
| Exclusive group | Admin | `desk` = {`presales`, `sales`} | A user holds at most one role per group |
| Assignment | Admin | a user holds {`presales`, `viewer`} | |
| User attribute | Manifest declares, admin sets | `broker_tools.desk` = `presales` | Per service, per user. Returned in introspect, readable by the service's SQL |

Resolution rules:

- **Union.** A user's permissions are the union of their roles' grants. Scopes
  union too: a user holding `own_presales` and `own_sales` on `lead.read` sees
  rows matching either. Holding `all` for an action makes the answer `["all"]`.
- **Every resource has an `all` scope**, created automatically. A resource with
  no row rules declares no other scope.
- **Access is explicit.** Every service has an implicit resource `app` with one
  action, `use`. `access` is true only for a user holding `app.use`. A role can
  hold a permission in a service without using it: Broker Tools roles get the
  CMS's `property.view_internal`, which must not make them CMS users.
- **Superuser.** `admin` has `is_superuser`: every action at `all` in every
  service, including `app.use` and resources added later. The flag is set only
  by migration, so the console cannot make another superuser.
- **`tech` is ordinary grants**, seeded to match what each service does today.
  Broker Tools made lead distribution admin-only on 29 Sep 2026, and WA
  Automation keeps `tech` out of its admin routes. Seeding `tech` explicitly
  reproduces that and makes it visible.
- **Console access is a grant.** Identity is registered as a system service
  with one resource, `console`. System services' grants are locked in the API
  and the UI; `tech` holds `console.use`, `admin` has it as superuser.
- **`primary_role`** is the user's highest-priority role that holds `app.use`
  in that service. A priority number on each role reproduces today's two
  precedence lists. It is a label for display and audit columns, never access.
- **Retired** resources, actions, scopes and attributes (missing from the latest
  manifest) keep their grants but resolve to nothing.

## Database

`db/004_permissions.sql` adds these tables to the `call_logs` project, all
prefixed `identity_` because the project also holds Broker Tools' schema and a
name collision is silent. RLS is on with no policies, and `anon` and
`authenticated` are revoked, as for `user_profiles`.

| Table | Holds |
| --- | --- |
| `identity_services` | key, name, `is_system`, `is_active`, `grants_version`, last manifest push |
| `identity_service_keys` | SHA-256 of each key, a 6-character prefix, label, `revoked_at` |
| `identity_resources` | per service: key, label, `retired_at` |
| `identity_actions` | per resource: key, label, `retired_at` |
| `identity_scopes` | per resource: key, label, `is_all`, `retired_at` |
| `identity_attributes` | per service: key, label, kind (`enum`), options, `retired_at` |
| `identity_roles` | key (immutable), label, description, priority, `is_superuser`, `exclusive_group` |
| `identity_role_grants` | (role, resource, action, scope). Composite foreign keys make a grant unable to name another resource's action or scope |
| `identity_user_roles` | (user, role), plus the role's exclusive group copied in so a unique index can enforce it |
| `identity_user_attributes` | (user, attribute) to value |
| `identity_audit_log` | actor, action, target, before and after JSON. Append-only: update and delete are revoked from every role |

Constraints that keep the database the last line of defence, as `db/001`'s
role CHECKs did:

- A grant can only name an action and scope of its own resource.
- A user holds at most one role per exclusive group (unique index).
- An unknown role cannot be assigned (foreign key).
- Role keys never change (trigger).

`user_profiles.roles` stays, kept in step by `identity_set_user_roles`, until
the cleanup PR drops it. Its two CHECK constraints are dropped in `004`, because
the foreign key and the unique index replace them and new role names would fail
them.

Every multi-row write is one SQL function called over PostgREST RPC, because
PostgREST cannot hold a transaction across calls. Each writes its audit row in
the same transaction.

| Function | Does |
| --- | --- |
| `identity_policy_snapshot()` | The whole policy and roster as one JSON document, for the cache |
| `identity_set_user_roles(user, role_keys, actor)` | Replace a user's roles |
| `identity_set_user_attributes(user, service, values, actor)` | Replace a user's attributes in one service |
| `identity_set_service_grants(service, grants, expected_version, actor)` | Replace one service's whole matrix; a stale version raises |
| `identity_upsert_role(...)`, `identity_delete_role(key, actor)` | Role edits; delete refuses a role in use, and `admin` |
| `identity_apply_manifest(service, manifest, actor)` | Add new resources, actions, scopes and attributes; relabel; retire missing ones |
| `identity_create_service_key(...)`, `identity_revoke_service_key(...)` | Key lifecycle |

`db/005_seed_permissions.sql` seeds the catalogue and the grants that reproduce
today's access. It is generated from `app/permissions/seed/*.json` by
`scripts/build_seed_sql.py`; a test fails if the committed SQL and the JSON
disagree, and the same JSON feeds the equivalence test.

## Resolving permissions on the hot path

Introspect still does no database work per request.

- **The snapshot.** `identity_policy_snapshot()` returns every service,
  resource, action, scope, attribute, role, grant and active service key, plus
  the roster: each user's roles, active status, name, phone and attributes.
  Identity holds it in memory.
- **Refresh** is stale-while-revalidate with a 30 s TTL. The first request to
  find it older starts one background refresh and is answered from the current
  copy. A failed refresh keeps the last good snapshot and logs a warning. An
  admin write refreshes its own instance immediately.
- **No snapshot at cold start** means introspect answers 503, which consumers
  already treat as "refuse everyone".
- **Per request**, after the unchanged signature check, Identity takes the
  user's roles from the roster, resolves them through the snapshot, and
  memoises the result per role set.
- **Token fallback.** A user created after the last refresh is not in the
  roster yet; their token's claims are used. A user missing from a snapshot
  loaded after their token was issued has been deleted, and is inactive.

A grant change therefore reaches consumers in about 90 s (30 s refresh plus the
consumers' 60 s cache), and so does a role change or deactivation.

## The introspect payload

Each app block gains `permissions` (resource to action to granted scopes; an
absent action is denied) and `attributes`. The old flags stay alongside, derived
from `permissions` by `app/permissions/compat.py`, until every consumer has
moved over.

```json
"apps": {
  "broker_tools": {
    "access": true,
    "primary_role": "presales",
    "permissions": {
      "lead": {"create": ["all"], "read": ["own_presales"], "update": ["own_presales"]},
      "lead_note": {"read": ["via_lead"], "create": ["via_lead"]}
    },
    "attributes": {"desk": "presales"},
    "unrestricted_leads": false,
    "own_presales": true,
    "own_sales": false
  }
}
```

How the legacy flags are derived, and why it is exact (pinned by
`tests/test_permissions_equivalence.py` for every legal role set):

| Flag | Derived from |
| --- | --- |
| `cms.can_add_property` / `can_edit_property` / `can_publish` / `can_edit_seo` / `can_delete_property` | `property.create` / `update` / `publish` / `update_seo` / `delete` |
| `cms.can_upload_media` | `media.create` |
| `cms.can_manage_users` | `identity.console.use` |
| `broker_tools.unrestricted_leads` | `lead.read` includes `all` |
| `broker_tools.own_presales` / `own_sales` | `lead.read` was granted `own_presales` / `own_sales` by any held role |

## Registering a service

A service describes what can be controlled in `identity-manifest.json` in its
own repo, next to the code that enforces it, and its deploy pushes it with
`PUT /v1/services/manifest` and its own service key. Who gets what stays in the
console, so a deploy can never grant or remove anyone's access.

```json
{
  "service": "broker_tools",
  "resources": {
    "lead": {
      "label": "Leads",
      "actions": ["create", "read", "update", "assign", "sync"],
      "scopes": {"own_presales": "Own leads (pre-sales owner)", "own_sales": "Own leads (sales owner)"}
    },
    "distribution_settings": {"label": "Lead distribution", "actions": ["read", "update"]}
  },
  "attributes": {
    "desk": {"label": "Desk", "kind": "enum", "options": ["presales", "sales"]}
  }
}
```

`app.use` and every resource's `all` scope are implicit. A push adds what is
new with no grants (only `admin` can use it until someone grants it), updates
labels, and retires whatever is missing instead of deleting it. An admin deletes
a retired resource explicitly.

Adding a service:

1. Register it in the console and generate its key (shown once).
2. Store the key in the service's Secret Manager; call introspect with it.
3. Write the manifest, a scope handler per declared scope, and the test that
   every scope has a handler.
4. Push the manifest from the deploy.
5. Tick the matrix in the console. No Identity change and no Identity deploy.

## Record rules: the scope catalogue

What each service declares, matching what it enforces in code today.

| Service | Resource | Scopes | Filter |
| --- | --- | --- | --- |
| Broker Tools | `lead` | `own_presales`, `own_sales` | `fk_presales_owner` / `fk_sales_owner` = the caller's team member |
| Broker Tools | lead children: `lead_note`, `lead_call`, `lead_requirement`, `lead_recommendation`, `lead_shared_option`, `lead_consultation`, `lead_site_visit`, `lead_whatsapp`, `lead_task` (create) | `via_lead` | Rows whose lead the caller may read |
| Broker Tools | `lead_task` (read, close) | `assigned` | `fk_assignee` = the caller |
| Broker Tools | `report` | `own`, `own_team_aggregate` | The caller's own numbers, or their desk team's with names stripped |
| Broker Tools | `daily_remark` | `own` | The caller's own row |
| WA Automation | `lead` (chats) | `assigned_presales`, `assigned_sales`, `own_test_identity` | `leads_master` owners; the caller's own phone or Instagram handle |
| WA Automation | `prompt`, `agent_models` | `own` | The caller's own draft; `all` adds anyone's and production |
| Consultation Agent | `consultation_session`, `recording`, `itinerary` | `own` | `broker_id` = the caller's broker |
| CMS | every resource | none | No ownership rules. Draft/live/archived visibility depends on signed-in versus anonymous and stays in code |

## Enforcing scopes in a service

Each consumer copies one small helper and keeps a scope-handler map per
resource. Unknown scope names match nothing, and an empty filter is a denial,
never an empty `Q()` that matches every row.

```python
def scoped(queryset, user, resource, action, handlers):
    scopes = user.permissions.get(resource, {}).get(action)
    if not scopes:
        raise PermissionDenied
    if 'all' in scopes:
        return queryset
    q = Q()
    for name in scopes:
        if name in handlers:
            q |= handlers[name](user)
    if not q:
        raise PermissionDenied
    return queryset.filter(q)
```

"Mine" needs a local link from the Identity user to the service's row. Every
service matches on Identity's `user_id`, except Consultation Agent, which
matches brokers by phone.

## Admin API

All under `/v1/admin`, requiring `identity.console.use`. The original endpoints
keep their paths and behaviour.

| Method | Path | Does |
| --- | --- | --- |
| GET, POST | `/users` | List (filters `role`, `service`, `active`); invite |
| GET, PATCH | `/users/{id}` | Detail with roles, attributes and effective permissions; edit name and phone |
| PATCH | `/users/{id}/roles` | Replace roles; revokes sessions |
| PUT | `/users/{id}/attributes/{service}` | Replace that service's attribute values |
| PATCH | `/users/{id}/status` | Activate or deactivate |
| POST | `/users/{id}/reset-password`, `/users/{id}/set-password` | Unchanged |
| GET, POST | `/roles` | List with member counts; create |
| PATCH, DELETE | `/roles/{key}` | Edit; delete refuses a role in use, and `admin` |
| GET, POST | `/services` | List; register |
| GET, PATCH | `/services/{key}` | Catalogue with retired items; rename, deactivate |
| DELETE | `/services/{key}/resources/{resource}` | Remove a retired resource and its grants |
| GET, PUT | `/services/{key}/grants` | One service's whole matrix; PUT needs `If-Match: <grants_version>`, answers 409 when stale, and is refused for system services |
| POST | `/services/{key}/keys` | New key, plaintext returned once |
| DELETE | `/services/{key}/keys/{id}` | Revoke a key |
| GET | `/audit` | The audit log, filtered by actor, target or date |

Service-facing: `PUT /v1/services/manifest`, authenticated by the calling
service's own key.

Lockout guards, all server-side: you cannot change your own roles so that you
lose `console.use`; the last active `admin` cannot be deactivated or lose the
role; `admin`'s superuser flag and system services' grants cannot be edited.

## Admin console

A single-page app in `admin/` (React 18, TypeScript, Vite, Tailwind, TanStack
Query, react-router, the same stack as CMS `admin_ui`), built into the same
container and served at `/admin`, and at `/identity/admin` through the Firebase
rewrite. Same origin, so no CORS entry.

| Page | What the admin does |
| --- | --- |
| Sign in | Email and password; anyone without `console.use` sees "no access" |
| Users | Search and filter; invite |
| User | Name and phone; roles (a second role from the same exclusive group is refused); per-service attributes such as desk, with a warning when desk and role disagree; activate or deactivate; set a password or send a reset; effective access per service |
| Roles | Create, edit, delete; member counts |
| Permissions | Pick a service: rows are resource and action, columns are roles, each cell the granted scopes. A review step lists the changes before saving |
| Services | Register; catalogue with retired items; manifest push time; generate and revoke keys |
| Audit | Who changed what and when |

The UI hides what the caller cannot do; the API enforces every rule.

## Consumer migration

Each service, in one PR: get its own service key; commit
`identity-manifest.json` and push it on deploy; replace flag and role-name
checks with `permissions` and the scope helper; match users by Identity
`user_id`; stop reading the legacy flags.

| Service | Notes |
| --- | --- |
| Consultation Agent | Signs in through Identity (Consultation Agent #1). Then moves onto `permissions` |
| CMS | Uses Identity's permissions instead of its local `can_*` copy and the `is_superuser` override. Each check moves to its proper action: create and publish checked `can_edit_property`, and `can_edit_seo` was never enforced. The Users & Roles page moves to the console. `media.update` becomes write roles only (viewers could edit alt text) |
| Broker Tools | `IsAnyTeamMember` becomes `access`; `IsAdminRole` becomes `distribution_settings.update`. Lead, task and report scoping moves onto scopes. Its SQL that selects people by `team_members.role` reads `broker_tools.desk` from Identity's attributes instead |
| WA Automation | Gets its own `apps.wa_automation` block; its role aliases and role tuples go. Seeded exactly as it behaves today, which makes two things visible for review: `lead_manager` administers WhatsApp numbers, templates and Meta Ads, and `tech` cannot publish prompts. The web router's "any Instagram lead" rule is not carried over |

## Security, audit and revocation

- **Failing closed:** an unknown scope matches nothing; an empty scope list is a
  denial; no snapshot is 503; a manifest push cannot create a grant.
- **Audit:** every role, grant, user, attribute, service and key change writes
  `identity_audit_log` inside the same SQL function as the change.
- **Service keys:** 32 random bytes, stored as SHA-256, plaintext shown once.
  Database-held keys are checked from the snapshot, so a revoked key stops
  working within 30 s. `ALLSET_SERVICE_KEY` and `ALLSET_SERVICE_KEYS` keep
  working until every consumer has its own key.
- **The console** sends `Content-Security-Policy` with `script-src 'self'` and
  `frame-ancestors 'none'`. Tokens travel in the `Authorization` header, so CSRF
  stays out of scope.

| Change | Before | After |
| --- | --- | --- |
| Grant added or removed | A deploy | About 90 s |
| Role assigned or removed, user deactivated | Up to 7 days | About 90 s; tokens still last 7 days |
| Service key revoked | A redeploy | About 30 s |

## Rollout

Per environment:

1. Apply `db/004_permissions.sql`, then `db/005_seed_permissions.sql`.
2. Deploy Identity. It serves both the new `permissions` and the legacy flags.
3. Migrate the consumers, one PR per repo.
4. When all four are live, a follow-up PR removes the legacy flags,
   `app/capabilities.py`, `user_profiles.roles` and the shared introspect key.
   It cannot ship in the same PR as the engine: consumers still read the flags
   until their own PRs deploy.

## Known limits

- **A moved phone.** Consultation Agent matches brokers by phone. With the
  roster in memory, a phone moved between people takes effect in about 90 s,
  but a phone is still a weaker link than a `user_id`.
- **Superuser widens `admin` in Consultation Agent.** Today every broker,
  admins included, sees only their own sessions. As superuser, `admin` sees all.
