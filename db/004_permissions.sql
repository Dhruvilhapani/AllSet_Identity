-- AllSet Identity — data-driven permissions.
--
-- Moves the role matrix out of app/capabilities.py into tables an admin edits
-- in the console. See docs/ARCHITECTURE_ADMIN.md for the model. Apply after
-- 001-003, then apply 005_seed_permissions.sql, then deploy the code that reads
-- these tables.
--
-- Every name is prefixed identity_: this project also holds Broker Tools'
-- schema, and a collision is silent (see 000_preflight.sql).
--
-- Every multi-row write is one of the functions below, called over PostgREST
-- RPC with the service-role key, because PostgREST cannot hold a transaction
-- across calls. Each function writes its audit row in the same transaction.
-- They raise:
--   22023  a request that can never succeed as sent      -> HTTP 400
--   P0002  the thing it names does not exist             -> HTTP 404
--   PT409  someone else changed it first; reload, retry  -> HTTP 409
--
-- PT409 and not 40001 (serialization_failure): PostgREST retries a transaction
-- that fails with 40001, so a stale write would be retried forever. A PTxxx
-- code is PostgREST's own convention for "answer with HTTP xxx".
--
-- Idempotent: safe to re-run.

-- ── Catalogue: what each service lets an admin control ──────────────────────

create table if not exists public.identity_services (
    id                 uuid        primary key default gen_random_uuid(),
    key                text        not null unique check (key ~ '^[a-z][a-z0-9_]{1,39}$'),
    name               text        not null,
    description        text        not null default '',
    -- Identity itself. Its grants decide who reaches the console, so they are
    -- seeded and never edited through the API.
    is_system          boolean     not null default false,
    is_active          boolean     not null default true,
    -- Bumped by every grant change, so two admins editing the same matrix
    -- cannot silently overwrite each other.
    grants_version     integer     not null default 0,
    manifest_pushed_at timestamptz,
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now()
);

create table if not exists public.identity_service_keys (
    id          uuid        primary key default gen_random_uuid(),
    service_id  uuid        not null references public.identity_services(id) on delete cascade,
    -- SHA-256 of the key. The plaintext is shown once and never stored.
    key_hash    text        not null unique check (key_hash ~ '^[0-9a-f]{64}$'),
    key_prefix  text        not null default '',
    label       text        not null default '',
    created_by  uuid,
    created_at  timestamptz not null default now(),
    revoked_at  timestamptz
);

create table if not exists public.identity_resources (
    id          uuid        primary key default gen_random_uuid(),
    service_id  uuid        not null references public.identity_services(id) on delete cascade,
    key         text        not null check (key ~ '^[a-z][a-z0-9_]{0,62}$'),
    label       text        not null default '',
    description text        not null default '',
    sort        integer     not null default 0,
    -- Set when a manifest push no longer lists it. Grants are kept, and resolve
    -- to nothing, until an admin deletes it.
    retired_at  timestamptz,
    created_at  timestamptz not null default now(),
    updated_at  timestamptz not null default now(),
    unique (service_id, key)
);

create table if not exists public.identity_actions (
    id          uuid        primary key default gen_random_uuid(),
    resource_id uuid        not null references public.identity_resources(id) on delete cascade,
    key         text        not null check (key ~ '^[a-z][a-z0-9_]{0,62}$'),
    label       text        not null default '',
    sort        integer     not null default 0,
    retired_at  timestamptz,
    unique (resource_id, key),
    -- Target of the composite foreign key on identity_role_grants.
    unique (id, resource_id)
);

create table if not exists public.identity_scopes (
    id          uuid        primary key default gen_random_uuid(),
    resource_id uuid        not null references public.identity_resources(id) on delete cascade,
    key         text        not null check (key ~ '^[a-z][a-z0-9_]{0,62}$'),
    label       text        not null default '',
    sort        integer     not null default 0,
    -- Every resource has exactly one: the scope that means "every row".
    is_all      boolean     not null default false,
    retired_at  timestamptz,
    unique (resource_id, key),
    unique (id, resource_id),
    constraint identity_scopes_all_is_all check (is_all = (key = 'all'))
);

-- Per-service user attributes, such as Broker Tools' desk.
create table if not exists public.identity_attributes (
    id          uuid        primary key default gen_random_uuid(),
    service_id  uuid        not null references public.identity_services(id) on delete cascade,
    key         text        not null check (key ~ '^[a-z][a-z0-9_]{0,62}$'),
    label       text        not null default '',
    kind        text        not null default 'enum' check (kind in ('enum')),
    options     text[]      not null default '{}',
    sort        integer     not null default 0,
    retired_at  timestamptz,
    unique (service_id, key)
);

-- ── Who gets what ────────────────────────────────────────────────────────────

create table if not exists public.identity_roles (
    id              uuid        primary key default gen_random_uuid(),
    -- Fixed once created (trigger below): keys appear in tokens and in Broker
    -- Tools' audit columns.
    key             text        not null unique check (key ~ '^[a-z][a-z0-9_]{1,39}$'),
    label           text        not null,
    description     text        not null default '',
    -- Lowest wins when a role set is collapsed to one primary_role.
    priority        integer     not null default 100,
    -- Every action at every scope in every service, including ones added later.
    -- Set only here and in the seed, never through the API.
    is_superuser    boolean     not null default false,
    -- A user holds at most one role per group (presales and sales: 'desk').
    exclusive_group text        check (exclusive_group is null or exclusive_group ~ '^[a-z][a-z0-9_]{0,39}$'),
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);

create table if not exists public.identity_role_grants (
    role_id     uuid        not null references public.identity_roles(id) on delete cascade,
    resource_id uuid        not null,
    action_id   uuid        not null,
    scope_id    uuid        not null,
    created_at  timestamptz not null default now(),
    -- A role may hold several scopes for one action (WA Automation's pre-sales
    -- sees assigned leads AND its own test chats).
    primary key (role_id, action_id, scope_id),
    -- A grant cannot name another resource's action or scope.
    foreign key (action_id, resource_id)
        references public.identity_actions(id, resource_id) on delete cascade,
    foreign key (scope_id, resource_id)
        references public.identity_scopes(id, resource_id) on delete cascade
);

create index if not exists identity_role_grants_resource on public.identity_role_grants (resource_id);

create table if not exists public.identity_user_roles (
    user_id         uuid        not null references public.user_profiles(user_id) on delete cascade,
    role_id         uuid        not null references public.identity_roles(id) on delete restrict,
    -- Copied from the role by trigger, so the unique index below can enforce
    -- "one role per group" without a subquery.
    exclusive_group text,
    created_at      timestamptz not null default now(),
    primary key (user_id, role_id)
);

create unique index if not exists identity_user_roles_one_per_group
    on public.identity_user_roles (user_id, exclusive_group)
    where exclusive_group is not null;

create table if not exists public.identity_user_attributes (
    user_id      uuid        not null references public.user_profiles(user_id) on delete cascade,
    attribute_id uuid        not null references public.identity_attributes(id) on delete cascade,
    value        text        not null,
    updated_at   timestamptz not null default now(),
    primary key (user_id, attribute_id)
);

create table if not exists public.identity_audit_log (
    id            bigint      generated always as identity primary key,
    at            timestamptz not null default now(),
    actor_user_id uuid,
    actor_email   text        not null default '',
    action        text        not null,
    target_type   text        not null,
    target_key    text        not null default '',
    before        jsonb,
    after         jsonb
);

create index if not exists identity_audit_log_at on public.identity_audit_log (at desc);
create index if not exists identity_audit_log_target on public.identity_audit_log (target_type, target_key);

-- Broker Tools' SQL reads desk values from here (read-only), joining
-- team_members.supabase_user_id to user_id.
create or replace view public.identity_user_attribute_values as
select ua.user_id, s.key as service_key, a.key as attribute_key, ua.value
  from public.identity_user_attributes ua
  join public.identity_attributes a on a.id = ua.attribute_id
  join public.identity_services s on s.id = a.service_id
 where a.retired_at is null;

comment on view public.identity_user_attribute_values is
    'Per-service user attributes set in the Identity console, e.g. broker_tools.desk. Read-only for services.';

-- The roles CHECKs on user_profiles listed the eight original role names. The
-- foreign key and unique index on identity_user_roles replace them, and new
-- role names would fail them. user_profiles.roles stays as a mirror, written
-- only by identity_set_user_roles, until the cleanup PR drops it.
alter table public.user_profiles drop constraint if exists roles_valid;
alter table public.user_profiles drop constraint if exists roles_one_desk;

-- ── Triggers ─────────────────────────────────────────────────────────────────

drop trigger if exists identity_services_set_updated_at on public.identity_services;
create trigger identity_services_set_updated_at
    before update on public.identity_services
    for each row execute function public.identity_set_updated_at();

drop trigger if exists identity_resources_set_updated_at on public.identity_resources;
create trigger identity_resources_set_updated_at
    before update on public.identity_resources
    for each row execute function public.identity_set_updated_at();

drop trigger if exists identity_roles_set_updated_at on public.identity_roles;
create trigger identity_roles_set_updated_at
    before update on public.identity_roles
    for each row execute function public.identity_set_updated_at();

create or replace function public.identity_roles_guard()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
    if new.key <> old.key then
        raise exception using errcode = '22023', message = 'a role key cannot be changed';
    end if;
    if new.exclusive_group is distinct from old.exclusive_group then
        -- Raises unique_violation, refusing the change, if it would leave a
        -- user holding two roles of one group.
        update public.identity_user_roles
           set exclusive_group = new.exclusive_group
         where role_id = new.id;
    end if;
    return new;
end;
$$;

drop trigger if exists identity_roles_guard on public.identity_roles;
create trigger identity_roles_guard
    before update on public.identity_roles
    for each row execute function public.identity_roles_guard();

create or replace function public.identity_user_roles_copy_group()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
    select r.exclusive_group into new.exclusive_group
      from public.identity_roles r
     where r.id = new.role_id;
    return new;
end;
$$;

drop trigger if exists identity_user_roles_copy_group on public.identity_user_roles;
create trigger identity_user_roles_copy_group
    before insert or update of role_id on public.identity_user_roles
    for each row execute function public.identity_user_roles_copy_group();

-- ── Internal helpers ─────────────────────────────────────────────────────────

create or replace function public.identity_audit(
    p_actor uuid, p_action text, p_target_type text, p_target_key text,
    p_before jsonb, p_after jsonb
)
returns void
language sql
set search_path = ''
as $$
    insert into public.identity_audit_log (actor_user_id, actor_email, action, target_type, target_key, before, after)
    values (
        p_actor,
        coalesce((select p.email::text from public.user_profiles p where p.user_id = p_actor), ''),
        p_action, p_target_type, coalesce(p_target_key, ''), p_before, p_after
    );
$$;

create or replace function public.identity_service_id(p_service text)
returns uuid
language plpgsql
stable
set search_path = ''
as $$
declare
    v_id uuid;
begin
    select s.id into v_id from public.identity_services s where s.key = p_service;
    if v_id is null then
        raise exception using errcode = 'P0002', message = 'service not found: ' || coalesce(p_service, '');
    end if;
    return v_id;
end;
$$;

create or replace function public.identity_user_role_keys(p_user_id uuid)
returns jsonb
language sql
stable
set search_path = ''
as $$
    select coalesce(jsonb_agg(r.key order by r.key), '[]'::jsonb)
      from public.identity_user_roles ur
      join public.identity_roles r on r.id = ur.role_id
     where ur.user_id = p_user_id;
$$;

create or replace function public.identity_service_grants_json(p_service_id uuid)
returns jsonb
language sql
stable
set search_path = ''
as $$
    -- role -> resource -> action -> [scopes], for live (non-retired) items only.
    select coalesce(jsonb_object_agg(role_key, resources), '{}'::jsonb)
      from (
        select role_key, jsonb_object_agg(resource_key, actions) as resources
          from (
            select role_key, resource_key, jsonb_object_agg(action_key, scopes) as actions
              from (
                select r.key as role_key, res.key as resource_key, a.key as action_key,
                       jsonb_agg(sc.key order by sc.sort, sc.key) as scopes
                  from public.identity_role_grants g
                  join public.identity_roles r on r.id = g.role_id
                  join public.identity_resources res on res.id = g.resource_id
                  join public.identity_actions a on a.id = g.action_id
                  join public.identity_scopes sc on sc.id = g.scope_id
                 where res.service_id = p_service_id
                   and res.retired_at is null and a.retired_at is null and sc.retired_at is null
                 group by r.key, res.key, a.key
              ) per_action
             group by role_key, resource_key
          ) per_resource
         group by role_key
      ) per_role;
$$;

-- ── The snapshot every Identity instance caches ──────────────────────────────

create or replace function public.identity_policy_snapshot()
returns jsonb
language sql
stable
set search_path = ''
as $$
    select jsonb_build_object(
        'services', coalesce((
            select jsonb_agg(jsonb_build_object(
                'key', s.key, 'name', s.name, 'description', s.description,
                'is_system', s.is_system, 'is_active', s.is_active,
                'grants_version', s.grants_version,
                'manifest_pushed_at', s.manifest_pushed_at,
                'resources', coalesce((
                    select jsonb_agg(jsonb_build_object(
                        'key', res.key, 'label', res.label, 'description', res.description,
                        'retired', res.retired_at is not null,
                        'actions', coalesce((
                            select jsonb_agg(jsonb_build_object(
                                'key', a.key, 'label', a.label, 'retired', a.retired_at is not null
                            ) order by a.sort, a.key)
                              from public.identity_actions a where a.resource_id = res.id
                        ), '[]'::jsonb),
                        'scopes', coalesce((
                            select jsonb_agg(jsonb_build_object(
                                'key', sc.key, 'label', sc.label, 'is_all', sc.is_all,
                                'retired', sc.retired_at is not null
                            ) order by sc.sort, sc.key)
                              from public.identity_scopes sc where sc.resource_id = res.id
                        ), '[]'::jsonb)
                    ) order by res.sort, res.key)
                      from public.identity_resources res where res.service_id = s.id
                ), '[]'::jsonb),
                'attributes', coalesce((
                    select jsonb_agg(jsonb_build_object(
                        'key', at.key, 'label', at.label, 'kind', at.kind,
                        'options', to_jsonb(at.options), 'retired', at.retired_at is not null
                    ) order by at.sort, at.key)
                      from public.identity_attributes at where at.service_id = s.id
                ), '[]'::jsonb)
            ) order by s.key)
              from public.identity_services s
        ), '[]'::jsonb),
        'roles', coalesce((
            select jsonb_agg(jsonb_build_object(
                'key', r.key, 'label', r.label, 'description', r.description,
                'priority', r.priority, 'is_superuser', r.is_superuser,
                'exclusive_group', r.exclusive_group
            ) order by r.priority, r.key)
              from public.identity_roles r
        ), '[]'::jsonb),
        'grants', coalesce((
            select jsonb_agg(jsonb_build_object(
                'role', r.key, 'service', s.key, 'resource', res.key,
                'action', a.key, 'scope', sc.key
            ))
              from public.identity_role_grants g
              join public.identity_roles r on r.id = g.role_id
              join public.identity_resources res on res.id = g.resource_id
              join public.identity_services s on s.id = res.service_id
              join public.identity_actions a on a.id = g.action_id
              join public.identity_scopes sc on sc.id = g.scope_id
        ), '[]'::jsonb),
        'users', coalesce((
            select jsonb_agg(jsonb_build_object(
                'user_id', p.user_id, 'email', p.email, 'full_name', p.full_name,
                'phone', p.phone, 'is_active', p.is_active,
                'roles', public.identity_user_role_keys(p.user_id),
                'attributes', coalesce((
                    select jsonb_object_agg(per_service.service_key, per_service.attrs)
                      from (
                        select s.key as service_key, jsonb_object_agg(at.key, ua.value) as attrs
                          from public.identity_user_attributes ua
                          join public.identity_attributes at on at.id = ua.attribute_id
                          join public.identity_services s on s.id = at.service_id
                         where ua.user_id = p.user_id and at.retired_at is null
                         group by s.key
                      ) per_service
                ), '{}'::jsonb)
            ))
              from public.user_profiles p
        ), '[]'::jsonb),
        'service_keys', coalesce((
            select jsonb_agg(jsonb_build_object('service', s.key, 'key_hash', k.key_hash))
              from public.identity_service_keys k
              join public.identity_services s on s.id = k.service_id
             where k.revoked_at is null and s.is_active
        ), '[]'::jsonb)
    );
$$;

-- ── Users ────────────────────────────────────────────────────────────────────

create or replace function public.identity_set_user_roles(
    p_user_id uuid, p_role_keys text[], p_actor uuid default null
)
returns jsonb
language plpgsql
set search_path = ''
as $$
declare
    v_keys     text[];
    v_unknown  text;
    v_clash    text;
    v_before   jsonb;
    v_after    jsonb;
begin
    if not exists (select 1 from public.user_profiles p where p.user_id = p_user_id) then
        raise exception using errcode = 'P0002', message = 'user not found';
    end if;

    select coalesce(array_agg(distinct lower(btrim(k))), '{}')
      into v_keys
      from unnest(coalesce(p_role_keys, '{}')) k
     where btrim(k) <> '';

    select string_agg(k, ', ' order by k) into v_unknown
      from unnest(v_keys) k
     where not exists (select 1 from public.identity_roles r where r.key = k);
    if v_unknown is not null then
        raise exception using errcode = '22023', message = 'unknown role: ' || v_unknown;
    end if;

    -- Same wording as the old app/capabilities.py message:
    -- 'a user may hold at most one of presales/sales, got: presales, sales'.
    select string_agg(format('a user may hold at most one of %s, got: %s', grp.members, held.keys), '; ')
      into v_clash
      from (
        select r.exclusive_group, string_agg(r.key, '/' order by r.key) as members
          from public.identity_roles r
         where r.exclusive_group is not null
         group by r.exclusive_group
      ) grp
      join (
        select r.exclusive_group, string_agg(r.key, ', ' order by r.key) as keys, count(*) as n
          from public.identity_roles r
         where r.key = any(v_keys) and r.exclusive_group is not null
         group by r.exclusive_group
      ) held on held.exclusive_group = grp.exclusive_group
     where held.n > 1;
    if v_clash is not null then
        raise exception using errcode = '22023', message = v_clash;
    end if;

    v_before := public.identity_user_role_keys(p_user_id);

    -- Never leave the organisation without an active superuser.
    if exists (
        select 1 from public.identity_user_roles ur
          join public.identity_roles r on r.id = ur.role_id
         where ur.user_id = p_user_id and r.is_superuser and not (r.key = any(v_keys))
    ) and not exists (
        select 1 from public.identity_user_roles ur
          join public.identity_roles r on r.id = ur.role_id
          join public.user_profiles p on p.user_id = ur.user_id
         where r.is_superuser and p.is_active and ur.user_id <> p_user_id
    ) then
        raise exception using errcode = '22023',
            message = 'cannot remove the last active admin; give another active user the admin role first';
    end if;

    -- Remove before adding, so swapping presales for sales never trips the
    -- one-per-group index halfway through.
    delete from public.identity_user_roles ur
     using public.identity_roles r
     where ur.user_id = p_user_id and r.id = ur.role_id and not (r.key = any(v_keys));

    insert into public.identity_user_roles (user_id, role_id)
    select p_user_id, r.id from public.identity_roles r where r.key = any(v_keys)
    on conflict do nothing;

    v_after := public.identity_user_role_keys(p_user_id);

    update public.user_profiles p
       set roles = coalesce((select array_agg(x order by x) from jsonb_array_elements_text(v_after) x), '{}')
     where p.user_id = p_user_id;

    if v_before is distinct from v_after then
        perform public.identity_audit(p_actor, 'user.roles', 'user', p_user_id::text, v_before, v_after);
    end if;
    return v_after;
end;
$$;

create or replace function public.identity_set_user_attributes(
    p_user_id uuid, p_service text, p_values jsonb, p_actor uuid default null
)
returns jsonb
language plpgsql
set search_path = ''
as $$
declare
    v_service_id uuid := public.identity_service_id(p_service);
    v_bad        text;
    v_before     jsonb;
    v_after      jsonb;
begin
    if not exists (select 1 from public.user_profiles p where p.user_id = p_user_id) then
        raise exception using errcode = 'P0002', message = 'user not found';
    end if;
    if jsonb_typeof(coalesce(p_values, '{}'::jsonb)) <> 'object' then
        raise exception using errcode = '22023', message = 'attributes must be an object';
    end if;

    select string_agg(e.key, ', ' order by e.key) into v_bad
      from jsonb_each_text(coalesce(p_values, '{}'::jsonb)) e
     where not exists (
        select 1 from public.identity_attributes a
         where a.service_id = v_service_id and a.key = e.key and a.retired_at is null
     );
    if v_bad is not null then
        raise exception using errcode = '22023', message = 'unknown attribute for ' || p_service || ': ' || v_bad;
    end if;

    select string_agg(e.key || '=' || e.value, ', ' order by e.key) into v_bad
      from jsonb_each_text(coalesce(p_values, '{}'::jsonb)) e
      join public.identity_attributes a on a.service_id = v_service_id and a.key = e.key
     where coalesce(e.value, '') <> '' and a.kind = 'enum' and not (e.value = any(a.options));
    if v_bad is not null then
        raise exception using errcode = '22023', message = 'value not allowed: ' || v_bad;
    end if;

    select coalesce(jsonb_object_agg(a.key, ua.value), '{}'::jsonb) into v_before
      from public.identity_user_attributes ua
      join public.identity_attributes a on a.id = ua.attribute_id
     where ua.user_id = p_user_id and a.service_id = v_service_id;

    delete from public.identity_user_attributes ua
     using public.identity_attributes a
     where ua.user_id = p_user_id and a.id = ua.attribute_id and a.service_id = v_service_id;

    -- An empty value clears the attribute.
    insert into public.identity_user_attributes (user_id, attribute_id, value)
    select p_user_id, a.id, e.value
      from jsonb_each_text(coalesce(p_values, '{}'::jsonb)) e
      join public.identity_attributes a on a.service_id = v_service_id and a.key = e.key
     where coalesce(e.value, '') <> '';

    select coalesce(jsonb_object_agg(a.key, ua.value), '{}'::jsonb) into v_after
      from public.identity_user_attributes ua
      join public.identity_attributes a on a.id = ua.attribute_id
     where ua.user_id = p_user_id and a.service_id = v_service_id;

    if v_before is distinct from v_after then
        perform public.identity_audit(p_actor, 'user.attributes', 'user', p_user_id::text,
                                      jsonb_build_object(p_service, v_before),
                                      jsonb_build_object(p_service, v_after));
    end if;
    return v_after;
end;
$$;

-- ── Roles ────────────────────────────────────────────────────────────────────

create or replace function public.identity_upsert_role(
    p_key text, p_label text, p_description text default '',
    p_priority integer default 100, p_exclusive_group text default null,
    p_actor uuid default null
)
returns jsonb
language plpgsql
set search_path = ''
as $$
declare
    v_before jsonb;
    v_after  jsonb;
begin
    if coalesce(btrim(p_label), '') = '' then
        raise exception using errcode = '22023', message = 'a role needs a label';
    end if;

    select to_jsonb(r) - 'id' - 'created_at' - 'updated_at' into v_before
      from public.identity_roles r where r.key = p_key;

    insert into public.identity_roles (key, label, description, priority, exclusive_group)
    values (p_key, btrim(p_label), coalesce(p_description, ''), coalesce(p_priority, 100),
            nullif(btrim(coalesce(p_exclusive_group, '')), ''))
    on conflict (key) do update
       set label = excluded.label,
           description = excluded.description,
           priority = excluded.priority,
           exclusive_group = excluded.exclusive_group;

    select to_jsonb(r) - 'id' - 'created_at' - 'updated_at' into v_after
      from public.identity_roles r where r.key = p_key;

    perform public.identity_audit(p_actor, case when v_before is null then 'role.create' else 'role.update' end,
                                  'role', p_key, v_before, v_after);
    return v_after;
end;
$$;

create or replace function public.identity_delete_role(p_key text, p_actor uuid default null)
returns void
language plpgsql
set search_path = ''
as $$
declare
    v_role public.identity_roles;
    v_held integer;
begin
    select * into v_role from public.identity_roles r where r.key = p_key;
    if v_role.id is null then
        raise exception using errcode = 'P0002', message = 'role not found: ' || coalesce(p_key, '');
    end if;
    if v_role.is_superuser then
        raise exception using errcode = '22023', message = 'the superuser role cannot be deleted';
    end if;
    select count(*) into v_held from public.identity_user_roles ur where ur.role_id = v_role.id;
    if v_held > 0 then
        raise exception using errcode = '22023',
            message = format('role %s is held by %s user(s); remove it from them first', p_key, v_held);
    end if;

    delete from public.identity_roles r where r.id = v_role.id;
    perform public.identity_audit(p_actor, 'role.delete', 'role', p_key,
                                  to_jsonb(v_role) - 'id' - 'created_at' - 'updated_at', null);
end;
$$;

-- ── Grants ───────────────────────────────────────────────────────────────────

-- {role: {resource: {action: [scope, ...]}}} as rows.
create or replace function public.identity_expand_grants(p_grants jsonb)
returns table (role_key text, resource_key text, action_key text, scope_key text)
language sql
immutable
set search_path = ''
as $$
    select r.key, res.key, act.key, sc.value
      from jsonb_each(coalesce(p_grants, '{}'::jsonb)) r
      cross join lateral jsonb_each(r.value) res
      cross join lateral jsonb_each(res.value) act
      cross join lateral jsonb_array_elements_text(act.value) sc;
$$;

create or replace function public.identity_set_service_grants(
    p_service text, p_grants jsonb, p_expected_version integer default null,
    p_actor uuid default null, p_allow_system boolean default false
)
returns integer
language plpgsql
set search_path = ''
as $$
declare
    v_service public.identity_services;
    v_bad     text;
    v_before  jsonb;
    v_after   jsonb;
begin
    select * into v_service from public.identity_services s where s.key = p_service for update;
    if v_service.id is null then
        raise exception using errcode = 'P0002', message = 'service not found: ' || coalesce(p_service, '');
    end if;
    -- Identity's own grants decide who reaches the console; only the seed sets them.
    if v_service.is_system and not p_allow_system then
        raise exception using errcode = '22023', message = 'grants for ' || p_service || ' cannot be edited';
    end if;
    if p_expected_version is not null and p_expected_version <> v_service.grants_version then
        raise exception using errcode = 'PT409',
            message = 'these permissions were changed by someone else; reload and try again';
    end if;
    if jsonb_typeof(coalesce(p_grants, '{}'::jsonb)) <> 'object' then
        raise exception using errcode = '22023', message = 'grants must be an object';
    end if;

    select string_agg(distinct w.role_key, ', ') into v_bad
      from public.identity_expand_grants(p_grants) w
     where not exists (select 1 from public.identity_roles r where r.key = w.role_key);
    if v_bad is not null then
        raise exception using errcode = '22023', message = 'unknown role: ' || v_bad;
    end if;

    select string_agg(distinct w.role_key, ', ') into v_bad
      from public.identity_expand_grants(p_grants) w
      join public.identity_roles r on r.key = w.role_key
     where r.is_superuser;
    if v_bad is not null then
        raise exception using errcode = '22023', message = v_bad || ' is a superuser and needs no grants';
    end if;

    select string_agg(distinct w.resource_key || '.' || w.action_key || '@' || w.scope_key, ', ') into v_bad
      from public.identity_expand_grants(p_grants) w
     where not exists (
        select 1
          from public.identity_resources res
          join public.identity_actions a on a.resource_id = res.id and a.key = w.action_key and a.retired_at is null
          join public.identity_scopes sc on sc.resource_id = res.id and sc.key = w.scope_key and sc.retired_at is null
         where res.service_id = v_service.id and res.key = w.resource_key and res.retired_at is null
     );
    if v_bad is not null then
        raise exception using errcode = '22023', message = 'not in the ' || p_service || ' catalogue: ' || v_bad;
    end if;

    v_before := public.identity_service_grants_json(v_service.id);

    -- Replace the grants on live items only. Grants on retired items stay until
    -- an admin deletes the retired resource.
    delete from public.identity_role_grants g
     using public.identity_resources res, public.identity_actions a, public.identity_scopes sc
     where g.resource_id = res.id and res.service_id = v_service.id and res.retired_at is null
       and a.id = g.action_id and a.retired_at is null
       and sc.id = g.scope_id and sc.retired_at is null;

    insert into public.identity_role_grants (role_id, resource_id, action_id, scope_id)
    select distinct r.id, res.id, a.id, sc.id
      from public.identity_expand_grants(p_grants) w
      join public.identity_roles r on r.key = w.role_key
      join public.identity_resources res on res.service_id = v_service.id and res.key = w.resource_key
      join public.identity_actions a on a.resource_id = res.id and a.key = w.action_key
      join public.identity_scopes sc on sc.resource_id = res.id and sc.key = w.scope_key;

    v_after := public.identity_service_grants_json(v_service.id);

    update public.identity_services s set grants_version = s.grants_version + 1 where s.id = v_service.id;

    if v_before is distinct from v_after then
        perform public.identity_audit(p_actor, 'service.grants', 'service', p_service, v_before, v_after);
    end if;
    return v_service.grants_version + 1;
end;
$$;

-- ── Services and manifests ───────────────────────────────────────────────────

create or replace function public.identity_register_service(
    p_key text, p_name text, p_description text default '', p_actor uuid default null
)
returns void
language plpgsql
set search_path = ''
as $$
begin
    if exists (select 1 from public.identity_services s where s.key = p_key) then
        raise exception using errcode = '22023', message = 'a service with key ' || p_key || ' already exists';
    end if;
    insert into public.identity_services (key, name, description)
    values (p_key, btrim(p_name), coalesce(p_description, ''));
    -- Gives it the implicit app.use, so it can be granted before its first push.
    perform public.identity_apply_manifest(p_key, '{"resources": {}}'::jsonb, null, false);
    perform public.identity_audit(p_actor, 'service.create', 'service', p_key, null,
                                  jsonb_build_object('name', p_name, 'description', p_description));
end;
$$;

create or replace function public.identity_update_service(
    p_key text, p_name text default null, p_description text default null,
    p_is_active boolean default null, p_actor uuid default null
)
returns void
language plpgsql
set search_path = ''
as $$
declare
    v_before public.identity_services;
    v_after  public.identity_services;
begin
    select * into v_before from public.identity_services s where s.key = p_key;
    if v_before.id is null then
        raise exception using errcode = 'P0002', message = 'service not found: ' || coalesce(p_key, '');
    end if;
    if v_before.is_system and p_is_active is false then
        raise exception using errcode = '22023', message = p_key || ' cannot be deactivated';
    end if;
    update public.identity_services s
       set name = coalesce(nullif(btrim(p_name), ''), s.name),
           description = coalesce(p_description, s.description),
           is_active = coalesce(p_is_active, s.is_active)
     where s.id = v_before.id
    returning * into v_after;
    perform public.identity_audit(p_actor, 'service.update', 'service', p_key,
        jsonb_build_object('name', v_before.name, 'description', v_before.description, 'is_active', v_before.is_active),
        jsonb_build_object('name', v_after.name, 'description', v_after.description, 'is_active', v_after.is_active));
end;
$$;

-- Adds what the manifest names, relabels what changed, retires what is missing.
-- Never creates a grant. The implicit app.use action and every resource's
-- 'all' scope are added here, so manifests never declare them.
create or replace function public.identity_apply_manifest(
    p_service text, p_manifest jsonb, p_actor uuid default null, p_audit boolean default true
)
returns jsonb
language plpgsql
set search_path = ''
as $$
declare
    v_service_id uuid := public.identity_service_id(p_service);
    v_resources  jsonb;
    v_res        record;
    v_res_id     uuid;
    v_res_sort   integer := 0;
    v_item       record;
    v_sort       integer;
    v_before     jsonb;
    v_after      jsonb;
begin
    if jsonb_typeof(coalesce(p_manifest, '{}'::jsonb)) <> 'object' then
        raise exception using errcode = '22023', message = 'manifest must be an object';
    end if;
    v_resources := coalesce(p_manifest->'resources', '{}'::jsonb);
    if jsonb_typeof(v_resources) <> 'object' then
        raise exception using errcode = '22023', message = 'manifest.resources must be an object';
    end if;
    if v_resources ? 'app' then
        raise exception using errcode = '22023', message = 'app is implicit; do not declare it';
    end if;

    select svc.value into v_before
      from jsonb_array_elements(public.identity_policy_snapshot()->'services') as svc(value)
     where svc.value->>'key' = p_service;

    v_resources := jsonb_build_object('app', jsonb_build_object('label', 'The app', 'actions', jsonb_build_array('use')))
                   || v_resources;

    -- Retire everything first; whatever the manifest lists is revived below.
    update public.identity_resources set retired_at = coalesce(retired_at, now()) where service_id = v_service_id;
    update public.identity_actions a set retired_at = coalesce(a.retired_at, now())
      from public.identity_resources res where res.id = a.resource_id and res.service_id = v_service_id;
    update public.identity_scopes sc set retired_at = coalesce(sc.retired_at, now())
      from public.identity_resources res where res.id = sc.resource_id and res.service_id = v_service_id;
    update public.identity_attributes set retired_at = coalesce(retired_at, now()) where service_id = v_service_id;

    for v_res in select key, value from jsonb_each(v_resources) loop
        if jsonb_typeof(v_res.value) <> 'object'
           or jsonb_typeof(coalesce(v_res.value->'actions', '[]'::jsonb)) <> 'array'
           or jsonb_array_length(coalesce(v_res.value->'actions', '[]'::jsonb)) = 0 then
            raise exception using errcode = '22023', message = 'resource ' || v_res.key || ' needs a non-empty actions list';
        end if;
        if v_res.value->'scopes' is not null and jsonb_typeof(v_res.value->'scopes') <> 'object' then
            raise exception using errcode = '22023', message = 'resource ' || v_res.key || ': scopes must be an object';
        end if;
        if coalesce(v_res.value->'scopes', '{}'::jsonb) ? 'all' then
            raise exception using errcode = '22023', message = 'resource ' || v_res.key || ': the all scope is implicit';
        end if;

        v_res_sort := v_res_sort + 1;
        insert into public.identity_resources (service_id, key, label, description, sort, retired_at)
        values (v_service_id, v_res.key,
                coalesce(v_res.value->>'label', initcap(replace(v_res.key, '_', ' '))),
                coalesce(v_res.value->>'description', ''), v_res_sort, null)
        on conflict (service_id, key) do update
           set label = excluded.label, description = excluded.description,
               sort = excluded.sort, retired_at = null
        returning id into v_res_id;

        v_sort := 0;
        for v_item in select value #>> '{}' as key from jsonb_array_elements(v_res.value->'actions') loop
            v_sort := v_sort + 1;
            insert into public.identity_actions (resource_id, key, label, sort, retired_at)
            values (v_res_id, v_item.key, initcap(replace(v_item.key, '_', ' ')), v_sort, null)
            on conflict (resource_id, key) do update
               set label = excluded.label, sort = excluded.sort, retired_at = null;
        end loop;

        insert into public.identity_scopes (resource_id, key, label, sort, is_all, retired_at)
        values (v_res_id, 'all', 'All', 0, true, null)
        on conflict (resource_id, key) do update set retired_at = null, label = 'All', sort = 0;

        v_sort := 0;
        for v_item in select key, value #>> '{}' as label from jsonb_each(coalesce(v_res.value->'scopes', '{}'::jsonb)) loop
            v_sort := v_sort + 1;
            insert into public.identity_scopes (resource_id, key, label, sort, is_all, retired_at)
            values (v_res_id, v_item.key, coalesce(v_item.label, initcap(replace(v_item.key, '_', ' '))), v_sort, false, null)
            on conflict (resource_id, key) do update
               set label = excluded.label, sort = excluded.sort, retired_at = null;
        end loop;
    end loop;

    v_sort := 0;
    for v_item in select key, value from jsonb_each(coalesce(p_manifest->'attributes', '{}'::jsonb)) loop
        v_sort := v_sort + 1;
        if coalesce(v_item.value->>'kind', 'enum') <> 'enum'
           or jsonb_typeof(coalesce(v_item.value->'options', '[]'::jsonb)) <> 'array'
           or jsonb_array_length(coalesce(v_item.value->'options', '[]'::jsonb)) = 0 then
            raise exception using errcode = '22023', message = 'attribute ' || v_item.key || ' must be an enum with options';
        end if;
        insert into public.identity_attributes (service_id, key, label, kind, options, sort, retired_at)
        values (v_service_id, v_item.key,
                coalesce(v_item.value->>'label', initcap(replace(v_item.key, '_', ' '))), 'enum',
                array(select jsonb_array_elements_text(v_item.value->'options')), v_sort, null)
        on conflict (service_id, key) do update
           set label = excluded.label, options = excluded.options, sort = excluded.sort, retired_at = null;
    end loop;

    update public.identity_services s set manifest_pushed_at = now() where s.id = v_service_id;

    select svc.value into v_after
      from jsonb_array_elements(public.identity_policy_snapshot()->'services') as svc(value)
     where svc.value->>'key' = p_service;
    if p_audit and v_before is distinct from v_after then
        perform public.identity_audit(p_actor, 'service.manifest', 'service', p_service,
                                      v_before->'resources', v_after->'resources');
    end if;
    return v_after;
end;
$$;

create or replace function public.identity_delete_retired_resource(
    p_service text, p_resource text, p_actor uuid default null
)
returns void
language plpgsql
set search_path = ''
as $$
declare
    v_res public.identity_resources;
begin
    select res.* into v_res from public.identity_resources res
     where res.service_id = public.identity_service_id(p_service) and res.key = p_resource;
    if v_res.id is null then
        raise exception using errcode = 'P0002', message = 'resource not found: ' || p_service || '.' || p_resource;
    end if;
    if v_res.retired_at is null then
        raise exception using errcode = '22023',
            message = p_resource || ' is still in the ' || p_service || ' manifest; only retired resources can be deleted';
    end if;
    delete from public.identity_resources res where res.id = v_res.id;
    perform public.identity_audit(p_actor, 'service.resource.delete', 'service', p_service,
                                  jsonb_build_object('resource', p_resource), null);
end;
$$;

-- ── Service keys ─────────────────────────────────────────────────────────────

create or replace function public.identity_create_service_key(
    p_service text, p_key_hash text, p_key_prefix text, p_label text default '', p_actor uuid default null
)
returns uuid
language plpgsql
set search_path = ''
as $$
declare
    v_id uuid;
begin
    insert into public.identity_service_keys (service_id, key_hash, key_prefix, label, created_by)
    values (public.identity_service_id(p_service), p_key_hash, p_key_prefix, coalesce(p_label, ''), p_actor)
    returning id into v_id;
    perform public.identity_audit(p_actor, 'service.key.create', 'service', p_service, null,
                                  jsonb_build_object('key_id', v_id, 'prefix', p_key_prefix, 'label', p_label));
    return v_id;
end;
$$;

create or replace function public.identity_revoke_service_key(
    p_service text, p_key_id uuid, p_actor uuid default null
)
returns void
language plpgsql
set search_path = ''
as $$
declare
    v_prefix text;
begin
    update public.identity_service_keys k
       set revoked_at = coalesce(k.revoked_at, now())
     where k.id = p_key_id and k.service_id = public.identity_service_id(p_service)
    returning k.key_prefix into v_prefix;
    if v_prefix is null then
        raise exception using errcode = 'P0002', message = 'key not found';
    end if;
    perform public.identity_audit(p_actor, 'service.key.revoke', 'service', p_service,
                                  jsonb_build_object('key_id', p_key_id, 'prefix', v_prefix), null);
end;
$$;

-- ── Privileges ───────────────────────────────────────────────────────────────

alter table public.identity_services        enable row level security;
alter table public.identity_service_keys    enable row level security;
alter table public.identity_resources       enable row level security;
alter table public.identity_actions         enable row level security;
alter table public.identity_scopes          enable row level security;
alter table public.identity_attributes      enable row level security;
alter table public.identity_roles           enable row level security;
alter table public.identity_role_grants     enable row level security;
alter table public.identity_user_roles      enable row level security;
alter table public.identity_user_attributes enable row level security;
alter table public.identity_audit_log       enable row level security;

revoke all on public.identity_services, public.identity_service_keys, public.identity_resources,
              public.identity_actions, public.identity_scopes, public.identity_attributes,
              public.identity_roles, public.identity_role_grants, public.identity_user_roles,
              public.identity_user_attributes, public.identity_audit_log,
              public.identity_user_attribute_values
    from anon, authenticated;

-- Append-only, for every role including the service role, which bypasses RLS
-- but not table privileges.
revoke update, delete, truncate on public.identity_audit_log from public, anon, authenticated, service_role;

do $$
declare
    fn text;
begin
    foreach fn in array array[
        'identity_audit(uuid, text, text, text, jsonb, jsonb)',
        'identity_service_id(text)',
        'identity_user_role_keys(uuid)',
        'identity_service_grants_json(uuid)',
        'identity_policy_snapshot()',
        'identity_set_user_roles(uuid, text[], uuid)',
        'identity_set_user_attributes(uuid, text, jsonb, uuid)',
        'identity_upsert_role(text, text, text, integer, text, uuid)',
        'identity_delete_role(text, uuid)',
        'identity_expand_grants(jsonb)',
        'identity_set_service_grants(text, jsonb, integer, uuid, boolean)',
        'identity_register_service(text, text, text, uuid)',
        'identity_update_service(text, text, text, boolean, uuid)',
        'identity_apply_manifest(text, jsonb, uuid, boolean)',
        'identity_delete_retired_resource(text, text, uuid)',
        'identity_create_service_key(text, text, text, text, uuid)',
        'identity_revoke_service_key(text, uuid, uuid)',
        'identity_roles_guard()',
        'identity_user_roles_copy_group()'
    ] loop
        execute format('revoke execute on function public.%s from public, anon, authenticated', fn);
        execute format('grant execute on function public.%s to service_role', fn);
    end loop;
end;
$$;
