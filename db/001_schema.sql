-- AllSet Identity — profile + role storage.
--
-- Runs against the **call_logs** Supabase project (qizrtmvgcwxuycbpkeua,
-- ap-northeast-2), chosen because the free tier allows only two projects and a
-- dedicated third one was not available. auth.users therefore lives alongside
-- Broker Tools' leads schema.
--
-- Two consequences of sharing that project, recorded here because they are not
-- obvious from the code:
--
--   1. db/README.md in AllSet_Broker_Tools describes 001_schema.sql there as a
--      scripted replacement of this project. That rebuild is now also an auth
--      migration: the JWT signing key is per-project, so moving would
--      invalidate every issued token and log everyone out. A rebuild must
--      apply this file too, or the new database has no profiles.
--   2. The service_role key for this project reaches every lead, note and call
--      record, not just identity data. It belongs only in the identity
--      service's environment.
--
-- This file adds exactly one table to `public` and two functions. The `auth`
-- schema is provisioned by Supabase in every project and is not touched here.
-- See db/002_access_token_hook.sql for the JWT claim injection that keeps
-- /v1/introspect free of any database round trip.
--
-- Idempotent: safe to re-run.

create extension if not exists citext;

create table if not exists public.user_profiles (
    user_id            uuid        primary key references auth.users(id) on delete cascade,
    -- citext because every account is an @allset.in address typed by a human,
    -- and the legacy CMS lookup during shadow migration joins on it.
    email              citext      not null unique,
    full_name          text        not null default '',
    roles              text[]      not null default '{}',
    phone              text        not null default '',
    is_active          boolean     not null default true,
    -- Stamped the first time a legacy Django PBKDF2 password is upgraded to
    -- Supabase. Non-null for every row means the shadow-migration path can be
    -- switched off and deleted.
    legacy_migrated_at timestamptz,
    created_at         timestamptz not null default now(),
    updated_at         timestamptz not null default now(),

    -- The role set is the one piece of state that must never be wrong, so both
    -- rules are enforced here as well as in app/capabilities.py. Neither uses a
    -- subquery: Postgres forbids those in CHECK constraints.

    -- Every element must be a known role. `<@` is "contained by".
    constraint roles_valid check (
        roles <@ array['admin', 'tech', 'manager', 'editor', 'viewer',
                       'lead_manager', 'presales', 'sales']::text[]
    ),
    -- At most one desk role. `@>` is "contains all", so this rejects a set
    -- holding presales AND sales while allowing either alone or neither.
    -- team_members.role over in call_logs is single-valued and drives
    -- call_sync.py's owner auto-assignment, which is why both is not allowed.
    constraint roles_one_desk check (
        not (roles @> array['presales', 'sales']::text[])
    ),
    -- A NULL element would slip past both operators above.
    constraint roles_no_nulls check (
        array_position(roles, null) is null
    )
);

comment on table public.user_profiles is
    'One row per person. Roles combine as a union; see app/capabilities.py for the matrix.';
comment on column public.user_profiles.roles is
    'Union-combined role set. Empty means the account exists with no app access '
    '(the offboarding state), which is distinct from is_active = false.';

-- Lookup by email happens on every shadow-migrated login; the unique constraint
-- above already provides the index, so no extra one is needed.

-- Deliberately NOT named set_updated_at(). The call_logs database this shares
-- already has a public.set_updated_at() with three live triggers attached, and
-- `create or replace` matches on name plus argument signature — so the generic
-- name would have silently swapped the body out from under all three. The
-- bodies are probably identical, but "probably" is not a good enough reason to
-- rewrite a function three triggers depend on.
create or replace function public.identity_set_updated_at()
returns trigger
language plpgsql
as $$
begin
    new.updated_at := now();
    return new;
end;
$$;

drop trigger if exists user_profiles_set_updated_at on public.user_profiles;
create trigger user_profiles_set_updated_at
    before update on public.user_profiles
    for each row execute function public.identity_set_updated_at();

-- RLS is enabled with no policies. Only the identity service touches this table
-- and it connects with the service-role key, which bypasses RLS. Enabling it
-- anyway means a leaked anon key reads nothing rather than the whole roster.
alter table public.user_profiles enable row level security;

revoke all on public.user_profiles from anon, authenticated;
