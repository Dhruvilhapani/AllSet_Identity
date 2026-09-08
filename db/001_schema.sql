-- AllSet Identity — profile + role storage.
--
-- Runs against the dedicated identity Supabase project (ap-south-1, colocated
-- with Cloud Run asia-south1). This project holds auth.users and nothing else;
-- the CMS's property catalogue and Broker Tools' call_logs stay in their own
-- projects. See db/002_access_token_hook.sql for the JWT claim injection that
-- keeps /v1/introspect free of any database round trip.
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

create or replace function public.set_updated_at()
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
    for each row execute function public.set_updated_at();

-- RLS is enabled with no policies. Only the identity service touches this table
-- and it connects with the service-role key, which bypasses RLS. Enabling it
-- anyway means a leaked anon key reads nothing rather than the whole roster.
alter table public.user_profiles enable row level security;

revoke all on public.user_profiles from anon, authenticated;
