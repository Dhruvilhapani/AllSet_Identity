-- Custom Access Token Hook — the load-bearing piece of the performance design.
--
-- Supabase calls this whenever it mints an access token, letting us stamp the
-- user's role set into the JWT itself. That is what makes /v1/introspect a
-- pure-CPU operation: the gateway verifies the signature against cached JWKS
-- and reads the claim, with zero database or Supabase round trips on the hot
-- path. Without this hook every authenticated request in both apps would cost
-- a lookup against this project from Cloud Run.
--
-- After applying, register it in the Supabase dashboard:
--   Authentication -> Hooks -> Customize Access Token (JWT) Claims
--   -> Postgres -> public.custom_access_token_hook
--
-- Idempotent: safe to re-run.

create or replace function public.custom_access_token_hook(event jsonb)
returns jsonb
language plpgsql
-- stable, not volatile: the hook only reads. Supabase requires it not mutate.
stable
security definer
set search_path = public
as $$
declare
    profile      public.user_profiles;
    claims       jsonb;
    app_metadata jsonb;
begin
    select * into profile
    from public.user_profiles
    where user_id = (event->>'user_id')::uuid;

    claims := coalesce(event->'claims', '{}'::jsonb);
    app_metadata := coalesce(claims->'app_metadata', '{}'::jsonb);

    if profile.user_id is null then
        -- An auth.users row with no profile: fail closed. The gateway will see
        -- an empty role set plus is_active false and deny both apps, rather
        -- than treating a half-provisioned account as a valid login.
        app_metadata := app_metadata || jsonb_build_object(
            'roles', '[]'::jsonb,
            'is_active', false
        );
    else
        app_metadata := app_metadata || jsonb_build_object(
            'roles', to_jsonb(profile.roles),
            'is_active', profile.is_active,
            'full_name', profile.full_name
        );
    end if;

    claims := jsonb_set(claims, '{app_metadata}', app_metadata);
    return jsonb_set(event, '{claims}', claims);
end;
$$;

comment on function public.custom_access_token_hook(jsonb) is
    'Stamps roles/is_active into every issued JWT so token introspection needs no DB read.';

-- Only Supabase's auth service may run the hook, and it needs to read the table
-- the hook selects from. Everything else is revoked: an anon or authenticated
-- caller must not be able to invoke it or read the roster.
grant usage on schema public to supabase_auth_admin;
grant execute on function public.custom_access_token_hook(jsonb) to supabase_auth_admin;
grant select on public.user_profiles to supabase_auth_admin;

revoke execute on function public.custom_access_token_hook(jsonb) from authenticated, anon, public;

-- The hook runs as its owner (security definer) and RLS is enabled on
-- user_profiles with no policies, so grant auth_admin an explicit bypass policy
-- scoped to reading only.
drop policy if exists auth_admin_reads_profiles on public.user_profiles;
create policy auth_admin_reads_profiles
    on public.user_profiles
    for select
    to supabase_auth_admin
    using (true);
