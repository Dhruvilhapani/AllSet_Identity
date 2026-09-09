-- Admin-side session revocation.
--
-- Why this exists: GoTrue has no HTTP endpoint that revokes another user's
-- sessions. `POST /admin/users/{id}/logout` does not exist — it returns 404
-- "page not found" — and `POST /logout?scope=global` requires the user's own
-- access token, which an admin does not have. Verified empirically against a
-- live project, not assumed.
--
-- Without this, removing someone's role only takes effect once their access
-- token expires: up to the token lifetime plus each consumer's 60s
-- introspection cache. Since roles gate access to customer PII, that window is
-- worth closing rather than documenting.
--
-- The auth schema is not exposed through PostgREST, so the service role
-- reaches it through this security-definer function via
-- POST /rest/v1/rpc/identity_revoke_user_sessions.
--
-- Idempotent: safe to re-run. Run db/000_preflight.sql first on a new database.

create or replace function public.identity_revoke_user_sessions(target_user_id uuid)
returns integer
language plpgsql
security definer
-- Empty search_path with fully-qualified names: a security-definer function
-- runs as its owner, so a mutable search_path is how these get hijacked.
set search_path = ''
as $$
declare
    removed_refresh integer := 0;
    removed_sessions integer := 0;
begin
    -- auth.refresh_tokens.user_id is varchar in GoTrue's schema, not uuid.
    delete from auth.refresh_tokens where user_id = target_user_id::text;
    get diagnostics removed_refresh = row_count;

    -- auth.sessions arrived in later GoTrue versions; tolerate its absence so
    -- this function works across versions rather than erroring on one.
    begin
        delete from auth.sessions where user_id = target_user_id;
        get diagnostics removed_sessions = row_count;
    exception
        when undefined_table then removed_sessions := 0;
    end;

    return removed_refresh + removed_sessions;
end;
$$;

comment on function public.identity_revoke_user_sessions(uuid) is
    'Revokes every session for one user. Called by the identity service on role '
    'change and deactivation, because GoTrue exposes no admin logout endpoint.';

-- Only the service role may call it. It deletes from auth, so a leaked anon or
-- authenticated key must not be able to sign other people out.
revoke execute on function public.identity_revoke_user_sessions(uuid)
    from public, anon, authenticated;
grant execute on function public.identity_revoke_user_sessions(uuid) to service_role;
