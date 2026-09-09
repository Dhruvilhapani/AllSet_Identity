-- Pre-flight check. READ-ONLY — changes nothing. Run this before 001_schema.sql
-- against any database you have not applied it to before.
--
-- Why this file exists: the identity schema shares a Supabase project with
-- other schemas, and the two ways it can go wrong are both SILENT rather than
-- errors.
--
--   * `create or replace function` matches on name plus argument signature, so
--     a function that already exists is REPLACED with no warning. This caught
--     a real one: the call_logs project already had public.set_updated_at()
--     with three live triggers attached. Ours is now
--     identity_set_updated_at() for that reason.
--   * `create table if not exists` SKIPS creation when the name is taken, and
--     every statement after it then operates on somebody else's table.
--
-- Expected result: every count 0. `citext` may be 1 on some projects, which is
-- fine — the extension is additive.
--
-- If set_updated_at() or user_profiles comes back non-zero on a NEW target,
-- rename the colliding object in 001_schema.sql before applying it. Do not
-- "just run it and see".

select 'TABLE public.user_profiles' as object, count(*) as found
  from information_schema.tables
 where table_schema = 'public' and table_name = 'user_profiles'

union all
select 'FUNCTION identity_set_updated_at()', count(*)
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public'
   and p.proname = 'identity_set_updated_at'
   and p.pronargs = 0

union all
select 'FUNCTION custom_access_token_hook', count(*)
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
 where n.nspname = 'public' and p.proname = 'custom_access_token_hook'

union all
select 'EXTENSION citext', count(*)
  from pg_extension where extname = 'citext';


-- Context, not a gate: what else in this database maintains updated_at, and
-- which triggers depend on it. Useful when deciding whether a future rename is
-- safe. On the call_logs project this returns three rows.
select p.proname            as function_name,
       c.relname            as table_name,
       t.tgname             as trigger_name
  from pg_trigger t
  join pg_proc  p on p.oid = t.tgfoid
  join pg_class c on c.oid = t.tgrelid
 where not t.tgisinternal
   and p.proname like '%updated_at%'
 order by c.relname, t.tgname;
