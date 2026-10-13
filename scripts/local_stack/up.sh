#!/usr/bin/env bash
# A local stand-in for a Supabase project, for running Identity and the admin
# console without Supabase credentials: Postgres 15 with db/001-005 applied and
# a few test users, PostgREST behind /rest/v1 like Supabase, on localhost:54321.
# Supabase Auth itself is stubbed by run_identity.py. Needs Docker.
#
#   scripts/local_stack/up.sh && python scripts/local_stack/run_identity.py
#   scripts/local_stack/down.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
SECRET=local-stack-jwt-secret-at-least-32-characters

# Docker on Windows needs a Windows path for the bind mount.
CONF="$HERE/nginx.conf"
if command -v cygpath >/dev/null 2>&1; then CONF="$(cygpath -w "$CONF")"; fi

docker rm -f idlocal-pg idlocal-pgrst idlocal-nginx >/dev/null 2>&1 || true
docker network create idlocal >/dev/null 2>&1 || true

docker run -d --name idlocal-pg --network idlocal -e POSTGRES_PASSWORD=local -p 55433:5432 postgres:15 >/dev/null
until docker exec idlocal-pg pg_isready -U postgres >/dev/null 2>&1; do sleep 1; done
sleep 2
for f in tests/db/supabase_stub.sql db/001_schema.sql db/002_access_token_hook.sql db/003_revoke_sessions.sql \
         tests/db/existing_roster.sql db/004_permissions.sql db/005_seed_permissions.sql; do
  docker exec -i idlocal-pg psql -U postgres -v ON_ERROR_STOP=1 -q -X -o /dev/null < "$REPO/$f" 2>&1 | grep -v NOTICE || true
done

docker run -d --name idlocal-pgrst --network idlocal \
  -e PGRST_DB_URI=postgres://postgres:local@idlocal-pg:5432/postgres \
  -e PGRST_DB_SCHEMAS=public -e PGRST_DB_ANON_ROLE=anon -e PGRST_JWT_SECRET=$SECRET \
  postgrest/postgrest:v12.2.3 >/dev/null
docker run -d --name idlocal-nginx --network idlocal -p 54321:80 -v "$CONF:/etc/nginx/nginx.conf:ro" nginx:1.27-alpine >/dev/null

echo "Local stack up: Postgres on localhost:55433, PostgREST on http://localhost:54321/rest/v1"
