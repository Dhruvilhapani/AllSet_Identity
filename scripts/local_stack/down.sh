#!/usr/bin/env bash
# Remove the local stack started by up.sh.
docker rm -f idlocal-pg idlocal-pgrst idlocal-nginx >/dev/null 2>&1 || true
docker network rm idlocal >/dev/null 2>&1 || true
echo "Local stack removed"
