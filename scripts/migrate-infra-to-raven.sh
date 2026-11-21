#!/usr/bin/env bash
# One-shot migration of the shared dev infra from the old "asi" compose project
# to "raven" (task N1). Run it once, from a checkout that already has the RAVEN
# code, after stopping every `make dev` that uses the shared database:
#
#   scripts/migrate-infra-to-raven.sh [--from asi] [--to raven] [--env-file <main checkout>/.env]
#
# What it does (each step is skipped when already done, so re-running is safe):
#   1. backs up the env file to <env-file>.asi-backup and renames ASI_* to RAVEN_*
#      (RAVEN_DOJO_ORGANIZATION=ASI becomes RAVEN);
#   2. stops the containers of the old project (they are kept, not removed);
#   3. copies every volume of the old project into a new one for the new project
#      (asi-db-data -> raven-db-data, defectdojo_* keep their names); the old volumes
#      are kept for rollback;
#   4. starts raven-db and renames the role and database asi -> raven, and the
#      per-worktree databases asi_<slug> -> raven_<slug>;
#   5. starts the rest of the infra and renames the Dojo organization "ASI" and
#      the "ASI Planning" asset to their RAVEN names.
#
# Rollback: docker compose -p raven down; restore the .env backup; start the old
# checkout's `make infra-up` (its volumes are untouched).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

from=asi to=raven
env_file="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")/.env"
while [[ $# -gt 0 ]]; do
  case $1 in
    --from) from=$2; shift 2 ;;
    --to) to=$2; shift 2 ;;
    --env-file) env_file=$2; shift 2 ;;
    *) echo "usage: $0 [--from asi] [--to raven] [--env-file path]" >&2; exit 2 ;;
  esac
done
compose=(docker compose -p "$to" --env-file "$env_file")
infra=$(sed -n 's/^INFRA_SERVICES := //p' Makefile)
step() { echo "── $*"; }

# 1. env file
[[ -f $env_file ]] || { echo "no env file $env_file" >&2; exit 1; }
if grep -q '^ASI_' "$env_file"; then
  step "renaming ASI_* -> RAVEN_* in $env_file (backup: $env_file.asi-backup)"
  [[ -e $env_file.asi-backup ]] || cp -p "$env_file" "$env_file.asi-backup"
  sed -i -e 's/^ASI_/RAVEN_/' -e 's/^RAVEN_DOJO_ORGANIZATION=ASI$/RAVEN_DOJO_ORGANIZATION=RAVEN/' "$env_file"
fi
set -a; . "$env_file"; set +a

# 2. stop the old project
old_running=$(docker ps -q --filter "label=com.docker.compose.project=$from")
if [[ -n $old_running ]]; then
  step "stopping compose project $from"
  # shellcheck disable=SC2086
  docker stop $old_running >/dev/null
fi

# 3. copy volumes
image=$(sed -n 's/^ *image: \(postgres:.*\)$/\1/p' compose.yml | head -1)
for old in $(docker volume ls -q --filter "label=com.docker.compose.project=$from"); do
  vol=$(docker volume inspect -f '{{index .Labels "com.docker.compose.volume"}}' "$old")
  newvol=${vol/#asi-/raven-}
  new="${to}_${newvol}"
  if docker volume inspect "$new" >/dev/null 2>&1; then
    echo "volume $new exists, skipping copy from $old"
    continue
  fi
  step "copying volume $old -> $new"
  docker volume create --label "com.docker.compose.project=$to" \
    --label "com.docker.compose.volume=$newvol" "$new" >/dev/null
  docker run --rm -v "$old:/from:ro" -v "$new:/to" "$image" cp -a /from/. /to/
done

# 4. raven-db: role, database, worktree databases
step "starting raven-db"
"${compose[@]}" up -d raven-db >/dev/null
for _ in $(seq 60); do
  "${compose[@]}" exec -T raven-db pg_isready -q && break
  sleep 1
done
psql_as() { "${compose[@]}" exec -T raven-db psql -v ON_ERROR_STOP=1 -qtA -U "$1" -d postgres -c "$2"; }
if psql_as asi 'SELECT 1' >/dev/null 2>&1; then
  step "renaming role/database asi -> raven"
  psql_as asi "CREATE ROLE n1_migrate SUPERUSER LOGIN"
  psql_as n1_migrate "ALTER ROLE asi RENAME TO raven"
  psql_as n1_migrate "ALTER ROLE raven PASSWORD '${RAVEN_DB_PASSWORD}'"
  psql_as raven "DROP ROLE n1_migrate"
fi
if [[ $(psql_as raven "SELECT 1 FROM pg_database WHERE datname = 'asi'") == 1 ]]; then
  psql_as raven 'ALTER DATABASE asi RENAME TO raven'
fi
for db in $(psql_as raven "SELECT datname FROM pg_database WHERE datname LIKE 'asi\_%'"); do
  target="raven_${db#asi_}"
  if [[ $(psql_as raven "SELECT 1 FROM pg_database WHERE datname = '$target'") == 1 ]]; then
    echo "database $target exists, keeping $db"
  else
    step "renaming database $db -> $target"
    psql_as raven "ALTER DATABASE \"$db\" RENAME TO \"$target\""
  fi
done

# 5. the rest of the infra, Dojo names
step "starting infra ($to)"
# shellcheck disable=SC2086
"${compose[@]}" up -d $infra >/dev/null
for _ in $(seq 120); do
  "${compose[@]}" exec -T postgres pg_isready -q 2>/dev/null && break
  sleep 2
done
step "renaming Dojo organization ASI and asset 'ASI Planning'"
"${compose[@]}" exec -T postgres psql -v ON_ERROR_STOP=1 -qtA \
  -U "${DD_DATABASE_USER:-defectdojo}" -d "${DD_DATABASE_NAME:-defectdojo}" <<'SQL'
UPDATE dojo_product_type SET name = 'RAVEN'
 WHERE name = 'ASI' AND NOT EXISTS (SELECT 1 FROM dojo_product_type WHERE name = 'RAVEN');
UPDATE dojo_product SET name = 'RAVEN Planning'
 WHERE name = 'ASI Planning' AND NOT EXISTS (SELECT 1 FROM dojo_product WHERE name = 'RAVEN Planning');
SQL

echo "done: re-run scripts/wt-env.sh in every worktree (env vars and DB names changed)."
