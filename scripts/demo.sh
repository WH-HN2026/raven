#!/usr/bin/env bash
# One-command demo (docs/vuln-lab.md §6): RAVEN + DefectDojo + the vuln lab, seeded and scanned.
#
#   scripts/demo.sh up [--scale[=N]] [--l1] [--no-run]   # make demo ARGS="…"; idempotent
#   scripts/demo.sh down                                   # make demo-down; data kept
#   scripts/demo.sh reset                                  # make demo-reset; deletes volumes (CONFIRM=1 skips the question)
#
# Environment (for testing next to a running lab; the jury needs none of these):
#   DEMO_LAB=shared          use the vuln lab (and L1 / scale layer) that is already running; never start,
#                            stop or delete them
#   DEMO_COMPOSE_OVERRIDE=f  one more compose file for the RAVEN stack (e.g. another image tag or RAVEN address)
#   COMPOSE_PROJECT_NAME     Docker Compose's own variable; overrides the project name `raven`
set -euo pipefail

cd "$(dirname "$0")/.."
. scripts/lib/raven-api.sh

DEMO_PROFILE=vuln-lab
SCALE_PROFILE=vuln-lab-scale
SCALE_CIDR=10.77.64.0/18
CREDS=.demo-credentials

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }
warn() { printf 'demo: warning: %s\n' "$*" >&2; }
die() {
  printf 'demo: %s\n' "$*" >&2
  exit 1
}

shared_lab() { [ "${DEMO_LAB:-}" = shared ]; }

# env_or VAR DEFAULT: VAR from .env, else DEFAULT.
env_or() { raven_env "$1" 2>/dev/null || printf '%s\n' "$2"; }

# compose files for the RAVEN stack; --l1 adds the L1 network override.
raven_compose() {
  local files=(-f compose.yml -f lab/vuln/raven.compose.yml)
  [ "${WITH_L1:-0}" = 1 ] && files+=(-f lab/raven.compose.yml)
  [ -n "${DEMO_COMPOSE_OVERRIDE:-}" ] && files+=(-f "$DEMO_COMPOSE_OVERRIDE")
  docker compose "${files[@]}" "$@"
}

project_running() { [ -n "$(raven_compose ps -q raven 2>/dev/null)" ]; }
lab_running() { [ -n "$(docker compose -f "$1" ps -q 2>/dev/null)" ]; }
have_scale() { [ -x scripts/vlab-scale.sh ]; }

# ───────────────────────── up ─────────────────────────

preflight() {
  say "preflight"
  command -v docker >/dev/null || die "docker not found"
  docker compose version >/dev/null 2>&1 || die "Docker Compose v2 (docker compose) not found"
  command -v curl >/dev/null || die "curl not found"
  command -v jq >/dev/null || die "jq not found"
  docker info >/dev/null 2>&1 || die "cannot talk to the Docker daemon"

  if [ "$SCALE" != 0 ] && ! have_scale; then
    die "--scale needs scripts/vlab-scale.sh (the scale layer, roadmap V4), which is not in this checkout yet"
  fi

  # Host ports: only when this stack isn't already running (then they are ours).
  if ! project_running; then
    local p name busy=""
    for name in RAVEN_PORT:8000 DD_PORT:8080 DD_TLS_PORT:8443 RAVEN_DB_PORT:5433; do
      p=$(env_or "${name%%:*}" "${name#*:}")
      if command -v ss >/dev/null && [ -n "$(ss -Hltn "sport = :$p" 2>/dev/null)" ]; then
        busy+=" ${name%%:*}=$p"
      fi
    done
    [ -z "$busy" ] || die "host ports in use:$busy. Set other values in .env (and RAVEN_DOJO_PUBLIC_URL=http://localhost:<DD_PORT>)."
  fi

  lab/vuln/preflight.sh

  local mem_kb disk_kb
  mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  [ "${mem_kb:-0}" -ge $((8 * 1024 * 1024)) ] || warn "less than 8 GB RAM; RAVEN + DefectDojo + the vuln lab need about 4 GB"
  disk_kb=$(df -Pk "$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo .)" 2>/dev/null | awk 'NR == 2 {print $4}')
  [ "${disk_kb:-0}" -ge $((20 * 1024 * 1024)) ] || warn "less than 20 GB free disk for Docker; the images need about 12 GB"
  echo "Docker Hub limits anonymous pulls (100 per 6 h per IP); run 'docker login' first if a pull fails with 429."
}

ensure_env() {
  if [ -f .env ]; then
    echo ".env exists; keeping it"
  else
    scripts/gen-env.sh
  fi
}

start_labs() {
  if shared_lab; then
    say "DEMO_LAB=shared: using the running vuln lab"
    docker network inspect raven_vlab >/dev/null 2>&1 || die "DEMO_LAB=shared but network raven_vlab does not exist (make vlab-up)"
    [ "$WITH_L1" = 0 ] || docker network inspect raven_lab >/dev/null 2>&1 || die "DEMO_LAB=shared but network raven_lab does not exist (make lab-up)"
  else
    say "vuln lab"
    make vlab-pull
    make vlab-up
    if [ "$WITH_L1" = 1 ]; then
      say "L1 lab"
      make lab-up
    fi
  fi
  if [ "$SCALE" != 0 ]; then
    say "scale layer ($SCALE hosts)"
    scripts/vlab-scale.sh up "$SCALE"
  fi
}

start_raven() {
  say "RAVEN + DefectDojo"
  raven_compose up -d --build
}

wait_ready() {
  say "waiting for RAVEN and its DefectDojo connection (up to 10 min)"
  local start now last=0
  start=$(date +%s)
  until curl -fsS -o /dev/null "$(raven_url)/api/healthz" 2>/dev/null &&
    raven_compose logs raven 2>/dev/null | grep 'dojo bootstrap done' >/dev/null; do
    now=$(date +%s)
    [ $((now - start)) -lt 600 ] || die "RAVEN not ready after 10 min; see: docker compose logs raven"
    if [ $((now - last)) -ge 15 ]; then
      echo "  … $((now - start)) s (healthz, then 'dojo bootstrap done' in the raven log; DefectDojo's first boot takes a few minutes)"
      last=$now
    fi
    sleep 3
  done
  echo "RAVEN ready at $(raven_url) after $(($(date +%s) - start)) s"
}

# global_exclude VALUE NOTE
global_exclude() {
  if raven_get "/scope?limit=1000" | jq -e --arg v "$1" '.items[] | select(.list == "exclude" and .value == $v and .profile_id == null)' >/dev/null; then
    echo "  exclude $1: exists"
  else
    RAVEN_OK=409 raven_post /scope "$(jq -cn --arg v "$1" --arg n "$2" '{value: $v, list: "exclude", note: $n}')" >/dev/null
    echo "  exclude $1: created"
  fi
}

check_blacklist() {
  local v missing=""
  for v in "${BLACKLIST[@]}"; do
    raven_get "/scope?limit=1000" | jq -e --arg v "$v" '.items[] | select(.list == "exclude" and .value == $v and .profile_id == null)' >/dev/null ||
      missing+=" $v"
  done
  [ -z "$missing" ] || die "global blacklist entries missing:$missing; refusing to continue"
}

# profile_id NAME: print the id or nothing.
profile_id() {
  raven_get "/profiles?limit=1000" | jq -r --arg n "$1" '.items[] | select(.name == $n) | .id'
}

# seed_profile JSON INCLUDE: create the profile or PUT it back to the seed values, then its include entry.
seed_profile() {
  local body=$1 include=$2 name id
  name=$(jq -r .name <<<"$body")
  id=$(profile_id "$name")
  if [ -n "$id" ]; then
    raven_put "/profiles/$id" "$body" >/dev/null
    echo "  profile $name: reset to the seed values (id $id)"
  else
    id=$(raven_post /profiles "$body" | jq -r .id)
    echo "  profile $name: created (id $id)"
  fi
  if raven_get "/scope?profile_id=$id&limit=1000" | jq -e --arg v "$include" '.items[] | select(.list == "include" and .value == $v)' >/dev/null; then
    echo "  profile $name include $include: exists"
  else
    RAVEN_OK=409 raven_post /scope "$(jq -cn --arg v "$include" --argjson p "$id" '{value: $v, list: "include", profile_id: $p, note: "demo seed"}')" >/dev/null
    echo "  profile $name include $include: created"
  fi
}

seed_users() {
  local role user pass var existing
  existing=$(raven_get "/users?limit=1000" | jq -r '.items[].username')
  if [ ! -f "$CREDS" ]; then
    (umask 077 && printf '# demo users created by scripts/demo.sh (username = demo-<role>)\n' >"$CREDS")
  fi
  chmod 600 "$CREDS"
  for role in editor operator viewer; do
    user=demo-$role
    var=DEMO_${role^^}_PASSWORD
    if grep -qx "$user" <<<"$existing"; then
      if grep -q "^$var=" "$CREDS"; then
        echo "  user $user: exists"
      else
        echo "  user $user: exists, password not in $CREDS (kept; reset it on the Users page)"
      fi
      continue
    fi
    pass=$(head -c 18 /dev/urandom | base64 | tr '+/' '-_')
    raven_post /users "$(jq -cn --arg u "$user" --arg p "$pass" --arg r "$role" '{username: $u, password: $p, role: $r}')" >/dev/null
    sed -i "/^$var=/d" "$CREDS"
    printf '%s=%s\n' "$var" "$pass" >>"$CREDS"
    echo "  user $user: created ($role)"
  done
}

seed() {
  say "seeding as $ADMIN_USER"
  RAVEN_JAR=$(mktemp)
  trap 'rm -f "$RAVEN_JAR"' EXIT
  raven_login "$ADMIN_USER" "$(raven_env RAVEN_ADMIN_PASSWORD)" || die "admin login failed (RAVEN_ADMIN_PASSWORD in .env)"

  echo "global blacklist:"
  global_exclude 10.77.0.1 "vlab gateway = host"
  global_exclude 10.77.254.0/23 "RAVEN + lab helpers"
  if [ "$WITH_L1" = 1 ]; then
    global_exclude 172.30.0.1 "L1 gateway = host"
    global_exclude 172.30.0.128/25 "L1 lab helpers"
  fi
  check_blacklist

  echo "targets:"
  raven_upload /targets/upload lab/vuln/targets.csv |
    jq -r '"  lab/vuln/targets.csv: \(.targets | length) entries, \(.created) written, \(.errors | length) errors"'
  if [ "$SCALE" != 0 ]; then
    RAVEN_OK=409 raven_post /targets "$(jq -cn --arg v "$SCALE_CIDR" '{targets: [{value: $v, tags: ["vlab", "scale"], note: "vuln lab scale layer"}]}')" >/dev/null
    echo "  $SCALE_CIDR: present"
  fi
  if [ "$WITH_L1" = 1 ]; then
    raven_upload /targets/upload lab/targets.txt |
      jq -r '"  lab/targets.txt: \(.targets | length) entries, \(.created) written, \(.errors | length) errors"'
  fi

  echo "profiles:"
  seed_profile "$(jq -cn --arg ports "$(tr -d '[:space:]' <lab/vuln/ports.txt)" --arg n "$DEMO_PROFILE" '{
    name: $n, ports: $ports, nmap_max_rate: 300, nuclei_rate: 25,
    nuclei_tags: ["tech", "panel", "ssl", "waf", "favicon"], miss_threshold: 2,
    target_batch_seconds: 600, enabled: true, stages: ["nmap", "httpx", "nuclei"]}')" 10.77.0.0/20
  if [ "$SCALE" != 0 ]; then
    seed_profile "$(jq -cn --arg n "$SCALE_PROFILE" '{
      name: $n, ports: "21,22,80,443,8080,8443,9100", nmap_max_rate: 1000, enabled: true,
      stages: ["nmap", "httpx", "nuclei"]}')" "$SCALE_CIDR"
  fi

  echo "users:"
  seed_users
}

first_run() {
  local id run status
  id=$(profile_id "$DEMO_PROFILE")
  run=$(raven_get "/runs?profile_id=$id&limit=1&sort=id&dir=desc" | jq -c '.items[0] // empty')
  status=$(jq -r '.status // empty' <<<"$run")
  if [ "$status" = "done" ]; then
    RUN_ID=$(jq -r .id <<<"$run")
    say "$DEMO_PROFILE already has a finished run (#$RUN_ID); not starting another"
    return
  fi
  check_blacklist
  if [ "$status" = pending ] || [ "$status" = running ] || [ "$status" = suspended ]; then
    RUN_ID=$(jq -r .id <<<"$run")
    say "waiting for the running $DEMO_PROFILE run #$RUN_ID"
  else
    RUN_ID=$(raven_post /runs "$(jq -cn --argjson p "$id" '{profile_id: $p}')" | jq -r .id)
    say "Run 1: $DEMO_PROFILE run #$RUN_ID started"
  fi
  raven_wait_run "$RUN_ID" 3600 || die "run #$RUN_ID did not finish (see the Runs page)"
}

summary() {
  local rp dp run t0 t1 dur="?"
  rp=$(env_or RAVEN_PORT 8000)
  dp=$(env_or DD_PORT 8080)
  if [ -n "${RUN_ID:-}" ]; then
    run=$(raven_get "/runs/$RUN_ID")
    t0=$(jq -r '.started_at // empty' <<<"$run")
    t1=$(jq -r '.finished_at // empty' <<<"$run")
    if [ -n "$t0" ] && [ -n "$t1" ]; then
      dur="$(($(date -d "$t1" +%s) - $(date -d "$t0" +%s))) s"
    fi
    say "$(jq -r --arg d "$dur" '"run #\(.id) (\(.status)): hosts up \(.hosts_up) of \(.hosts_total) scanned, services \(.stats.services_open // "?"), duration \($d)"' <<<"$run")"
  fi
  cat <<EOF

RAVEN       http://localhost:$rp   user $ADMIN_USER, password: grep RAVEN_ADMIN_PASSWORD .env
DefectDojo  http://localhost:$dp   user $(env_or DD_ADMIN_USER admin), password: grep DD_ADMIN_PASSWORD .env
Demo users  demo-editor, demo-operator, demo-viewer; passwords in $CREDS

Next:
  scripts/vlab-scenario.sh status            # scenario steps, docs/vuln-lab.md §4
  scripts/vlab-scenario.sh baseline --run
  make demo-down                             # stop, keep data
  make demo-reset                            # delete all demo data (asks first)
EOF
}

cmd_up() {
  SCALE=0
  WITH_L1=0
  local run=1 a
  for a in "$@"; do
    case $a in
      --scale) SCALE=256 ;;
      --scale=*) SCALE=${a#--scale=} ;;
      --l1) WITH_L1=1 ;;
      --no-run) run=0 ;;
      *) die "unknown option $a (usage: scripts/demo.sh up [--scale[=N]] [--l1] [--no-run])" ;;
    esac
  done
  [[ $SCALE =~ ^[0-9]+$ ]] || die "--scale=N needs a number"
  BLACKLIST=(10.77.0.1 10.77.254.0/23)
  [ "$WITH_L1" = 0 ] || BLACKLIST+=(172.30.0.1 172.30.0.128/25)

  preflight
  ensure_env
  RAVEN_PORT=$(env_or RAVEN_PORT 8000)
  export RAVEN_PORT
  ADMIN_USER=$(env_or RAVEN_ADMIN_USERNAME admin)
  start_labs
  start_raven
  wait_ready
  seed
  [ "$run" = 0 ] || first_run
  summary
}

# ───────────────────────── down / reset ─────────────────────────

# stop_all [-v]
stop_all() {
  say "RAVEN + DefectDojo"
  raven_compose down "$@"
  if shared_lab; then
    echo "DEMO_LAB=shared: leaving the labs running"
    return
  fi
  if have_scale; then
    say "scale layer"
    scripts/vlab-scale.sh down
  fi
  say "vuln lab"
  make vlab-down
  [ $# -eq 0 ] || docker compose -f compose.vlab.yml --profile scenario --profile tools --profile init down "$@"
  if lab_running compose.lab.yml || [ $# -gt 0 ]; then
    say "L1 lab"
    docker compose -f compose.lab.yml down "$@"
  fi
}

cmd_down() { stop_all; }

cmd_reset() {
  if [ "${CONFIRM:-}" != 1 ]; then
    printf 'Delete all RAVEN, DefectDojo and lab data (volumes) and %s? .env is kept. [y/N] ' "$CREDS"
    local answer
    read -r answer
    case $answer in y | Y | yes) ;; *) die "cancelled" ;; esac
  fi
  stop_all -v
  rm -f "$CREDS"
  echo "removed the volumes and $CREDS; .env kept"
}

case ${1:-} in
  up) shift; cmd_up "$@" ;;
  down) cmd_down ;;
  reset) cmd_reset ;;
  *) die "usage: scripts/demo.sh up [--scale[=N]] [--l1] [--no-run] | down | reset" ;;
esac
