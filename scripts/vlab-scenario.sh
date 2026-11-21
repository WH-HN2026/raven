#!/usr/bin/env bash
# Scenario driver for the vuln lab (docs/vuln-lab.md §4, "Scenario driver" section).
#
#   scripts/vlab-scenario.sh <step> [args] [--run]
#
# Steps (each is idempotent and prints "check:" lines):
#   status                      lab state, RAVEN setup, last runs of the profile
#   baseline                    lab back to baseline (+ blacklist, targets, profile ensured)
#   service-gone | service-back flask-app (10.77.4.20:8787) stopped / started
#   upgrade | downgrade         flask-app nginx 1.20.0-alpine <-> 1.30.7-alpine
#   device-new | device-remove  shadow-IT device 10.77.9.50 (httpd 2.4.49)
#   host-off | host-on          httpbin 10.77.4.10 stopped / started
#   toxic latency <ms>|timeout|slow-close|down|clear    Toxiproxy proxy "wordpress" (10.77.2.11)
#   signature                   editor: custom signature (lab/vuln/scenario/*.yaml), validate + test
#   edit                        operator: host/service/finding edits on 10.77.3.14
#   exchange                    viewer exports, editor imports lab/vuln/scenario/import-sample.json
#   roles                       permission matrix of the four roles (403 vs allowed)
#   window                      vuln-lab-slow profile + 2-minute window: start, suspend, resume
#   dojo-plan                   planned engagement in Dojo "RAVEN Planning" -> schedule -> run
#   walk                        steps 1-7 with runs in between, PASS/FAIL per checkable outcome
#
# --run starts a run of the vuln-lab profile after the step and waits for it.
#
# Environment: RAVEN_URL (default http://localhost:${RAVEN_PORT:-8000}), RAVEN_ENV_FILE (default .env:
# RAVEN_ADMIN_USERNAME/PASSWORD, DD_ADMIN_USER/PASSWORD, DD_PORT), VLAB_CREDENTIALS (default
# .demo-credentials, DEMO_<ROLE>_PASSWORD= lines as scripts/demo.sh writes), VLAB_PROFILE (default vuln-lab),
# VLAB_RUN_TIMEOUT (seconds, default 3600), VLAB_ASYNC_WAIT (walk: seconds to wait for the
# 5-minute CVE/Dojo passes, default 720; 0 skips those checks).
#
# Safety: lab changes go through docker compose (compose.vlab.yml) and Toxiproxy calls are made from a
# one-shot container on raven_vlab, never from the host. No step logs in to a lab service.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT"
# shellcheck source=scripts/lib/raven-api.sh
. scripts/lib/raven-api.sh

PROFILE=${VLAB_PROFILE:-vuln-lab}
SLOW_PROFILE=vuln-lab-slow
CREDS=${VLAB_CREDENTIALS:-.demo-credentials}
RUN_TIMEOUT=${VLAB_RUN_TIMEOUT:-3600}
ASYNC_WAIT=${VLAB_ASYNC_WAIT:-720}
VLAB=(docker compose -f compose.vlab.yml)
FLASK_OLD=1.20.0-alpine
FLASK_NEW=1.30.7-alpine
TOXI=http://10.77.2.11:8474
SIG_FILE=lab/vuln/scenario/vlab-dvwa-security-cookie.yaml
SIG_NAME=vlab-dvwa-security-cookie
IMPORT_FILE=lab/vuln/scenario/import-sample.json
BLACKLIST=("10.77.0.1|vlab gateway = host" "10.77.254.0/23|RAVEN + lab helpers")
VLAB_INCLUDE=10.77.0.0/20
EXPECTED_HOSTS=19

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
PASS=0
FAIL=0
LAST_RUN=""

# ───────────────────────── output ─────────────────────────

say() { printf '== %s\n' "$*"; }
check() { printf 'check: %s\n' "$*"; }
die() {
  printf 'vlab-scenario: %s\n' "$*" >&2
  exit 1
}
ok() {
  PASS=$((PASS + 1))
  printf 'PASS  %s\n' "$1"
}
bad() {
  FAIL=$((FAIL + 1))
  printf 'FAIL  %s\n' "$1"
}
# expect DESC JSON JQ_FILTER: PASS when the filter is true for JSON.
expect() {
  if jq -e "$3" >/dev/null 2>&1 <<<"$2"; then ok "$1"; else bad "$1"; fi
}

# ───────────────────────── RAVEN sessions ─────────────────────────

env_or_file() { # VAR DEFAULT
  local v=${!1:-}
  [ -n "$v" ] || v=$(raven_env "$1" 2>/dev/null) || v=$2
  printf '%s' "$v"
}

admin_user() { env_or_file RAVEN_ADMIN_USERNAME admin; }

# as_user USER PASSWORD: switch to USER's session (one cookie jar per user).
as_user() {
  export RAVEN_JAR="$TMP/$1.jar"
  [ -s "$RAVEN_JAR" ] && return 0
  raven_login "$1" "$2" "$RAVEN_JAR" || {
    rm -f "$RAVEN_JAR"
    die "login as $1 failed ($(raven_url))"
  }
}

as_admin() {
  local pw
  pw=$(env_or_file RAVEN_ADMIN_PASSWORD "")
  [ -n "$pw" ] || die "RAVEN_ADMIN_PASSWORD not found (set it or RAVEN_ENV_FILE)"
  as_user "$(admin_user)" "$pw"
}

cred_var() { printf 'DEMO_%s_PASSWORD' "${1^^}"; } # ROLE -> variable in $CREDS (scripts/demo.sh)

cred_lookup() { # ROLE -> password from $CREDS, or empty
  [ -f "$CREDS" ] || return 0
  RAVEN_ENV_FILE=$CREDS raven_env "$(cred_var "$1")" 2>/dev/null || true
}

# ensure_demo_user ROLE: demo-<role> exists and its password is in $CREDS (created if missing,
# in the same dotenv format scripts/demo.sh writes).
ensure_demo_user() {
  local u=demo-$1 pw x
  pw=$(cred_lookup "$1")
  [ -n "$pw" ] && return 0
  as_admin
  if raven_get "/users?limit=1000" | jq -e --arg u "$u" '.items[] | select(.username == $u)' >/dev/null; then
    die "user $u exists but $CREDS has no password for it"
  fi
  x=$(head -c 64 /dev/urandom | base64 -w0 | tr -dc 'A-Za-z0-9')
  pw=${x:0:24}
  raven_post /users "$(jq -cn --arg u "$u" --arg p "$pw" --arg r "$1" '{username: $u, password: $p, role: $r}')" >/dev/null
  (
    umask 077
    printf '%s=%s\n' "$(cred_var "$1")" "$pw" >>"$CREDS"
  )
  chmod 600 "$CREDS"
  say "created user $u ($1); password in $CREDS"
}

as_demo() { # ROLE
  ensure_demo_user "$1"
  as_user "demo-$1" "$(cred_lookup "$1")"
}

# api_code METHOD PATH [JSON]: print the HTTP status; the body goes to $TMP/body.
api_code() {
  local args=(-sS -o "$TMP/body" -w '%{http_code}' -X "$1" -b "$RAVEN_JAR" -c "$RAVEN_JAR")
  case $1 in GET | HEAD) ;; *) args+=(-H 'X-RAVEN-CSRF: 1') ;; esac
  [ $# -ge 3 ] && args+=(-H 'Content-Type: application/json' --data-binary "$3")
  curl "${args[@]}" "$(raven_url)$(_raven_path "$2")"
}

# ───────────────────────── RAVEN setup ─────────────────────────

profile_id() { # NAME -> id or empty
  raven_get "/profiles?limit=1000" | jq -r --arg n "$1" '.items[] | select(.name == $n) | .id'
}

profile_json() {
  jq -cn --arg ports "$(tr -d '[:space:]' <lab/vuln/ports.txt)" --arg n "$PROFILE" '{
    name: $n, ports: $ports, nmap_max_rate: 300, nuclei_rate: 25,
    nuclei_tags: ["tech", "panel", "ssl", "waf", "favicon"], miss_threshold: 2,
    target_batch_seconds: 600, enabled: true, stages: ["nmap", "httpx", "nuclei"]}'
}

slow_profile_json() {
  jq -cn --arg n "$SLOW_PROFILE" '{
    name: $n, ports: "1-65535", nmap_max_rate: 2, nuclei_rate: 1, nuclei_tags: [],
    miss_threshold: 2, target_batch_seconds: 600, enabled: true, stages: ["nmap", "httpx", "nuclei"]}'
}

ensure_include() { # PROFILE_ID VALUE
  local have
  have=$(raven_get "/scope?profile_id=$1&limit=1000" |
    jq -r --arg v "$2" '[.items[] | select(.list == "include" and .value == $v)] | length')
  [ "$have" -gt 0 ] && return 0
  RAVEN_OK=409 raven_post /scope "$(jq -cn --arg v "$2" --argjson p "$1" '{value: $v, list: "include", profile_id: $p, note: "vlab-scenario"}')" >/dev/null
}

# ensure_profile NAME JSON INCLUDE: create the profile if missing (never touches an existing one).
ensure_profile() {
  local id
  as_admin
  id=$(profile_id "$1")
  if [ -z "$id" ]; then
    id=$(raven_post /profiles "$2" | jq -r .id)
    say "created profile $1 (id $id)" >&2
  fi
  ensure_include "$id" "$3"
  printf '%s' "$id"
}

# The global blacklist comes first: a run is never started without it.
ensure_blacklist() {
  local entries e v note
  as_admin
  entries=$(raven_get "/scope?limit=1000" | jq -c '[.items[] | select(.list == "exclude" and .profile_id == null) | .value]')
  for e in "${BLACKLIST[@]}"; do
    v=${e%%|*}
    note=${e#*|}
    if jq -e --arg v "$v" 'any(.[]; . == $v or . == ($v + "/32"))' >/dev/null <<<"$entries"; then continue; fi
    RAVEN_OK=409 raven_post /scope "$(jq -cn --arg v "$v" --arg n "$note" '{value: $v, list: "exclude", note: $n}')" >/dev/null
    say "added global exclude $v"
  done
}

ensure_targets() {
  local have missing=0 v
  as_admin
  have=$(raven_get "/targets?limit=1000" | jq -c '[.items[].value]')
  while IFS=, read -r v _; do
    case $v in value | '' | \#*) continue ;; esac
    jq -e --arg v "$v" 'index($v) != null' >/dev/null <<<"$have" || missing=1
  done <lab/vuln/targets.csv
  if [ "$missing" = 1 ]; then
    raven_upload /targets/upload lab/vuln/targets.csv >/dev/null
    say "uploaded lab/vuln/targets.csv"
  fi
}

ensure_setup() {
  ensure_blacklist
  ensure_targets
  ensure_profile "$PROFILE" "$(profile_json)" "$VLAB_INCLUDE" >/dev/null
}

blacklist_ok() {
  local entries e
  entries=$(raven_get "/scope?limit=1000" | jq -c '[.items[] | select(.list == "exclude" and .profile_id == null) | .value]')
  for e in "${BLACKLIST[@]}"; do
    jq -e --arg v "${e%%|*}" 'any(.[]; . == $v or . == ($v + "/32"))' >/dev/null <<<"$entries" || return 1
  done
}

# ───────────────────────── runs ─────────────────────────

active_run() { # PROFILE_ID -> id of a pending/running run, or empty
  raven_get "/runs?profile_id=$1&limit=20" | jq -r '[.items[] | select(.status == "pending" or .status == "running")][0].id // empty'
}

run_summary() { # ID
  raven_get "/runs/$1" | jq -r '"run \(.id) \(.status): hosts_up=\(.hosts_up)/\(.hosts_total) services_open=\(.stats.services_open // "?") reprobed=\(.stats.reprobed // 0) became_unstable=\(.stats.became_unstable // 0) became_inactive=\(.stats.became_inactive // 0) recovered=\(.stats.recovered // 0) started=\(.started_at) finished=\(.finished_at)"'
}

# do_run: start a run of $PROFILE (after any run already active), wait, set LAST_RUN.
do_run() {
  local pid id busy
  ensure_setup
  as_admin
  blacklist_ok || die "global blacklist incomplete; refusing to start a run"
  pid=$(profile_id "$PROFILE")
  busy=$(active_run "$pid")
  if [ -n "$busy" ]; then
    say "run $busy of $PROFILE is active; waiting for it first"
    raven_wait_run "$busy" "$RUN_TIMEOUT" || true
  fi
  id=$(raven_post /runs "$(jq -cn --argjson p "$pid" '{profile_id: $p}')" | jq -r .id)
  say "started run $id ($PROFILE)"
  raven_wait_run "$id" "$RUN_TIMEOUT" || die "run $id did not finish: $(run_summary "$id")"
  run_summary "$id"
  LAST_RUN=$id
}

last_done_run() { # PROFILE_ID -> id of the latest done run
  raven_get "/runs?profile_id=$1&limit=50" | jq -r '[.items[] | select(.status == "done")][0].id // empty'
}

changes() { raven_get "/changes?from=$1&to=$2&limit=5000"; }

# ───────────────────────── lab ─────────────────────────

container_state() { # SERVICE -> "running nginx:1.20.0-alpine" | "absent"
  local s
  s=$(docker inspect -f '{{.State.Status}} {{.Config.Image}}' "raven-vlab-$1-1" 2>/dev/null) || s=absent
  printf '%s\n' "$s"
}

# lab_curl ARGS…: curl from a one-shot container on raven_vlab (dynamic range 10.77.255.0/24).
lab_curl() {
  "${VLAB[@]}" run --rm --no-deps -T --entrypoint curl vlab-init -fsS --max-time 15 "$@" 2>/dev/null
}

toxi_get() { lab_curl "$TOXI$1"; }
toxi_send() { # METHOD PATH [JSON]
  if [ $# -ge 3 ]; then
    lab_curl -X "$1" -H 'Content-Type: application/json' -d "$3" "$TOXI$2" >/dev/null
  else
    lab_curl -X "$1" "$TOXI$2" >/dev/null
  fi
}

toxics_state() {
  toxi_get /proxies/wordpress | jq -c '{enabled, toxics: [.toxics[] | {name, type, attributes}]}'
}

toxic_clear() {
  local t
  while IFS= read -r t; do
    [ -n "$t" ] || continue
    toxi_send DELETE "/proxies/wordpress/toxics/$t"
  done < <(toxi_get /proxies/wordpress/toxics | jq -r '.[].name')
  toxi_send POST /proxies/wordpress '{"enabled": true}'
}

toxic_add() { # TYPE ATTRIBUTES_JSON
  toxi_send POST /proxies/wordpress/toxics "$(jq -cn --arg t "$1" --argjson a "$2" '{name: ("raven_" + $t), type: $t, stream: "downstream", toxicity: 1, attributes: $a}')"
}

flask_tag() { # TAG
  VLAB_FLASK_NGINX_TAG=$1 "${VLAB[@]}" up -d --wait flask-app
}

# ───────────────────────── steps ─────────────────────────

step_status() {
  say "lab"
  printf '  flask-app  %s\n' "$(container_state flask-app)"
  printf '  custom-api %s\n' "$(container_state custom-api)"
  printf '  device     %s\n' "$(container_state device)"
  printf '  toxiproxy  %s\n' "$(toxics_state 2>/dev/null || echo unreachable)"
  say "RAVEN $(raven_url)"
  as_admin
  if blacklist_ok; then echo "  global blacklist: ok"; else echo "  global blacklist: MISSING (run baseline)"; fi
  local pid
  pid=$(profile_id "$PROFILE")
  if [ -z "$pid" ]; then
    echo "  profile $PROFILE: missing (baseline creates it)"
    return 0
  fi
  echo "  profile $PROFILE: id $pid"
  raven_get "/runs?profile_id=$pid&limit=5" | jq -r '.items[] | "  run \(.id) \(.status) hosts_up=\(.hosts_up) started=\(.started_at)"'
  check "Runs page: the last runs of $PROFILE"
}

step_baseline() {
  ensure_setup
  say "lab back to baseline"
  toxic_clear
  flask_tag "$FLASK_OLD"
  "${VLAB[@]}" up -d --wait --no-recreate custom-api
  "${VLAB[@]}" --profile scenario rm -sf device
  check "Dashboard / Hosts: $EXPECTED_HOSTS hosts active in 10.77.1-4.x after the run; no 10.77.x address outside §2.3 created"
  check "Hosts: 'New device found' for each new host in Findings (Dojo, ~5-10 min after the run)"
  check "Findings: CVE matches (WordPress 4.7.5 on 10.77.3.10, nginx 1.20.0 CVE-2021-23017 on 10.77.4.20:8787) after the 5-minute CVE pass"
}

step_service_gone() {
  "${VLAB[@]}" stop flask-app
  check "Changes (previous run -> next run): 10.77.4.20:8787 gone; 10.77.4.20:3000 and :22 unchanged; host 10.77.4.20 stays active"
  check "Dojo Asset 10.77.4.20: the nmap finding for 8787 closed"
}

step_service_back() {
  "${VLAB[@]}" up -d --wait --no-recreate flask-app
  check "Changes: 10.77.4.20:8787 new again; Dojo finding reactivated or recreated"
}

step_upgrade() {
  flask_tag "$FLASK_NEW"
  check "Changes: 10.77.4.20:8787 changed, fields [version, …], nginx 1.20.0 -> ${FLASK_NEW%-alpine}"
  check "CVE matches of 10.77.4.20:8787: CVE-2021-23017 closed after the next CVE pass ('downgrade' reverts)"
}

step_downgrade() {
  flask_tag "$FLASK_OLD"
  check "Changes: 10.77.4.20:8787 changed back to nginx ${FLASK_OLD%-alpine}; CVE-2021-23017 matched again"
}

step_device_new() {
  "${VLAB[@]}" --profile scenario up -d --wait device
  check "Dashboard 'new devices' / Changes: 10.77.9.50 new"
  check "Findings: 'New device found: 10.77.9.50' and CVE-2021-41773 (KEV, Critical) after the 5-minute passes"
}

step_device_remove() {
  "${VLAB[@]}" --profile scenario rm -sf device
  check "next run: 10.77.9.50 re-probed -> unstable; at the second miss inactive + 'Host offline: 10.77.9.50'"
}

step_host_off() {
  "${VLAB[@]}" stop custom-api
  check "run A: Hosts state=unstable shows 10.77.4.10 (miss_count 1); run stats reprobed/became_unstable >= 1; its findings stay active"
  check "run B: 10.77.4.10 inactive; run stats became_inactive >= 1; Findings 'Host offline: 10.77.4.10'"
}

step_host_on() {
  "${VLAB[@]}" up -d --wait --no-recreate custom-api
  check "next run: 10.77.4.10 active again (miss_count 0)"
}

step_toxic() {
  local kind=${1:-}
  case $kind in
    latency)
      local ms=${2:-}
      [[ $ms =~ ^[0-9]+$ ]] || die "usage: toxic latency <ms>"
      toxic_clear
      toxic_add latency "$(jq -cn --argjson l "$ms" '{latency: $l, jitter: 0}')"
      check "next run: slower but complete; 10.77.2.10:80 and 10.77.2.11:8666 keep their facts (title 'RAVEN vlab Proxy') and record ~${ms} ms / slow (at >=2000 ms)"
      ;;
    timeout)
      toxic_clear
      toxic_add timeout '{"timeout": 0}'
      check "next run: 10.77.2.11:8666 open with http_unresponsive in Changes and run stats; 10.77.2.10:80 (Traefik) changed in Changes"
      ;;
    slow-close)
      toxic_clear
      toxic_add slow_close '{"delay": 5000}'
      check "next run: complete; batch durations longer for 10.77.2.0/24"
      ;;
    down)
      toxic_clear
      toxi_send POST /proxies/wordpress '{"enabled": false}'
      check "next run: 10.77.2.11:8666 gone (proxy disabled); 10.77.2.10:80 answers 502 -> changed in Changes"
      ;;
    clear)
      toxic_clear
      check "next run: 10.77.2.10:80 back to 200 'RAVEN vlab Proxy'"
      ;;
    *) die "usage: toxic latency <ms>|timeout|slow-close|down|clear" ;;
  esac
  echo "toxiproxy: $(toxics_state)"
}

step_signature() {
  local yaml v id current res code
  ensure_setup
  yaml=$(<"$SIG_FILE")
  as_demo editor
  v=$(raven_post /signatures/validate "$(jq -cn --arg y "$yaml" '{template_yaml: $y}')")
  expect "signature $SIG_NAME passes the safe-subset validator" "$v" '.valid == true'
  id=$(raven_get "/signatures?limit=1000" | jq -r --arg n "$SIG_NAME" '.items[] | select(.name == $n) | .id')
  if [ -z "$id" ]; then
    id=$(raven_post /signatures "$(jq -cn --arg y "$yaml" '{template_yaml: $y, enabled: true}')" | jq -r .id)
    say "created signature $SIG_NAME (id $id)"
  else
    current=$(raven_get "/signatures/$id")
    if [ "$(jq -r .template_yaml <<<"$current")" != "$yaml" ] || [ "$(jq -r .enabled <<<"$current")" != true ]; then
      raven_put "/signatures/$id" "$(jq -cn --arg y "$yaml" '{template_yaml: $y, enabled: true}')" >/dev/null
      say "updated signature $SIG_NAME (id $id)"
    fi
  fi
  res=$(raven_post "/signatures/$id/test" '{"url": "http://10.77.3.14/"}')
  echo "test http://10.77.3.14/: $(jq -c '{matched, matches: [.matches[] | {template_id, extracted}]}' <<<"$res")"
  expect "signature matches DVWA http://10.77.3.14/" "$res" '.matched == true'
  res=$(raven_post "/signatures/$id/test" '{"url": "http://10.77.4.10/"}')
  expect "signature does not match httpbin http://10.77.4.10/" "$res" '.matched == false'
  # 10.77.254.20 is lab tooling inside the global blacklist: RAVEN must refuse it before any request.
  code=$(api_code POST "/signatures/$id/test" '{"url": "http://10.77.254.20/"}')
  echo "test http://10.77.254.20/ (blacklisted): HTTP $code $(cat "$TMP/body")"
  if [ "$code" = 400 ]; then ok "blacklisted URL refused (400)"; else bad "blacklisted URL refused (got $code)"; fi
  check "Signatures page: '$SIG_NAME' (custom, valid, enabled)"
  check "next run: Findings for 10.77.3.14 include 'DVWA security level cookie' (Dojo, after the sync)"
}

edit_values() {
  jq -cn '{owner: "vlab-blue-team", criticality: "high", notes: "DVWA training box, keep isolated (vlab scenario edit)", user_tags: ["dvwa", "scenario", "vlab"]}'
}

step_edit() {
  local ip=10.77.3.14 host svc fid f
  as_demo operator
  host=$(raven_get "/hosts/$ip") || die "host $ip unknown: run 'baseline --run' first"
  raven_patch "/hosts/$ip" "$(edit_values)" | jq -c '{ip, owner, criticality, user_tags, dojo_sync}'
  svc=$(jq -r '[.services[] | select(.port == 80 and .proto == "tcp")][0].id // empty' <<<"$host")
  [ -n "$svc" ] || die "no service $ip:80 yet: run 'baseline --run' first"
  raven_patch "/services/$svc" '{"overrides": {"product": "DVWA on Apache httpd"}}' | jq -c '{id, port, product, overridden, scan}'
  f=$(raven_get "/findings?ip=$ip&active=true&limit=1000" |
    jq -c '[.items[] | select(.title | test("PHP session cookie|PHPSESSID"; "i"))][0] // .items[0] // empty')
  if [ -z "$f" ]; then
    echo "no active finding for $ip in the mirror yet (Dojo sync every 5 min): finding edit skipped"
  else
    fid=$(jq -r .id <<<"$f")
    if [ "$(jq -r .severity <<<"$f")" != Medium ]; then
      raven_patch "/findings/$fid" '{"severity": "Medium"}' | jq -c '{id, title, severity}'
      raven_post "/findings/$fid/notes" '{"text": "vlab scenario: severity raised to Medium by the operator"}' >/dev/null
    fi
    echo "finding $fid ($(jq -r .title <<<"$f")): severity Medium"
  fi
  check "Host page $ip: owner vlab-blue-team, criticality high, tags dvwa/scenario/vlab, notes; Dojo Asset description"
  check "Services: $ip:80 product 'DVWA on Apache httpd' (override); the scan value underneath"
  if [ "${DO_RUN:-0}" = 1 ]; then
    do_run
    as_demo operator
    host=$(raven_get "/hosts/$ip")
    expect "edits kept after run $LAST_RUN (owner/criticality/tags)" "$host" '.owner == "vlab-blue-team" and .criticality == "high" and .user_tags == ["dvwa", "scenario", "vlab"]'
    expect "service override kept, scan value underneath" "$host" '[.services[] | select(.port == 80)][0] | (.product == "DVWA on Apache httpd") and (.overridden | index("product")) and (.scan.product != "DVWA on Apache httpd")'
    if [ -n "${fid:-}" ]; then
      expect "finding $fid severity kept" "$(raven_get "/findings?ip=$ip&limit=1000")" "any(.items[]; .id == $fid and .severity == \"Medium\")"
    fi
  fi
}

step_exchange() {
  local kind fmt code res
  as_demo viewer
  for kind in hosts services findings; do
    for fmt in csv json; do
      code=$(api_code GET "/export/$kind?format=$fmt")
      echo "viewer export $kind.$fmt: HTTP $code, $(wc -c <"$TMP/body") bytes"
      if [ "$code" = 200 ]; then ok "viewer export $kind $fmt"; else bad "viewer export $kind $fmt (got $code)"; fi
    done
  done
  ensure_setup
  as_demo editor
  res=$(raven_upload /import/results "$IMPORT_FILE" kind=results-json "profile=$PROFILE")
  echo "editor import: $(jq -c '{id, status, hosts_up, stats: (.stats | {source, import_kind})}' <<<"$res")"
  expect "import created host 10.77.9.51" "$(raven_get /hosts/10.77.9.51)" '.ip == "10.77.9.51" and (.open_ports | index(8080))'
  check "Import/Export page: the import run; Hosts: 10.77.9.51 (legacy-erp.vlab, 22 + 8080)"
  check "Findings: 'New device found: 10.77.9.51' after the Dojo sync"
}

# role_case PERM METHOD PATH [JSON]: invalid bodies on purpose, so an allowed role gets 4xx (not 403)
# and nothing is written.
ROLE_CASES=(
  "read|GET|/hosts?limit=1"
  "export|GET|/export/hosts?format=csv"
  "hosts:edit|PATCH|/hosts/10.77.3.14|{\"criticality\":\"bogus\"}"
  "findings:edit|PATCH|/findings/0|{}"
  "targets:write|POST|/targets|{}"
  "scope:write|POST|/scope|{\"list\":\"include\",\"value\":\"\",\"profile_id\":PID}"
  "scope:global|POST|/scope|{\"list\":\"exclude\",\"value\":\"\"}"
  "profiles:write|POST|/profiles|{}"
  "schedules:write|POST|/schedules|{}"
  "signatures:write|POST|/signatures|{}"
  "import|POST|/import/results|{}"
  "runs:control|POST|/runs|{\"profile_id\":0}"
  "users:admin|GET|/users?limit=1"
)

step_roles() {
  local role perms c perm method path body code allowed verdict user pid
  ensure_setup
  pid=$(profile_id "$PROFILE")
  printf '%-10s %-18s %-7s %s\n' role permission status result
  for role in viewer operator editor admin; do
    if [ "$role" = admin ]; then
      as_admin
      user=$(admin_user)
    else
      as_demo "$role"
      user=demo-$role
    fi
    perms=$(raven_get /auth/me | jq -c .permissions)
    for c in "${ROLE_CASES[@]}"; do
      IFS='|' read -r perm method path body <<<"$c"
      body=${body//PID/$pid}
      if [ -n "$body" ]; then code=$(api_code "$method" "$path" "$body"); else code=$(api_code "$method" "$path"); fi
      allowed=$(jq -r --arg p "$perm" 'index($p) != null' <<<"$perms")
      if [ "$allowed" = true ]; then
        if [ "$code" != 403 ] && [ "$code" != 401 ]; then verdict=allowed; else verdict=WRONG; fi
      else
        if [ "$code" = 403 ]; then verdict=denied; else verdict=WRONG; fi
      fi
      printf '%-10s %-18s %-7s %s\n' "$role" "$perm" "$code" "$verdict"
      if [ "$verdict" = WRONG ]; then bad "$user $method $path -> $code"; else PASS=$((PASS + 1)); fi
    done
  done
  check "viewer: 403 on every mutation, 200 on read/export; operator: only hosts:edit/findings:edit; editor: everything but users; admin: all"
}

step_window() {
  local pid sid rid st start end body i
  ensure_blacklist
  ensure_targets
  pid=$(ensure_profile "$SLOW_PROFILE" "$(slow_profile_json)" 10.77.4.0/24)
  as_admin
  # Idempotent: stop what an earlier window step left behind.
  while IFS= read -r rid; do
    [ -n "$rid" ] || continue
    raven_post "/runs/$rid/stop" >/dev/null && say "stopped earlier run $rid"
  done < <(raven_get "/runs?profile_id=$pid&limit=50" | jq -r '.items[] | select(.status == "pending" or .status == "running" or .status == "suspended") | .id')
  start=$(date -u -d '+1 min' +%Y-%m-%dT%H:%M:00Z)
  end=$(date -u -d '+3 min' +%Y-%m-%dT%H:%M:00Z)
  body=$(jq -cn --argjson p "$pid" --arg s "$start" --arg e "$end" '{name: "vlab-window", profile_id: $p, cron: "* * * * *", window_start: $s, window_end: $e, timezone: "UTC", enabled: true}')
  sid=$(raven_get "/schedules?limit=1000" | jq -r '.items[] | select(.source == "ui" and .name == "vlab-window") | .id' | head -n 1)
  if [ -n "$sid" ]; then raven_put "/schedules/$sid" "$body" >/dev/null; else sid=$(raven_post /schedules "$body" | jq -r .id); fi
  say "schedule $sid: $SLOW_PROFILE (ports 1-65535, rate 2) daily window $start -> $end (UTC)"
  rid=""
  for ((i = 1; i <= 60; i++)); do
    rid=$(raven_get "/runs?profile_id=$pid&limit=20" | jq -r --argjson s "$sid" '[.items[] | select(.schedule_id == $s and (.status == "running" or .status == "pending"))][0].id // empty')
    [ -n "$rid" ] && break
    sleep 5
  done
  [ -n "$rid" ] || die "no run of schedule $sid started within 5 minutes"
  expect "run $rid started by schedule $sid inside the window" "$(raven_get "/runs/$rid")" '.started_at != null'
  say "waiting for the window to close ($end)"
  for ((i = 1; i <= 60; i++)); do
    st=$(raven_get "/runs/$rid" | jq -r .status)
    if [ "$st" = suspended ] || [ "$st" = done ]; then break; fi
    sleep 5
  done
  run_summary "$rid"
  expect "run $rid suspended at the window end" "$(raven_get "/runs/$rid")" '.status == "suspended"'
  expect "unfinished batch back to pending" "$(raven_get "/runs/$rid/batches")" 'any(.items[]; .status == "pending")'
  # The next window: the same daily window moved to the next free minutes.
  start=$(date -u -d '+1 min' +%Y-%m-%dT%H:%M:00Z)
  end=$(date -u -d '+3 min' +%Y-%m-%dT%H:%M:00Z)
  raven_put "/schedules/$sid" "$(jq -c --arg s "$start" --arg e "$end" '.window_start = $s | .window_end = $e' <<<"$body")" >/dev/null
  say "next window $start -> $end"
  for ((i = 1; i <= 60; i++)); do
    st=$(raven_get "/runs/$rid" | jq -r .status)
    [ "$st" = running ] && break
    sleep 5
  done
  expect "run $rid resumed in the next window" "$(raven_get "/runs/$rid")" '.status == "running"'
  raven_post "/runs/$rid/stop" >/dev/null || true
  raven_put "/schedules/$sid" "$(jq -c '.enabled = false' <<<"$body")" >/dev/null
  say "stopped run $rid and disabled schedule $sid (re-run the step to repeat)"
  check "Runs: run $rid of $SLOW_PROFILE went running -> suspended -> running, then stopped; Schedules: vlab-window disabled"
}

dd_curl() { # METHOD PATH [JSON]
  local args=(-sS -f -X "$1" -H "Authorization: Token $DD_TOKEN")
  [ $# -ge 3 ] && args+=(-H 'Content-Type: application/json' --data-binary "$3")
  curl "${args[@]}" "$DD_URL$2"
}

step_dojo_plan() {
  local user pass asset day name eng eid sid rid i
  DD_URL="http://localhost:$(env_or_file DD_PORT 8080)"
  user=$(env_or_file DD_ADMIN_USER admin)
  pass=$(env_or_file DD_ADMIN_PASSWORD "")
  [ -n "$pass" ] || die "DD_ADMIN_PASSWORD not found"
  DD_TOKEN=$(curl -sS -f -X POST -H 'Content-Type: application/json' \
    --data-binary "$(jq -cn --arg u "$user" --arg p "$pass" '{username: $u, password: $p}')" \
    "$DD_URL/api/v2/api-token-auth/" | jq -r .token)
  [ -n "$DD_TOKEN" ] && [ "$DD_TOKEN" != null ] || die "no Dojo token from $DD_URL"
  asset=$(dd_curl GET "/api/v2/assets/?name_exact=RAVEN%20Planning" | jq -r '.results[0].id // empty')
  [ -n "$asset" ] || die "Dojo asset 'RAVEN Planning' missing (RAVEN creates it at startup)"
  ensure_setup
  day=$(TZ=Europe/Warsaw date +%F)
  name="RAVEN vlab scenario $day"
  eng=$(dd_curl GET "/api/v2/engagements/?product=$asset&name=$(jq -rn --arg n "$name" '$n | @uri')" | jq -c '.results[0] // empty')
  if [ -z "$eng" ]; then
    eng=$(dd_curl POST /api/v2/engagements/ "$(jq -cn --argjson a "$asset" --arg n "$name" --arg d "$day" --arg t "raven-profile:$PROFILE" \
      '{product: $a, name: $n, target_start: $d, target_end: $d, status: "Not Started", engagement_type: "Interactive", tags: [$t]}')")
    say "created Dojo engagement '$name' under RAVEN Planning (tag raven-profile:$PROFILE, $day)"
  fi
  eid=$(jq -r .id <<<"$eng")
  echo "engagement $eid: status $(jq -r .status <<<"$eng"), $(jq -r .target_start <<<"$eng") -> $(jq -r .target_end <<<"$eng")"
  as_admin
  say "waiting for RAVEN's planning poll (every 5 min)"
  sid=""
  for ((i = 1; i <= 80; i++)); do
    sid=$(raven_get "/schedules?limit=1000" | jq -r --argjson e "$eid" '.items[] | select(.source == "dojo" and .dojo_engagement_id == $e) | .id' | head -n 1)
    [ -n "$sid" ] && break
    sleep 5
  done
  [ -n "$sid" ] || die "no Dojo schedule for engagement $eid after ~7 min"
  ok "Dojo-sourced schedule $sid for engagement $eid"
  rid=""
  for ((i = 1; i <= 36; i++)); do
    rid=$(raven_get "/runs?limit=50" | jq -r --argjson s "$sid" '[.items[] | select(.schedule_id == $s)][0].id // empty')
    [ -n "$rid" ] && break
    sleep 5
  done
  if [ -n "$rid" ]; then ok "run $rid of $PROFILE started by schedule $sid"; else bad "no run for schedule $sid within 3 min"; fi
  check "Dojo: RAVEN Planning -> '$name' In Progress, then Completed when the run ends"
  check "Schedules page: source dojo, window $day (Europe/Warsaw day); Runs: run ${rid:-?}"
  if [ -n "$rid" ] && [ "${DO_RUN:-0}" = 1 ]; then
    raven_wait_run "$rid" "$RUN_TIMEOUT" || true
    run_summary "$rid"
  fi
}

# ───────────────────────── walk ─────────────────────────

svc_in() { # LIST IP PORT -> jq filter: the diff list has IP:PORT
  printf 'any(.%s[]; .ip == "%s" and .port == %s)' "$1" "$2" "$3"
}

walk() {
  local r1 r2 r3 r4 r5 r6 r7 r8 r9 r10 r11 c i
  say "1 baseline"
  step_baseline
  do_run
  r1=$LAST_RUN
  expect "1 baseline: run $r1 finds $EXPECTED_HOSTS hosts up" "$(raven_get "/runs/$r1")" ".hosts_up == $EXPECTED_HOSTS"
  expect "1 baseline: 10.77.4.20 has 22, 3000, 8787" "$(raven_get /hosts/10.77.4.20)" '.open_ports as $p | [22, 3000, 8787] | all(. as $x | $p | index($x))'

  say "2 service gone"
  step_service_gone
  do_run
  r2=$LAST_RUN
  c=$(changes "$r1" "$r2")
  expect "2 service-gone: 10.77.4.20:8787 gone" "$c" "$(svc_in services_gone 10.77.4.20 8787)"
  expect "2 service-gone: 10.77.4.20:3000 and :22 not gone" "$c" "($(svc_in services_gone 10.77.4.20 3000) or $(svc_in services_gone 10.77.4.20 22)) | not"
  expect "2 service-gone: host 10.77.4.20 still active" "$(raven_get /hosts/10.77.4.20)" '.state == "active"'

  say "3 service back"
  step_service_back
  do_run
  r3=$LAST_RUN
  expect "3 service-back: 10.77.4.20:8787 new" "$(changes "$r2" "$r3")" "$(svc_in services_new 10.77.4.20 8787)"

  say "4 version change"
  step_upgrade
  do_run
  r4=$LAST_RUN
  c=$(changes "$r3" "$r4")
  expect "4 upgrade: 10.77.4.20:8787 changed with field version" "$c" 'any(.services_changed[]; .ip == "10.77.4.20" and .port == 8787 and (.fields | index("version")))'
  expect "4 upgrade: version ${FLASK_NEW%-alpine} after" "$c" "any(.services_changed[]; .ip == \"10.77.4.20\" and .port == 8787 and .after.version == \"${FLASK_NEW%-alpine}\")"

  say "5 new device"
  step_device_new
  do_run
  r5=$LAST_RUN
  expect "5 device-new: 10.77.9.50 new in Changes" "$(changes "$r4" "$r5")" 'any(.hosts_new[]; .ip == "10.77.9.50")'
  expect "5 device-new: 10.77.9.50:80 Apache httpd 2.4.49" "$(raven_get /hosts/10.77.9.50)" 'any(.services[]; .port == 80 and (.product | test("Apache"; "i")) and .version == "2.4.49")'

  say "6 host offline"
  step_host_off
  do_run
  r6=$LAST_RUN
  expect "6 host-off run A: re-probed and became unstable" "$(raven_get "/runs/$r6")" '.stats.reprobed >= 1 and .stats.became_unstable >= 1'
  expect "6 host-off run A: 10.77.4.10 unstable, miss_count 1" "$(raven_get /hosts/10.77.4.10)" '.state == "unstable" and .miss_count == 1'
  expect "6 host-off run A: 10.77.4.10 gone in Changes" "$(changes "$r5" "$r6")" 'any(.hosts_gone[]; .ip == "10.77.4.10")'
  do_run
  r7=$LAST_RUN
  expect "6 host-off run B: became inactive (threshold 2)" "$(raven_get "/runs/$r7")" '.stats.became_inactive >= 1 and (.stats.inactive_ips | index("10.77.4.10"))'
  expect "6 host-off run B: 10.77.4.10 inactive" "$(raven_get /hosts/10.77.4.10)" '.state == "inactive"'
  step_host_on
  do_run
  r8=$LAST_RUN
  expect "6 host-on: 10.77.4.10 active again" "$(raven_get /hosts/10.77.4.10)" '.state == "active" and .miss_count == 0'

  say "7 slow / unstable responses"
  step_toxic latency 3000
  do_run
  r9=$LAST_RUN
  expect "7 latency: run $r9 done with $((EXPECTED_HOSTS + 1)) hosts up" "$(raven_get "/runs/$r9")" ".status == \"done\" and .hosts_up == $((EXPECTED_HOSTS + 1))"
  c=$(changes "$r8" "$r9")
  expect "7 latency: 10.77.2.10:80 facts unchanged (only slow allowed)" "$c" '[.services_changed[] | select(.ip == "10.77.2.10" and .port == 80) | .fields[] | select(. != "slow")] | length == 0'
  expect "7 latency: 10.77.2.10:80 marked slow" "$c" 'any(.services_changed[]; .ip == "10.77.2.10" and .port == 80 and (.fields | index("slow")))'
  step_toxic timeout
  do_run
  r10=$LAST_RUN
  c=$(changes "$r9" "$r10")
  echo "changes $r9 -> $r10 on 10.77.2.x: $(jq -c '[.services_changed[], .services_gone[] | select(.ip | startswith("10.77.2.")) | {ip, port, fields, before: .before.title, after: .after.title}]' <<<"$c")"
  expect "7 timeout: 10.77.2.10:80 changed (title)" "$c" 'any(.services_changed[]; .ip == "10.77.2.10" and .port == 80 and (.fields | index("title")))'
  expect "7 timeout: 10.77.2.11:8666 still open" "$c" "$(svc_in services_gone 10.77.2.11 8666) | not"
  expect "7 timeout: 10.77.2.11:8666 marked http_unresponsive" "$c" 'any(.services_changed[]; .ip == "10.77.2.11" and .port == 8666 and (.fields | index("http_unresponsive")))'
  step_toxic clear
  do_run
  r11=$LAST_RUN
  expect "7 clear: 10.77.2.10:80 back to 'RAVEN vlab Proxy'" "$(changes "$r10" "$r11")" 'any(.services_changed[]; .ip == "10.77.2.10" and .port == 80 and .after.title == "RAVEN vlab Proxy")'

  if [ "$ASYNC_WAIT" -gt 0 ]; then
    say "waiting up to ${ASYNC_WAIT}s for the 5-minute CVE and Dojo sync passes"
    local cve=0 newdev=0 off=0
    for ((i = 1; i <= ASYNC_WAIT / 15; i++)); do
      if [ "$cve" = 0 ] && raven_get "/cve-matches?ip=10.77.9.50" | jq -e 'any(.items[]; any(.cves[]; .id == "CVE-2021-41773"))' >/dev/null; then cve=1; fi
      if [ "$newdev" = 0 ] && raven_get "/findings?ip=10.77.9.50&limit=1000" | jq -e 'any(.items[]; .title == "New device found: 10.77.9.50")' >/dev/null; then newdev=1; fi
      if [ "$off" = 0 ] && raven_get "/findings?ip=10.77.4.10&limit=1000" | jq -e 'any(.items[]; .title == "Host offline: 10.77.4.10")' >/dev/null; then off=1; fi
      [ "$cve" = 1 ] && [ "$newdev" = 1 ] && [ "$off" = 1 ] && break
      sleep 15
    done
    if [ "$cve" = 1 ]; then ok "5 device-new: CVE-2021-41773 matched on 10.77.9.50"; else bad "5 device-new: CVE-2021-41773 matched on 10.77.9.50"; fi
    if [ "$newdev" = 1 ]; then ok "5 device-new: finding 'New device found: 10.77.9.50'"; else bad "5 device-new: finding 'New device found: 10.77.9.50'"; fi
    if [ "$off" = 1 ]; then ok "6 host-off: finding 'Host offline: 10.77.4.10'"; else bad "6 host-off: finding 'Host offline: 10.77.4.10'"; fi
  fi

  say "restoring the lab"
  toxic_clear
  flask_tag "$FLASK_OLD"
  "${VLAB[@]}" --profile scenario rm -sf device
  "${VLAB[@]}" up -d --wait --no-recreate custom-api
  echo "runs: 1=$r1 2=$r2 3=$r3 4=$r4 5=$r5 6=$r6,$r7 host-on=$r8 7=$r9,$r10,$r11"
}

usage() {
  sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-0}"
}

main() {
  local args=() a step
  if [ -z "${RAVEN_URL:-}" ] && [ -z "${RAVEN_PORT:-}" ]; then
    RAVEN_PORT=$(env_or_file RAVEN_PORT 8000)
    export RAVEN_PORT
  fi
  DO_RUN=0
  for a in "$@"; do
    case $a in
      --run) DO_RUN=1 ;;
      -h | --help) usage 0 ;;
      *) args+=("$a") ;;
    esac
  done
  [ ${#args[@]} -ge 1 ] || usage 1
  step=${args[0]}
  case $step in
    status) step_status ;;
    baseline) step_baseline ;;
    service-gone) step_service_gone ;;
    service-back) step_service_back ;;
    upgrade) step_upgrade ;;
    downgrade) step_downgrade ;;
    device-new) step_device_new ;;
    device-remove) step_device_remove ;;
    host-off) step_host_off ;;
    host-on) step_host_on ;;
    toxic) step_toxic "${args[@]:1}" ;;
    signature) step_signature ;;
    edit) step_edit ;;
    exchange) step_exchange ;;
    roles) step_roles ;;
    window) step_window ;;
    dojo-plan) step_dojo_plan ;;
    walk) walk ;;
    *) usage 1 ;;
  esac
  case $step in
    status | walk | edit | window | dojo-plan) ;;
    *) [ "$DO_RUN" = 1 ] && do_run ;;
  esac
  if [ $((PASS + FAIL)) -gt 0 ]; then
    printf '%s: %d passed, %d failed\n' "$step" "$PASS" "$FAIL"
  fi
  [ "$FAIL" = 0 ]
}

main "$@"
