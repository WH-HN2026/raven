# shellcheck shell=bash
# Small RAVEN API client for lab and demo scripts (docs/vuln-lab.md §8). Source it from bash:
#
#   . scripts/lib/raven-api.sh
#   raven_login admin "$(raven_env RAVEN_ADMIN_PASSWORD)"
#   raven_get /auth/me | jq .user
#   RAVEN_OK=409 raven_post /scope '{"value":"10.77.0.1","list":"exclude"}'
#
# Paths may be given with or without the /api prefix. Needs only curl and jq.
#
# Settings (environment):
#   RAVEN_URL       base URL (default http://localhost:${RAVEN_PORT:-8000})
#   RAVEN_JAR       cookie jar; set by raven_login (a temp file unless given)
#   RAVEN_OK        extra HTTP statuses (space or comma separated, e.g. 409) that count as success
#   RAVEN_ENV_FILE  file read by raven_env (default .env)

raven_url() {
  printf '%s\n' "${RAVEN_URL:-http://localhost:${RAVEN_PORT:-8000}}"
}

# raven_env VAR: print VAR's value from .env without sourcing it.
raven_env() {
  local file=${RAVEN_ENV_FILE:-.env} line v
  [ -f "$file" ] || { echo "raven_env: $file not found" >&2; return 1; }
  line=$(grep -E "^[[:space:]]*(export[[:space:]]+)?$1=" "$file" | tail -n 1)
  [ -n "$line" ] || { echo "raven_env: $1 not set in $file" >&2; return 1; }
  v=${line#*=}
  v=${v%$'\r'}
  case $v in
    \"*\") v=${v#\"}; v=${v%\"} ;;
    \'*\') v=${v#\'}; v=${v%\'} ;;
  esac
  printf '%s\n' "$v"
}

_raven_path() {
  case $1 in
    /api/*) printf '%s' "$1" ;;
    /*) printf '/api%s' "$1" ;;
    *) printf '/api/%s' "$1" ;;
  esac
}

_raven_ok() { # status
  local s
  [ "$1" -ge 200 ] && [ "$1" -lt 400 ] && return 0
  local ok=${RAVEN_OK:-}
  for s in ${ok//,/ }; do
    [ "$s" = "$1" ] && return 0
  done
  return 1
}

# _raven_req METHOD PATH [curl args…]: print the body, fail on a 4xx/5xx not in RAVEN_OK.
_raven_req() {
  local method=$1 path body code
  path=$(_raven_path "$2")
  shift 2
  body=$(mktemp) || return 1
  local args=(-sS -o "$body" -w '%{http_code}' -X "$method")
  [ -n "${RAVEN_JAR:-}" ] && args+=(-b "$RAVEN_JAR" -c "$RAVEN_JAR")
  case $method in GET | HEAD) ;; *) args+=(-H 'X-RAVEN-CSRF: 1') ;; esac
  code=$(curl "${args[@]}" "$@" "$(raven_url)$path") || { rm -f "$body"; echo "raven $method $path: request failed" >&2; return 1; }
  cat "$body"
  rm -f "$body"
  if ! _raven_ok "$code"; then
    echo "raven $method $path: HTTP $code" >&2
    return 1
  fi
  return 0
}

_raven_json() { # METHOD PATH [json]
  if [ $# -ge 3 ]; then
    _raven_req "$1" "$2" -H 'Content-Type: application/json' --data-binary "$3"
  else
    _raven_req "$1" "$2"
  fi
}

# raven_login USER PASSWORD [JAR]: open a session; the cookie (raven_session) goes to JAR / RAVEN_JAR.
raven_login() {
  local user=$1 pass=$2
  if [ -n "${3:-}" ]; then
    RAVEN_JAR=$3
  elif [ -z "${RAVEN_JAR:-}" ]; then
    RAVEN_JAR=$(mktemp) || return 1
  fi
  export RAVEN_JAR
  _raven_json POST /auth/login "$(jq -cn --arg u "$user" --arg p "$pass" '{username: $u, password: $p}')" >/dev/null
}

raven_get() { _raven_req GET "$1"; }
raven_post() { _raven_json POST "$@"; }
raven_put() { _raven_json PUT "$@"; }
raven_patch() { _raven_json PATCH "$@"; }
raven_delete() { _raven_json DELETE "$@"; }

# raven_upload PATH FILE [field=value…]: multipart upload (file field "file").
raven_upload() {
  local path=$1 file=$2 kv
  shift 2
  [ -f "$file" ] || { echo "raven_upload: $file not found" >&2; return 1; }
  local args=(-F "file=@$file")
  for kv in "$@"; do args+=(--form-string "$kv"); done
  _raven_req POST "$path" "${args[@]}"
}

# raven_wait_run ID [TIMEOUT_SECONDS=3600]: wait until the run is done (0), failed/stopped (1)
# or the timeout passes (2). Prints each status change; a suspended run keeps waiting.
raven_wait_run() {
  local id=$1 timeout=${2:-3600} start status last=""
  start=$(date +%s)
  while :; do
    status=$(raven_get "/runs/$id" | jq -r .status) || return 1
    if [ "$status" != "$last" ]; then
      echo "run $id: $status" >&2
      last=$status
    fi
    case $status in
      done) return 0 ;;
      failed | stopped) return 1 ;;
    esac
    if [ $(($(date +%s) - start)) -ge "$timeout" ]; then
      echo "run $id: still $status after ${timeout}s" >&2
      return 2
    fi
    sleep 5
  done
}
