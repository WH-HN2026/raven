#!/usr/bin/env bash
# make dev: runs the Go server (rebuilt and restarted when a .go/.sql file
# changes; polls every second, no extra tooling) and the Vite dev server,
# which proxies /api to the Go server.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -f .env.local ]]; then
  echo ".env.local missing: run scripts/wt-env.sh first" >&2
  exit 1
fi
set -a; . ./.env.local; set +a

mkdir -p bin
srv=""
vite=""
cleanup() {
  [[ -n "$srv" ]] && kill "$srv" 2>/dev/null
  [[ -n "$vite" ]] && pkill -P "$vite" 2>/dev/null && kill "$vite" 2>/dev/null
  wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

(cd web && exec npm run dev -- --clearScreen false) &
vite=$!

changed() {
  find cmd internal web/embed.go \( -name '*.go' -o -name '*.sql' \) -newer bin/.dev-stamp 2>/dev/null | head -1
}

while true; do
  if [[ -z "$srv" || ! -f bin/.dev-stamp || -n "$(changed)" ]]; then
    touch bin/.dev-stamp
    if go build -o bin/raven-dev ./cmd/raven; then
      if [[ -n "$srv" ]]; then kill "$srv" 2>/dev/null || true; wait "$srv" 2>/dev/null || true; fi
      bin/raven-dev &
      srv=$!
      echo "dev: raven (pid $srv) on $RAVEN_HTTP_ADDR — open http://127.0.0.1:$RAVEN_VITE_PORT"
    else
      echo "dev: go build failed; waiting for changes" >&2
    fi
  fi
  sleep 1
done
