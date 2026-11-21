#!/usr/bin/env bash
# Vuln lab scale layer (docs/vuln-lab.md §5): N hosts with personas in 10.77.64.0/18 on raven_vlab.
#
#   scripts/vlab-scale.sh up [N]    start (or resize) with N hosts (default 256, max 4096); returns when all answer
#   scripts/vlab-scale.sh churn     next epoch: ~3 % hosts gone, ~3 % new, ~5 % changed; prints `expect`
#   scripts/vlab-scale.sh expect    expected Changes of the current epoch vs the previous one (JSON on stdout)
#   scripts/vlab-scale.sh status    running?, N, seed, epoch, memory
#   scripts/vlab-scale.sh down      remove the container and its addresses
#
# VLAB_SCALE_SEED (default 1) picks another layout. Scan it only with the vuln-lab-scale profile
# (10.77.64.0/18, ports 21,22,80,443,8080,8443,9100) and the vlab blacklist in place.
set -euo pipefail
cd "$(dirname "$0")/.."

COMPOSE=(docker compose -f compose.vlab-scale.yml)
CONTAINER=raven-vlab-scale-swarm-1
IMAGE=raven-vlab-scale:local

die() { echo "vlab-scale: $*" >&2; exit 1; }

# cur VAR: the value of VAR in the running swarm, empty if it isn't running.
cur() {
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$CONTAINER" 2>/dev/null | sed -n "s/^$1=//p" || true
}

start() { # start N SEED EPOCH
  docker network inspect raven_vlab >/dev/null 2>&1 || die "network raven_vlab missing: run 'make vlab-up' first"
  local t0=$SECONDS
  VLAB_SCALE_HOSTS=$1 VLAB_SCALE_SEED=$2 VLAB_SCALE_EPOCH=$3 "${COMPOSE[@]}" up -d --build --wait --wait-timeout 300 swarm
  echo "vlab-scale: $1 hosts up (seed $2, epoch $3) in $((SECONDS - t0)) s"
  docker logs "$CONTAINER" 2>&1 | grep -E 'added|ready' | tail -n 2
}

case "${1:-}" in
  up)
    n=${2:-$(cur VLAB_SCALE_HOSTS)}
    n=${n:-256}
    if [[ ! $n =~ ^[0-9]+$ ]] || ((n < 1 || n > 4096)); then
      die "N must be 1..4096"
    fi
    seed=${VLAB_SCALE_SEED:-$(cur VLAB_SCALE_SEED)}
    seed=${seed:-1}
    epoch=0
    # same size and seed as the running swarm: keep its epoch (idempotent)
    if [[ "$(cur VLAB_SCALE_HOSTS)" == "$n" && "$(cur VLAB_SCALE_SEED)" == "$seed" ]]; then
      epoch=$(cur VLAB_SCALE_EPOCH)
    fi
    start "$n" "$seed" "$epoch"
    ;;
  churn)
    n=$(cur VLAB_SCALE_HOSTS)
    [[ -n $n ]] || die "not running: scripts/vlab-scale.sh up [N] first"
    seed=$(cur VLAB_SCALE_SEED)
    epoch=$(($(cur VLAB_SCALE_EPOCH) + 1))
    start "$n" "$seed" "$epoch"
    "$0" expect
    ;;
  expect)
    n=$(cur VLAB_SCALE_HOSTS)
    [[ -n $n ]] || die "not running: scripts/vlab-scale.sh up [N] first"
    docker run --rm --network none -e "VLAB_SCALE_HOSTS=$n" -e "VLAB_SCALE_SEED=$(cur VLAB_SCALE_SEED)" \
      -e "VLAB_SCALE_EPOCH=$(cur VLAB_SCALE_EPOCH)" "$IMAGE" expect
    ;;
  status)
    if [[ -z "$(cur VLAB_SCALE_HOSTS)" ]]; then
      echo "vlab-scale: not running"
      exit 0
    fi
    echo "hosts=$(cur VLAB_SCALE_HOSTS) seed=$(cur VLAB_SCALE_SEED) epoch=$(cur VLAB_SCALE_EPOCH)" \
      "health=$(docker inspect -f '{{.State.Health.Status}}' "$CONTAINER")"
    docker stats --no-stream --format 'mem={{.MemUsage}} cpu={{.CPUPerc}}' "$CONTAINER"
    ;;
  down)
    "${COMPOSE[@]}" down --remove-orphans --volumes
    ;;
  *)
    sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
