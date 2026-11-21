#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ $# != 1 || ! $1 =~ ^(on|off|toggle)$ ]]; then
  echo "usage: $0 on|off|toggle" >&2
  exit 2
fi

compose=(docker compose -f compose.lab.yml)
action=$1
if [[ $action == toggle ]]; then
  running=$("${compose[@]}" ps --status running -q flap)
  if [[ -n $running ]]; then
    action=off
  else
    action=on
  fi
fi

case "$action" in
  on) "${compose[@]}" up -d --no-deps --wait flap ;;
  off) "${compose[@]}" stop flap ;;
esac
