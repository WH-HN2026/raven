#!/usr/bin/env bash
# Creates .env from .env.example, replacing every "generated" value with a
# random secret. Refuses to overwrite an existing .env unless -f is given
# (overwriting loses ASI_ENCRYPTION_KEY and the DB passwords of existing volumes).
#
#   scripts/gen-env.sh [-f] [target-dir]
set -euo pipefail

force=0
if [[ "${1:-}" == "-f" ]]; then force=1; shift; fi
repo="$(cd "$(dirname "$0")/.." && pwd)"
dir="${1:-$repo}"
out="$dir/.env"

if [[ -e "$out" && $force -eq 0 ]]; then
  echo "$out already exists; not overwriting (use -f to force; you'd lose its secrets)" >&2
  exit 1
fi

# 32 random bytes as URL-safe base64 without padding: safe in URLs and shell.
secret() { head -c 32 /dev/urandom | base64 | tr -d '\n=' | tr '+/' '-_'; }

tmp="$(mktemp "$dir/.env.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
while IFS= read -r line || [[ -n "$line" ]]; do
  if [[ "$line" =~ ^([A-Z0-9_]+)=generated$ ]]; then
    echo "${BASH_REMATCH[1]}=$(secret)"
  else
    echo "$line"
  fi
done < "$repo/.env.example" > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$out"
trap - EXIT
echo "wrote $out"
