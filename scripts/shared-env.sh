#!/usr/bin/env bash
# The shared dev infra (`make infra-up`, compose project "raven") has ONE set of
# secrets: the .env of the main checkout. This script creates it there if it
# is missing, and in a linked worktree makes ./.env a symlink to it, so
# `docker compose` behaves the same from every checkout.
# Prints the path of the shared .env.
set -euo pipefail
here="$(git rev-parse --show-toplevel)"
main="$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")"
shared="$main/.env"

if [[ ! -f "$shared" ]]; then
  "$here/scripts/gen-env.sh" "$main" >&2
fi

if [[ "$here" != "$main" ]]; then
  if [[ -L "$here/.env" || ! -e "$here/.env" ]]; then
    ln -sfn "$shared" "$here/.env"
  elif ! cmp -s "$here/.env" "$shared"; then
    echo "warning: $here/.env is a separate file; the shared infra uses $shared" >&2
  fi
fi
echo "$shared"
