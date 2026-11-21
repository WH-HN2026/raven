#!/bin/sh
# Proves the built-in pack with real nuclei: every template must hit its own
# fixture and not the neutral one. nuclei and the fixture server run in ONE
# container of the asi image with --network none, so only loopback is
# reachable. Usage: signatures/fixsrv/prove.sh [image]   (default asi:local)
set -eu
cd "$(dirname "$0")/.."
image=${1:-asi:local}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
CGO_ENABLED=0 go build -o "$tmp/fixsrv" ./fixsrv
cp fixsrv/in-container.sh "$tmp/"
docker run --rm --network none -v "$PWD:/pack:ro" -v "$tmp:/w:ro" --entrypoint sh "$image" /w/in-container.sh
