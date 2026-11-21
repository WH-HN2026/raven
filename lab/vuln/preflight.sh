#!/usr/bin/env bash
# make vlab-up preflight: 10.77.0.0/16 must be free on this machine (docs/vuln-lab.md §2.1).
# Fails when another Docker network or a host route (VPN, site network) overlaps it.
set -euo pipefail

net=raven_vlab
subnet=10.77.0.0/16
own_dev=""

if docker network inspect "$net" >/dev/null 2>&1; then
  have=$(docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}} {{end}}' "$net")
  internal=$(docker network inspect -f '{{.Internal}}' "$net")
  if [ "${have% }" != "$subnet" ] || [ "$internal" != true ]; then
    echo "vlab preflight: network $net exists with subnet '${have% }' internal=$internal; expected $subnet internal=true." >&2
    echo "Remove it (make vlab-down) and retry." >&2
    exit 1
  fi
  id=$(docker network inspect -f '{{.Id}}' "$net")
  own_dev="br-${id:0:12}"
fi

# Other Docker networks inside 10.77.0.0/16.
others=$(docker network ls -q | xargs -r docker network inspect -f '{{.Name}} {{range .IPAM.Config}}{{.Subnet}} {{end}}' \
  | awk -v n="$net" '$1 != n { for (i = 2; i <= NF; i++) if ($i ~ /^10\.77\./ || $i ~ /^10\.0\.0\.0\/8$/) print $1 " " $i }')
if [ -n "$others" ]; then
  echo "vlab preflight: Docker networks overlap $subnet:" >&2
  echo "$others" >&2
  exit 1
fi

# Host routes that cover or sit inside 10.77.0.0/16 (except the default route and our own bridge).
routes=$( { ip -4 route show match "$subnet"; ip -4 route show root "$subnet"; } \
  | { grep -v '^default' || true; } | sort -u | { if [ -n "$own_dev" ]; then grep -v "dev $own_dev" || true; else cat; fi; } )
if [ -n "$routes" ]; then
  echo "vlab preflight: host routes overlap $subnet (VPN or site network?):" >&2
  echo "$routes" >&2
  echo "The vuln lab uses fixed addresses in $subnet; disconnect that network first." >&2
  exit 1
fi
echo "vlab preflight: $subnet is free"
