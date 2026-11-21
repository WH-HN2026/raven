#!/bin/sh
# vuln lab provisioning (docs/vuln-lab.md §2.4). Lab tooling, not scanning: RAVEN never sends a POST.
# Idempotent: skips installed WordPress sites, recreates the Toxiproxy proxy (no toxics).
set -eu

wait_http() { # url
  i=0
  until curl -s -o /dev/null --max-time 5 "$1"; do
    i=$((i + 1))
    [ "$i" -lt 60 ] || { echo "vlab-init: $1 not reachable" >&2; exit 1; }
    sleep 2
  done
}

install_wp() { # ip title
  url="http://$1"
  wait_http "$url/wp-login.php"
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$url/")
  if [ "$code" = 200 ]; then
    echo "vlab-init: $1 WordPress already installed"
    return
  fi
  # Random admin password, never printed or stored.
  pass=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)
  curl -fsS -o /dev/null --max-time 120 -X POST "$url/wp-admin/install.php?step=2" \
    --data-urlencode "weblog_title=$2" \
    --data-urlencode "user_name=vlab-admin" \
    --data-urlencode "admin_password=$pass" \
    --data-urlencode "admin_password2=$pass" \
    --data-urlencode "pw_weak=1" \
    --data-urlencode "admin_email=admin@example.invalid" \
    --data-urlencode "blog_public=0" \
    --data-urlencode "language="
  code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$url/")
  [ "$code" = 200 ] || { echo "vlab-init: $1 WordPress install failed (GET / = $code)" >&2; exit 1; }
  echo "vlab-init: $1 WordPress installed ($2)"
}

install_wp 10.77.1.10 "RAVEN vlab Modern"
install_wp 10.77.2.12 "RAVEN vlab Proxy"
install_wp 10.77.3.10 "RAVEN vlab Legacy"

tp=http://10.77.2.11:8474
wait_http "$tp/version"
curl -s -o /dev/null -X DELETE "$tp/proxies/wordpress" || true
curl -fsS -o /dev/null -X POST "$tp/proxies" -H 'Content-Type: application/json' \
  -d '{"name":"wordpress","listen":"0.0.0.0:8666","upstream":"10.77.2.12:80","enabled":true}'
echo "vlab-init: toxiproxy proxy wordpress 0.0.0.0:8666 -> 10.77.2.12:80"
