# vuln lab

The organizers' four example stacks (kept verbatim in [`organizers/`](organizers/)) rebuilt as one RAVEN-safe lab: `compose.vlab.yml` at the repo root, project `raven-vlab`, internal network `raven_vlab` (10.77.0.0/16), static IPs, pinned images, no published ports. Design, address plan, expected results and scenarios: [`docs/vuln-lab.md`](../../docs/vuln-lab.md).

```sh
docker login                 # optional; avoids Docker Hub's unauthenticated pull limit
make vlab-pull               # ~10 GB the first time, retries on 429
make vlab-up                 # subnet preflight, up --wait, then the init job (WordPress installs, Toxiproxy proxy)
make vlab-ps
docker compose -f compose.yml -f lab/vuln/raven.compose.yml up -d    # attach RAVEN as 10.77.254.10
make vlab-down               # detaches RAVEN and other containers, stops the lab, keeps volumes
```

Before the first scan, add the global excludes `10.77.0.1` (gateway = the host) and `10.77.254.0/23` (RAVEN and lab tooling). Targets: [`targets.csv`](targets.csv). Ports for the `vuln-lab` profile: [`ports.txt`](ports.txt).

| File | Purpose |
|---|---|
| `raven.compose.yml` | override that attaches the `raven` service to `raven_vlab` |
| `targets.csv`, `ports.txt` | targets (`value,tags,note`) and the profile port spec |
| `traefik/wordpress.yml` | Traefik dynamic config: `PathPrefix(/)` → Toxiproxy `10.77.2.11:8666` |
| `flask-app.conf` | nginx on 8787 for the "flask-app" on the shared app host 10.77.4.20 |
| `init/vlab-init.sh` | one-shot provisioning run by `make vlab-up` |
| `preflight.sh` | fails when 10.77.0.0/16 overlaps another Docker network or a host route |

Compose profiles: `scenario` (shadow-IT device `10.77.9.50`, `httpd:2.4.49-alpine`), `tools` (`raven-lab-tools:local` at `10.77.254.20`, curl/nc/nmap for checks inside the lab), `init` (the init job).

Scenario hooks for `scripts/vlab-scenario.sh`:
- `VLAB_FLASK_NGINX_TAG` selects the flask-app nginx tag. Default `1.20.0-alpine` (CVE-2021-23017); the upgrade tag is **`1.30.7-alpine`**:
  `VLAB_FLASK_NGINX_TAG=1.30.7-alpine docker compose -f compose.vlab.yml up -d --wait flask-app`.
- Toxics: Toxiproxy API `http://10.77.2.11:8474`, proxy `wordpress`, only from a container on `raven_vlab`.
