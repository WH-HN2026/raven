# RAVEN — Recon of Assets, Versions, Exposures & Networks

Recurring, safe discovery scans of large networks (nmap → httpx → nuclei), change tracking between runs, and DefectDojo 3.5 as the dedup and finding-lifecycle engine. Prototype for AGH CBI.

## Deploy

Needs Docker Engine with Compose v2, internet access for the image build, and free ports 8000, 8080, 8443 and 127.0.0.1:5433.

```sh
git clone https://github.com/WH-HN2026/raven && cd raven
scripts/gen-env.sh                 # writes .env with random secrets
docker compose up -d --build
```

| What | URL | User | Password |
|---|---|---|---|
| RAVEN | http://localhost:8000 | `admin` | `grep RAVEN_ADMIN_PASSWORD .env` |
| DefectDojo | http://localhost:8080 | `admin` | `grep DD_ADMIN_PASSWORD .env` |

RAVEN connects to DefectDojo by itself once Dojo has finished its first boot (about a minute); `docker compose logs raven | grep "dojo bootstrap done"` confirms it.

Ports taken? Set `RAVEN_PORT`, `DD_PORT`, `DD_TLS_PORT` and `RAVEN_DB_PORT` in `.env`, and `RAVEN_DOJO_PUBLIC_URL=http://localhost:<DD_PORT>`, then run `docker compose up -d` again.

## Demo

One command brings up RAVEN, DefectDojo and the vuln lab (the organizers' four example stacks on the isolated network `10.77.0.0/16`), seeds the blacklist, targets, the `vuln-lab` profile and three demo users, and runs the first scan. Details: [`docs/vuln-lab.md`](docs/vuln-lab.md) §6.

```sh
git clone https://github.com/WH-HN2026/raven && cd raven
docker login                   # recommended: Docker Hub rate-limits anonymous pulls (≈10 GB of lab images)
make demo                      # = scripts/demo.sh up; safe to re-run
make demo ARGS="--scale"       # + scale layer (256 hosts in 10.77.64.0/18) and the vuln-lab-scale profile
make demo ARGS="--l1 --no-run" # + the L1 test lab; seed only, no first run
make demo-down                 # stop everything, keep data
make demo-reset                # delete RAVEN/Dojo/lab volumes and .demo-credentials; keeps .env (asks first; CONFIRM=1 skips)
```

Needs Docker with Compose v2, `curl`, `jq`, about 8 GB RAM and 20 GB free disk. If a pull fails with `429 Too Many Requests`, run `docker login` (or wait) and run `make demo` again. Passwords: `admin` in `.env` (`RAVEN_ADMIN_PASSWORD`), `demo-editor`, `demo-operator` and `demo-viewer` in `.demo-credentials`. Scenario steps (service gone, version change, new device, host offline, …): `scripts/vlab-scenario.sh`.

## Scan the local test lab

```sh
docker compose -f compose.lab.yml up -d --build --wait            # 13 fixtures on 172.30.0.0/24
docker compose -f compose.yml -f lab/raven.compose.yml up -d      # attach RAVEN to the lab network
```

In RAVEN: **Targets** → add `172.30.0.16/28` as a target and as an include → **Runs** → **Start run**. Expected results per host: [`docs/lab.md`](docs/lab.md). Toggle the unstable host with `scripts/lab-flap.sh off|on`.

Add more users with the roles `admin`, `editor`, `operator` and `viewer` on the **Users** page.

## MCP server

RAVEN exposes a Streamable HTTP MCP server at `/mcp`, authenticated with `Authorization: Bearer <token>` (issue tokens on the **Users** page; tokens inherit their user's RBAC role).

- **Read tools** (`read`): `search_hosts`, `get_host`, `list_findings`, `get_changes`, `list_runs`
- **Editor tools** (`runs:control` / `targets:write`): `start_scan`, `add_targets`

## Stop

```sh
docker compose down                # keep data; add -v to delete all data
```

## Docs

[Architecture](docs/architecture.md) · [Import/export formats](docs/exchange.md) · [Test lab](docs/lab.md) · [Vuln lab and demo](docs/vuln-lab.md) · [Scale test](docs/scale.md) · [Acceptance pass](docs/acceptance.md) · [Roadmap](docs/roadmap.md)
