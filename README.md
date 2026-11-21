# RAVEN — Recon of Assets, Versions, Exposures & Networks

Recurring, safe discovery scans of large networks (nmap → httpx → nuclei), change tracking between runs, and DefectDojo 3.5 as the dedup and finding-lifecycle engine. Prototype for AGH CBI.

## Deploy

Needs Docker Engine with Compose v2, internet access for the image build, and free ports 8000, 18080, 8443 and 127.0.0.1:5433.

```sh
git clone https://github.com/WH-HN2026/raven && cd raven
scripts/gen-env.sh                 # writes .env with random secrets
docker compose up -d --build
```

| What | URL | User | Password |
|---|---|---|---|
| RAVEN | http://localhost:8000 | `admin` | `grep RAVEN_ADMIN_PASSWORD .env` |
| DefectDojo | http://localhost:18080 | `admin` | `grep DD_ADMIN_PASSWORD .env` |

RAVEN connects to DefectDojo by itself once Dojo has finished its first boot (about a minute); `docker compose logs raven | grep "dojo bootstrap done"` confirms it.

Ports taken? Set `RAVEN_PORT`, `DD_PORT`, `DD_TLS_PORT` and `RAVEN_DB_PORT` in `.env`, and `RAVEN_DOJO_PUBLIC_URL=http://localhost:<DD_PORT>`, then run `docker compose up -d` again.

## Scan a lab

Two lab scenarios, one at a time ([`docs/lab.md`](docs/lab.md)).

**Ours** (13 fixtures on the internal network `172.30.0.0/24`):

```sh
make lab-up                                                       # = docker compose -f compose.lab.yml up -d --build --wait
docker compose -f compose.yml -f lab/raven.compose.yml up -d      # attach RAVEN to the lab network
```

In RAVEN: **Targets** → add `172.30.0.16/28` as a target and as an include → **Runs** → **Start run**. Expected results per host: [`docs/lab.md`](docs/lab.md). Toggle the unstable host with `scripts/lab-flap.sh off|on`.

**The organizers'** (their files in `lab/organizers/`, run as-is):

```sh
make lab-up LAB=organizers                     # STACK=quickstart (default)|custom-network|modern|modern-proxy|vulnerable
make lab-change                                # their ./quickstart.sh change
make lab-down LAB=organizers                   # same STACK= as lab-up
```

In RAVEN: **Targets** → add `172.17.0.1` (once) → **Runs** → **Start run** with the profile **Organizers' lab** (include 172.17.0.1, their published ports only).

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

[Architecture](docs/architecture.md) · [Import/export formats](docs/exchange.md) · [Labs](docs/lab.md) · [Scale test](docs/scale.md) · [Acceptance pass](docs/acceptance.md) · [Roadmap](docs/roadmap.md)
