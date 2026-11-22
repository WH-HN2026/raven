# RAVEN — Recon of Assets, Versions, Exposures & Networks

**RAVEN** is a web application built for **AGH** to run safe, recurring attack-surface discovery scans across large networks (10,000+ IPs), track host and service changes between runs, match known vulnerabilities offline, and synchronize findings with **DefectDojo 3.5 (API v2)** as the deduplication and finding-lifecycle engine.

> **Full User Manual (Polish):** For detailed UI walkthroughs, configuration screenshots, workflow setup, and operational reference, see **[`docs/RAVEN-instrukcja.pdf`](docs/RAVEN-instrukcja.pdf)**.

---

## At a Glance

| Capability | Summary |
|---|---|
| **Discovery pipeline** | Modular Go backend (`nmap` → `httpx` → `nuclei`) with adaptive batch sizing and time windows. Optional, admin-gated aggressive stages (`nuclei_active`, `nikto`, `wpscan`, `zap`). |
| **Change tracking & lifecycle** | Run-to-run diffs (new, changed, and gone hosts/services), per-host presence timeline, automatic end-of-run re-probing of missing hosts, and configurable miss thresholds (`active` → `unstable` → `inactive`). |
| **Offline CVE matching** | Local CPE/version matching against an embedded NVD CVE 2.0, CISA KEV, and EPSS dataset (no external API calls at runtime), with distro-backport confidence capping. |
| **DefectDojo 3.5 integration** | One Asset per IP, native parser reimports with deduplication, write-through triage edits from RAVEN UI, **Import from Dojo** targets, and polling of planned engagements (`RAVEN Planning`). |
| **Custom safe signatures** | 49 built-in Nuclei templates plus a YAML editor with strict safe-subset validation (`GET`/`HEAD` only, no payloads, fuzzing, or OAST) and live single-URL testing. |
| **Import & export** | Export hosts, services, findings, changes, and targets to CSV/JSON; import `nmap` XML, `nuclei` JSONL, `.nessus`, and RAVEN CSV/JSON results. |
| **RBAC & data protection** | Four roles (`admin`, `editor`, `operator`, `viewer`), Argon2id passwords, audit logging, and PostgreSQL `pgcrypto` encryption at rest for sensitive scan artifacts and operator notes. |
| **MCP server** | Built-in Streamable HTTP Model Context Protocol server at `/mcp` using Bearer API tokens bound to user roles. |

---

## Quick Start

### Prerequisites

- Docker Engine with Docker Compose v2
- Internet access during the initial image build (all scanner templates, WPScan metadata, and CVE data are baked into the image for offline runtime)
- Free host ports: `8000` (RAVEN), `18080` (DefectDojo HTTP), `8443` (DefectDojo HTTPS), and `127.0.0.1:5433` (RAVEN Postgres)

### Deploy in 3 Commands

```sh
git clone https://github.com/WH-HN2026/raven.git && cd raven
scripts/gen-env.sh           # generates .env with random secrets and encryption key
docker compose up -d --build
```

### Access & Credentials

| Service | Default URL | Username | Password |
|---|---|---|---|
| **RAVEN** | http://localhost:8000 | `admin` | `RAVEN_ADMIN_PASSWORD` in `.env` |
| **DefectDojo** | http://localhost:18080 | `admin` | `DD_ADMIN_PASSWORD` in `.env` |

Print all login credentials at once:

```sh
grep -E '^(RAVEN_ADMIN_|DD_ADMIN_)' .env
```

### Verify DefectDojo Bootstrap

On first startup, DefectDojo runs database migrations (typically 1–2 minutes). RAVEN waits automatically, acquires an API token, and creates the `RAVEN` organization and `RAVEN Planning` asset. Confirm readiness with:

```sh
docker compose logs raven | grep "dojo bootstrap done"
```

### Changing Default Ports

If any default port is already in use, edit `.env` before (or after) starting and recreate the stack:

```sh
RAVEN_PORT=8000
DD_PORT=18080
DD_TLS_PORT=8443
RAVEN_DB_PORT=5433
RAVEN_DOJO_PUBLIC_URL=http://localhost:18080   # match DD_PORT so UI links point to Dojo
```

Then run `docker compose up -d`.

### Stopping & Resetting

```sh
docker compose down          # stop containers and keep database volumes
docker compose down -v       # stop containers and delete all stored data
```

> **Encryption key notice:** `scripts/gen-env.sh` generates `RAVEN_ENCRYPTION_KEY` in `.env` and refuses to overwrite an existing `.env` without `-f`. Losing `.env` makes existing encrypted columns unreadable.

---

## Bundled Test Labs

Two local test environments are included for safe verification without scanning external networks. Run **one lab (and one reference stack) at a time**.

### 1. Reference Lab (`lab/reference/`)

Runs the unmodified reference Compose stacks (verified against `lab/reference/SHA256SUMS` via `make lab-verify`):

```sh
make lab-up LAB=reference                      # STACK=quickstart (default) | custom-network | modern | modern-proxy | vulnerable
make lab-change                                # introduces a service change in quickstart (stops port 8787)
make lab-down LAB=reference                    # pass the same STACK= used with lab-up
```

**Steps in RAVEN:**
1. Open **Targets** → enter `172.17.0.1` (the Docker bridge gateway; `make lab-up` prints it if different) → click **Add targets**.
2. Open **Runs** → select **Default** (or **Aggressive**) → click **Start run**.
3. Review discovered assets and vulnerabilities in **Hosts**, **Services**, **Findings**, and DefectDojo (`http://localhost:18080`).
4. *(With `STACK=quickstart`)* Run `make lab-change`, click **Start run** again on **Runs**, then open **Changes** to view the diff.

**Notes:**
- The `Default` port list covers all reference stack ports (plus RAVEN `:8000` and DefectDojo TLS `:8443` on the host). Add `172.17.0.1` under **Profiles → Profile include** if you have other targets configured.
- The optional `zap` stage runs on an internal-only Docker network and cannot reach `172.17.0.1`.
- If a host firewall (`ufw`, `firewalld`, `nftables`) blocks container-to-host traffic to `172.17.0.1`, allow traffic from the Docker bridge. Stop conflicting host services before starting `STACK=modern` (ports `80`, `81`, `443`, `6379`, `8080`, `8081`).

### 2. Built-in Fixture Lab (`compose.lab.yml`)

Provides 13 isolated services on the internal `raven_lab` network (`172.30.0.0/24`, no ports published on the host): WordPress, Joomla, nginx `/admin`, staging app, Tomcat, simulated printer, self-signed and expired TLS hosts, simulated `Apache/2.4.49` and `OpenSSH_7.4` banners for offline CVE matching, a flapping host (`172.30.0.27`), and two MariaDB instances.

```sh
make lab-up                                                       # start fixture containers on 172.30.0.16/28
docker compose -f compose.yml -f lab/raven.compose.yml up -d      # attach raven and zap to raven_lab
```

**Steps in RAVEN:**
1. Open **Targets** → enter `172.30.0.16/28` (or switch to **Upload CSV / JSON** and upload `lab/targets.txt`) → click **Add targets**.
2. *(Optional)* Open **Profiles** → click **Default** (or **Aggressive**) → add `172.30.0.16/28` under **Profile include** to scan only the lab.
3. Open **Runs** → select **Default** (or **Aggressive**) → click **Start run**.
4. Review results in **Hosts**, **Services**, and **Findings** (CVE matches appear on `172.30.0.25` and `172.30.0.26`).
5. *(Unstable host test)* Run `scripts/lab-flap.sh off` (or `on` / `toggle`), click **Start run** again on **Runs**, then check **Changes** and **Hosts** (`172.30.0.27`).

**Clean shutdown** (detach `raven` and `zap` from `raven_lab` before stopping the lab):

```sh
docker compose up -d raven zap
make lab-down
```

---

## Roles & MCP Server

### Roles (RBAC)

RBAC is enforced server-side on both the HTTP API and the MCP endpoint. Manage users and API tokens on the **Users** page (admin-only).

| Role | Permissions |
|---|---|
| `viewer` | Read all views and export CSV/JSON (`read`, `export`). |
| `operator` | `viewer` + triage findings and edit host metadata/overrides (`findings:edit`, `hosts:edit`). |
| `editor` | `operator` + manage targets, non-aggressive profiles/scope, schedules, signatures, imports, and start/stop runs (`targets:write`, `scope:write`, `profiles:write`, `schedules:write`, `signatures:write`, `import`, `runs:control`). |
| `admin` | Full access: users, API tokens, global scope/blacklist, audit log, and creating/editing/scheduling aggressive profiles (`scan:aggressive`). |

### MCP Server (`/mcp`)

RAVEN exposes a Streamable HTTP MCP server at `http://localhost:8000/mcp`, authenticated with `Authorization: Bearer <token>` (issue tokens on **Users → API tokens**; each token inherits its user's RBAC role).

- **Read tools** (`read`): `search_hosts`, `get_host`, `list_findings`, `get_changes`, `list_runs`
- **Editor tools** (`runs:control`, `targets:write`): `start_scan`, `add_targets`

---

## Safety & Data Protection

- **Strict scope enforcement:** Targets are expanded (CIDR, DNS), filtered through profile include rules, and filtered against profile and global exclusions—exclusions always win.
- **Controlled scan intensity:** Every scanner runs with enforced rate limits, strict per-tool flag allowlists, and context-bound time caps (stopping a run or hitting a schedule window boundary terminates scanner processes immediately).
- **Safe default vs. gated aggressive mode:** The default workflow (`nmap → httpx → nuclei`) uses safe scripts, single-GET HTTP probes, and safe/validated templates only—never credential brute-forcing, DoS, or out-of-band callbacks (`interactsh`/OAST). Aggressive stages (`nuclei_active`, `nikto`, `wpscan`, `zap`) require explicit opt-in and admin privileges to configure or schedule (`scan:aggressive`), are audit-logged, and still disallow brute-forcing, DoS, and OAST.
- **Offline runtime:** CVE/KEV/EPSS matching, Nuclei templates, and WPScan metadata run completely offline with zero external API calls.
- **Encryption at rest & audit trail:** Sensitive columns in `raven-db` (operator notes, service banners, HTTP headers, cookies, TLS certificates, Nuclei evidence, and raw scan artifacts) are encrypted with PostgreSQL `pgcrypto` (`pgp_sym_encrypt`) and SQL statement logging is disabled (`log_statement=none`). All state-changing operations are recorded in `audit_log` with sensitive values redacted. *(DefectDojo uses its own stock PostgreSQL instance without column encryption.)*

---

## Documentation

- **[`docs/RAVEN-instrukcja.pdf`](docs/RAVEN-instrukcja.pdf)** — Complete Polish user manual covering deployment, UI workflows, profiles, DefectDojo integration, custom signatures, import/export, and labs.
