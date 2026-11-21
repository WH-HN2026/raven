# ASI — Architecture

Attack Surface Intelligence: a web app that runs safe, recurring discovery scans of large networks (10k+ IPs) for AGH CBI. It fingerprints services and web technologies, tracks changes over time, and uses **DefectDojo** as its deduplication and finding-lifecycle engine.

The brief and the organizers' notes are in [`challenge.md`](challenge.md), and the task breakdown is in [`roadmap.md`](roadmap.md). **This is a hackathon prototype: when in doubt, choose the simpler option.**

## 1. Decisions (settled; don't re-litigate)

| # | Decision |
|---|---|
| D1 | **Web-only.** No CLI. Every "push" action (target entry, CSV/JSON import, starting scans, schedules, signatures) is done in the web UI. |
| D2 | **Go backend in one binary, `asi`.** It contains the HTTP API, the embedded SPA, the scheduler, and the scan workers (goroutines plus a Postgres-backed job queue). |
| D3 | **React SPA** (Vite + TypeScript), built and embedded into the Go binary with `embed`. |
| D4 | **DefectDojo: newest only (3.5.x), API v2, token auth.** One service-account token. Dojo is the dedup and lifecycle engine. RBAC is enforced **only in our app**, because OSS Dojo 3.x has no real roles. |
| D5 | **Host identity = IP address. One Dojo Asset (Product) per IP.** Hostnames are attributes of the IP. |
| D6 | **Scanners: nmap → httpx → nuclei**, each behind a `Scanner` interface. nmap finds hosts and services, httpx collects the HTTP facts (title, status, headers, cookies, TLS, redirects, favicon hash, technologies), and nuclei runs detection templates and our signatures. Results reach Dojo through Dojo's **native parsers** ("Nmap Scan", "httpx Scan", "Nuclei Scan"). Nessus is supported by **importing `.nessus` files** (Dojo's "Tenable Scan" parser), not by running it. |
| D7 | **Custom signatures = nuclei templates**, restricted to a safe subset by our validator. |
| D8 | **Encryption at rest = Postgres-native `pgcrypto`** on sensitive columns of our DB. Dojo's own DB is stock Postgres 18 and is not encrypted; the docs say so. |
| D9 | **Schedules come from two sources:** our UI, and Dojo Engagements planned ahead (polled and imported into our schedule table). |
| D10 | **MCP server is the last feature.** It is a thin layer over the same service functions and RBAC. |
| D11 | **Vulnerability detection = fingerprints → offline CVE matching + safe signatures.** No active vulnerability checks. CPE + version from nmap/httpx/nuclei is matched against a CVE dataset committed to the repo (§11). |

## 2. System overview

```
                         Browser (React SPA, AGH theme)
                                    │  JSON / session cookie
┌───────────────────────────────────▼─────────────────────────────────────┐
│ asi  (single Go binary)                                                  │
│                                                                          │
│  HTTP API (chi) ── auth/RBAC middleware ── service layer (internal/*)    │
│        │                                         │                       │
│  scheduler ── creates runs ──► job queue (River, in Postgres)            │
│        ▲                              │                                  │
│  dojo engagement poller  scan workers: nmap ─► httpx ─► nuclei ─► ingest │
│                                       │                  │               │
│                                       │                  ▼               │
│  dojo sync (pull) ◄───────────────────┼──────── dojo push (reimport)     │
└────────┬──────────────────────────────┼────────────────────┬─────────────┘
         │                              │                    │
   our Postgres 18          nmap / httpx / nuclei       DefectDojo 3.5
   (pgcrypto, River,             binaries in the        (API v2, its own
    read-model)                  same container)        Postgres, celery…)
```

Runtime: Docker Compose runs `asi`, `asi-db` (Postgres 18 with pgcrypto) and the stock DefectDojo stack. See §10 for deployment.

## 3. Data flow of one scan run

1. **Targets → scan list.** Targets are entered manually or uploaded as CSV/JSON, and can be IPs, CIDRs or domains.
   - Domains are resolved to IPs; the domain → IP mapping is kept, so HTTP probes can use the hostname (virtual hosts).
   - The profile's include list is applied, then the **global blacklist** (exclusions always win).
   - IPs are de-duplicated.
2. **Batch planning.** The IP list is split into batches.
   - Size = `measured_hosts_per_second × target_batch_seconds` (default 600 s), clamped to `[64, 4096]`.
   - Throughput comes from the profile's previous runs (default 50 hosts/s for a first run).
   - Each batch is one job. Its duration and host count are recorded, which is how "check the scan duration" is answered.
3. **Discovery + services (nmap)**, one process per batch:
   - `-sn` host discovery (ICMP echo + TCP SYN/ACK pings on common ports);
   - then `-sS -sV` on the **allowed port list** of the profile;
   - safe scripts only: `http-title,http-headers,ssl-cert,banner`;
   - `--max-rate` from the profile;
   - output is XML.
4. **HTTP fingerprinting (httpx).** For every HTTP(S) service nmap found, build URLs: `scheme://ip:port` plus `scheme://hostname:port` for known hostnames (virtual hosts). Run httpx on them (JSON lines) with:
   - one GET per URL, following redirects and recording the chain (`-fr -include-chain`);
   - `-title -sc -irh -tls-grab -favicon -td`: title, status, all response headers (cookies come from `Set-Cookie`), TLS certificate, favicon mmh3 hash, technology detection;
   - `-rl` rate limit, `-disable-update-check`.

   This fills `http_observations`. The same URLs go to the next step.
5. **Detection (nuclei).** Run nuclei on the URLs httpx confirmed alive (JSONL output) with:
   - our curated official template tags (`tech`, `panel`, `ssl`, `waf`, `favicon`, …);
   - our custom signatures;
   - `-rl` rate limit, `-no-interactsh`, `-disable-update-check`;
   - exclude-tags `intrusive,dos,fuzz,bruteforce,rce,sqli,xss,…`;
   - exclude-types `code,headless,javascript`.
6. **Ingest (our DB).** Parse all three outputs into `hosts`, `services`, `http_observations` and `run_observations`. Store the raw artifacts (encrypted) in `artifacts`. Update `first_seen`/`last_seen` and the miss counters. Every product + version (with its CPE) is matched against the local CVE data (§11).
7. **Push (Dojo)**, for every IP that **responded** in this run:
   - make sure the Asset `"<ip>"`, its Engagement and its Tests exist;
   - `reimport-scan` the nmap XML, httpx JSON and nuclei JSONL filtered to this IP (one Test per scanner), with `close_old_findings=true`;
   - Dojo dedups and marks findings new/closed/reactivated.
8. **Shadow IT / lifecycle.**
   - IP never seen before → the Asset is created with an **INFO finding "New device found"**.
   - IP that didn't respond → **not reimported**; its `miss_count` goes up by one.
   - `miss_count` reaches the profile's threshold (default 3) → push an INFO finding "Host offline" and mark the host `inactive`.
   - A host that responds again resets its counter, and Dojo reactivates its findings on the next reimport.
9. **Unstable hosts.** IPs that were up in the previous run but are down now are re-probed **once more at the end of the run**, before they count as a miss.
10. **Time window.** A batch job runs with `ctx` deadline = window end. On deadline the scanner processes are killed, the batch is set back to `pending`, and the run becomes `suspended`. The next window resumes from the remaining batches of the same run.

## 4. DefectDojo mapping

| Dojo object | Our meaning | Notes |
|---|---|---|
| Organization (Product_Type) | `ASI` (one, configurable) | created on startup if missing |
| Asset (Product) | one IP, name = the IP | tags: `asi`, `host:<hostname>`, user tags; description = user notes |
| Engagement (per Asset) | `ASI: <profile name>`, type CI/CD | one long-lived engagement per (IP, profile) |
| Test | one per (IP, profile, scanner) | reimported every run → Dojo's diff |
| Finding | Dojo native parser output + our INFO findings | our INFO findings use Generic Findings Import with a stable `unique_id_from_tool` |
| Location (URL) | `tcp://ip:port`, `https://host:port/path` | produced by the native parsers |
| Asset `ASI Planning` + its Engagements | **planned scans** | engagements tagged `asi-profile:<name>`; their `target_start`/`target_end` become a schedule window |

**Planned engagements (D9).**
- Every 5 min the poller lists engagements of the `ASI Planning` asset that have status `Not Started`.
- For each one it upserts a `schedules` row (`source='dojo'`, `dojo_engagement_id`), using the tagged profile and the window from `target_start`–`target_end`.
- It sets the engagement status to `In Progress` when the run starts and `Completed` when it finishes.

**Pull / read-model.** Every 5 min `dojo sync` pages through `/api/v2/findings/?tags=asi` (plus Assets) and upserts them into `dojo_findings` / `dojo_assets`. A full resync is fine at lab scale. The dashboard reads only our DB and never calls Dojo per request.

**Write-through edits.** Finding edits made in our UI (severity, active / false-positive / risk-accepted, notes) are sent straight to Dojo with PATCH, then the mirror row is updated. Reimport keeps the triage state of existing findings.

## 5. Our database (Postgres 18)

Migrations: goose, **timestamp-named** (`YYYYMMDDHHMMSS_name.sql`), embedded into the binary. Queries: sqlc (`internal/db/queries/*.sql` → generated `internal/db/gen`). Job queue: River (its own tables, created by its migrator).

Core tables (sketch; M0 creates them, later tasks add their own migrations):

```
users(id, username, password_hash, role, disabled, created_at)
sessions(token_hash, user_id, expires_at)
api_tokens(id, user_id, token_hash, name, created_at)                 -- for MCP
scope_entries(id, kind ip|cidr|domain, value, list include|exclude,
              profile_id NULL = global, note, created_by)
targets(id, kind, value, source manual|csv|json|dojo, tags[], created_by)
profiles(id, name, ports, nmap_max_rate, nuclei_rate, nuclei_tags[],
         miss_threshold, target_batch_seconds, enabled)
schedules(id, profile_id, source ui|dojo, dojo_engagement_id NULL,
          cron NULL, window_start, window_end, timezone, enabled)
runs(id, profile_id, schedule_id, status pending|running|suspended|done|failed,
     started_at, finished_at, hosts_total, hosts_up, stats jsonb)
batches(id, run_id, seq, ips inet[], status, attempts, started_at, finished_at, duration_ms)
hosts(ip inet PK, hostnames text[], state active|unstable|inactive,
      first_seen, last_seen, miss_count, dojo_asset_id,
      -- user-owned, never written by scans:
      owner, criticality, notes_enc, user_tags[], overrides jsonb)
services(id, ip, port, proto, name, product, version, banner_enc,
         state open|gone, first_seen, last_seen, overrides jsonb)
http_observations(id, service_id, url, status, title, headers_enc, cookies_enc,
                  tls_cert_enc, redirects jsonb, technologies text[], favicon_hash,
                  run_id, observed_at)
run_observations(run_id, ip, port NULL, up bool, observed_at)          -- diff + time-of-day
signatures(id, name, template_yaml, enabled, valid, validation_error, created_by)
artifacts(id, run_id, batch_id, scanner, content_enc bytea)
dojo_assets(id, name, ip, tags[], synced_at)
dojo_findings(id, asset_id, ip, title, severity, active, verified, false_p,
              risk_accepted, is_mitigated, tags[], scanner, date, last_status_update, synced_at)
audit_log(id, user_id, action, object, object_id, diff jsonb, at)
```

**Scan-owned vs user-owned (requirement 14).** Scans write only the scan-owned columns. User-owned columns (owner, criticality, notes, user tags, and anything set through edit forms) are never touched by ingest. The same rule applies to user edits of scan-owned data, such as correcting a service name: they go into an `overrides` jsonb that the read path layers on top of the scan data.

**Encryption (D8).**
- `CREATE EXTENSION pgcrypto` plus two SQL helpers created by M0:
  - `asi_enc(text) → bytea` = `pgp_sym_encrypt(t, current_setting('asi.enc_key'))`
  - `asi_dec(bytea) → text`
- The key comes from `ASI_ENCRYPTION_KEY`. It is set on every pooled connection in pgx `AfterConnect` via `set_config('asi.enc_key', $1, false)`.
- Encrypted columns end in `_enc` and are `bytea`. Queries call `asi_enc(@x)` / `asi_dec(col)`.
- Keep IPs, ports and other filter/join keys **in plaintext**: they are identifiers, not secrets.
- Statement logging must stay off on `asi-db`.

## 6. RBAC

The roles come straight from requirement 13:

| Role | Can |
|---|---|
| `admin` | everything + users, roles, API tokens, Dojo connection, global blacklist, global rate limits |
| `editor` | add / delete / modify: targets, scope, profiles, schedules, signatures, imports, start/stop scans, edit findings and hosts |
| `operator` | modify + read: edit findings and hosts (triage, notes, tags), no create/delete |
| `viewer` | read everything, export |

- One file, `internal/auth/rbac.go`, defines the `Permission` constants and the `role → permissions` map.
- Each handler declares its permission with `auth.Require(perm)`, and the frontend hides what the role can't do.
- The **backend check is the source of truth**; the frontend only hides things.
- Every mutation writes to `audit_log`.

Auth: local users with argon2id passwords. Server-side sessions use an `HttpOnly; SameSite=Strict` cookie, and unsafe methods need a `X-ASI-CSRF` header. API tokens (hashed) exist for MCP.

## 7. Backend layout

```
cmd/asi/main.go              wires config → db → services → http server + workers
internal/config/             env config (ASI_*)
internal/db/                 pool (with enc key), migrations/, queries/, gen/ (sqlc)
internal/auth/               users, sessions, rbac.go, middleware
internal/httpapi/            router.go (mounts each area), one file per area: targets.go, runs.go …
internal/targets/            parse manual/CSV/JSON, CIDR expand, domain resolve, scope filtering
internal/scanner/            Scanner interface + types
internal/scanner/nmap/       command builder, XML parser → observations
internal/scanner/httpx/      command builder, JSON parser → http_observations
internal/scanner/nuclei/     command builder, JSONL parser, template policy
internal/signatures/         safe-subset validator for nuclei templates
internal/pipeline/           run orchestration: batching, jobs, ingest, miss counting, re-probe
internal/scheduler/          schedules, windows, suspend/resume, dojo engagement poller
internal/dojo/               API v2 client, push (reimport, INFO findings), sync (pull)
internal/changes/            diff between runs, time-of-day presence, interestingness score
internal/cve/                 CPE normalization, version-range matching, embedded CVE/KEV/EPSS data (§11)
internal/exchange/           JSON/CSV import & export; nmap XML, nuclei JSONL and .nessus import
internal/mcp/                (last) MCP server over the service layer
api/openapi.yaml             the HTTP contract (source of truth for the frontend)
signatures/                  built-in custom nuclei templates shipped with the app
```

**Scanner interface:**

```go
type Scanner interface {
    Name() string                 // "nmap", "httpx", "nuclei"
    DojoScanType() string         // "Nmap Scan", "httpx Scan", "Nuclei Scan"
    Run(ctx context.Context, in Input, opt Options) (*Result, error) // ctx cancel = kill process
}
type Result struct {
    Raw          []byte                      // tool output, stored encrypted, pushed to Dojo
    Observations []Observation               // normalized: host up/down, service, http, tech, match
    PerIP        func(ip netip.Addr) []byte  // raw output filtered to one IP, for per-Asset reimport
}
```

Adding a scanner means adding a package that implements `Scanner` and registering it in the pipeline's scanner list. Nothing else changes.

**API.**
- `api/openapi.yaml` is the contract.
- Go: hand-written chi handlers that follow it.
- Frontend: types generated with `openapi-typescript` (`web/src/api/schema.d.ts`, committed).
- JSON everywhere. Lists use `?limit=&offset=` and return `{items, total}`.
- Errors return `{error: {code, message}}`.

## 8. Frontend

`web/`: Vite + React + TypeScript + TanStack Query + React Router + Tailwind. Charts use Recharts.

- **Pages:**
  - Dashboard
  - Hosts (list, detail + edit)
  - Services / Technologies
  - Findings (from the Dojo mirror, editable)
  - Changes (run vs run compare, timeline, time-of-day heatmap)
  - Runs (progress, batches, durations)
  - Targets & Scope (form + CSV/JSON upload, black/whitelist)
  - Profiles & Schedules (UI + Dojo-sourced, read-only for the latter)
  - Signatures (editor + validate)
  - Import / Export
  - Users (admin)
- **Theme and layout:** [`design/README.md`](design/README.md), the agh.edu.pl look. Black top bar with the AGH logo, red `#C10D14` accents, Roboto, square corners, the AGH squares band in the page header and footer. Tokens go in `web/src/theme.css`; each screen has a mockup in `design/canvas/`.
- **Routing:** each page lives in `web/src/pages/<area>/` and exports its routes; `web/src/routes.tsx` only concatenates them.
- **Dev:** `vite` dev server proxies `/api` to the Go server. **Prod:** `make build` puts `web/dist` into the binary.

## 9. Safety (scored criterion; non-negotiable)

- **nmap:**
  - no `-A`, no `-sC`, no `--script` outside the allowlist in `internal/scanner/nmap`;
  - `--max-rate` is always set;
  - only the profile's allowed ports.
- **httpx:** one GET per URL (no path brute-forcing, no `-path` lists), rate limit always set.
- **nuclei:** only allowlisted tags plus our signatures; the exclusion flags above are always applied; `-no-interactsh`; a rate limit is always set.
- **Signatures:** the validator rejects any template that has
  - a method other than GET/HEAD;
  - a request body, payloads/attack/fuzzing;
  - `code`/`headless`/`javascript`/`network` write steps;
  - DSL that could make extra requests;
  - interactsh.
- **Scope:** the global blacklist is applied after every expansion step, and no target is scanned unless it matches some include entry.
- **Credentials:** no login attempts anywhere. Paths like `/admin`, `/login` and `/version` may be fetched with GET only.
- **CVE matching** is offline only: match product/version to CPEs locally. Never send our data to external APIs.

## 10. Deployment (Docker Compose) and configuration

**Deployment is `docker compose up -d --build` from the repo root, and nothing else.** One `compose.yml` serves as both the production deployment and the dev infra: dev just starts a subset of its services.

```
compose.yml                 # the deployment: asi + asi-db + DefectDojo (via include)
deploy/dojo.compose.yml     # DefectDojo 3.5.202 services copied from its repo, images pinned
deploy/Dockerfile           # multi-stage: node (web build) → go (binary) → runtime with nmap + httpx + nuclei + templates
compose.lab.yml             # local test lab (task L1), separate network, never needed in prod
.env.example                # every variable, with safe defaults; copied to .env
scripts/gen-env.sh          # creates .env with random secrets (encryption key, passwords, Dojo secret key)
```

| Service | Image | Port | Notes |
|---|---|---|---|
| `asi` | built from `deploy/Dockerfile` | 8000 | `cap_add: [NET_RAW, NET_ADMIN]`; on the default network and the lab network; runs migrations on start |
| `asi-db` | `postgres:18` | 5433 (dev only) | volume `asi-db-data`; `log_statement=none`; healthcheck |
| DefectDojo (`nginx`, `uwsgi`, `celeryworker`, `celerybeat`, `initializer`, `postgres`, `valkey`) | official `defectdojo/*:3.5.202` | 8080 | unchanged from upstream except the pinned tag and `DD_ADMIN_PASSWORD` coming from `.env` |

- **No manual Dojo token.** If `ASI_DOJO_TOKEN` is empty, `asi` waits for Dojo to be healthy and gets a token via `POST /api/v2/api-token-auth/` with `DD_ADMIN_USER`/`DD_ADMIN_PASSWORD`. It then creates the `ASI` organization and the `ASI Planning` asset if they're missing.
- **Startup order:** `depends_on` with `condition: service_healthy` on `asi-db`. The Dojo wait is a retry loop inside `asi`, because Dojo's first boot (migrations) takes minutes.
- **Dev:** `make infra-up` = `docker compose up -d asi-db nginx uwsgi celeryworker celerybeat initializer postgres valkey` (everything except `asi`). The Go binary then runs on the host via `make dev`.
- **Scanning network:** by default `asi` scans from the bridge network; it is attached to the lab network for the local lab. If the organizers' lab needs L2 host discovery (ARP), set `network_mode: host` on `asi` and point `ASI_DOJO_URL` at `localhost:8080`. That's a one-line override and is documented in the README.

Configuration (env, all in `.env`):

```
ASI_HTTP_ADDR=:8000
ASI_DATABASE_URL=postgres://asi:${ASI_DB_PASSWORD}@asi-db:5432/asi
ASI_ENCRYPTION_KEY=<32+ random bytes, base64>       # generated by gen-env.sh; losing it = losing encrypted data
ASI_DOJO_URL=http://nginx:8080
ASI_DOJO_TOKEN=                                      # optional; otherwise obtained with the admin credentials
DD_ADMIN_USER=admin
DD_ADMIN_PASSWORD=<generated>
ASI_DOJO_ORGANIZATION=ASI
ASI_ADMIN_USERNAME / ASI_ADMIN_PASSWORD              # bootstrap admin of our app on first start
```

## 11. Vulnerability matching (offline)

Matching fingerprints to known vulnerabilities is allowed (organizers' note 2); sending exploits is not. All matching is local.

- **Identity: CPE.**
  - Every `service`/`tech` observation carries `cpe` (vendor:product) and `version`.
  - nmap gives CPEs directly (`<cpe>` in `-sV` output).
  - httpx technology names map to CPEs through a table generated from Wappalyzer's fingerprint data.
  - nuclei tech templates carry `metadata.vendor/product`.
- **Data, committed to the repo** (`internal/cve/data/`, gzip, a few MB), regenerated by `make cve-db`. The build and runtime never call external APIs.
  - **NVD CVE 2.0** records for a curated product list (`internal/cve/products.txt`, about 50–100 vendor:product pairs we actually detect: web servers, CMSes, panels, SSH/FTP/mail servers, appliances).
  - **CISA KEV** (known exploited) and **EPSS** scores for prioritization.
- **Matching.** Product + version against NVD configuration ranges (`versionStart/End Including/Excluding`), with a version comparator that handles `1.2.3`, `8.9p1` and `2.4.49-r0`.
- **Confidence.**
  - `high`: an exact version from a banner/header with no distro suffix.
  - `low`: the banner shows a distro build (e.g. `OpenSSH 8.9p1 Ubuntu 3ubuntu0.10`, `Debian`, `el8`). Distros backport fixes, so these findings are capped at **Low** severity and tagged `cve:distro-build`.
- **Findings.** **One finding per product instance** (IP + port + product + version), not one per CVE:
  - title: `nginx 1.18.0: 7 known CVEs (2 KEV)`;
  - severity = highest CVSS, raised by one level if any CVE is in KEV (subject to the distro cap);
  - `vulnerability_ids` = all CVE IDs;
  - description lists CVEs with CVSS, EPSS and KEV.

  Pushed with Generic Findings Import into a per-IP Test "ASI CVE match", with `unique_id_from_tool = ip:port:cpe:version`. A version change closes the old finding and opens a new one on reimport.

## 12. Out of scope (for the hackathon)

Multi-tenant orgs inside our app, SSO/LDAP, HA/clustering, Dojo versions older than 3.5, a CLI, active vulnerability verification of any kind.
