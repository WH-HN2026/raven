# RAVEN — Roadmap

Each task is sized for **one worktree / one agent session**. Pick any task whose dependencies are `done`. The architecture is in [`architecture.md`](architecture.md); the workflow rules are in [`../AGENTS.md`](../AGENTS.md).

**Status:** `[ ]` todo · `[x]` done (flipped in the task's PR before merging). In progress = an open PR titled `<ID>: …` exists.
**Claiming a task:** open a draft PR titled `<ID>: …` (see AGENTS.md). `gh pr list` is the live view of who is working on what; this file is updated as PRs merge.

## Milestones

| Milestone | Goal | Demo-able result |
|---|---|---|
| **M0 Foundation** | skeleton, infra, contracts | `make dev` serves an AGH-themed login page; `make check` is green |
| **M1 Walking skeleton** | thin end-to-end path | manual target → nmap → hosts in our DB → Assets/findings in Dojo → list in UI |
| **M2 Scored features** | everything the jury tests | two runs against the lab show new/gone/changed, fingerprints, signatures, roles, import/export |
| **M3 Polish + extras** | the "nice to have" list | heatmap, interestingness, CVE matching, demo script, docs, slides |
| **M4 MCP** | last feature | an MCP client can query hosts/findings/changes and start scans, with RBAC |

M0 is sequential and blocking. Do it in **one** worktree, as fast as possible, then split. From M1 on, the tracks below run in parallel. Within a track, the order shown is the dependency order unless noted.

---

## M0 — Foundation (sequential, blocks everything)

- [x] **F0 Repo skeleton & tooling.**
  - `go.mod`, `cmd/raven`, `internal/config`.
  - Makefile targets `dev`, `check`, `gen`, `build`, `infra-up`, `infra-down`, `db-new name=…`.
  - `.gitignore`, `.env.example`.
  - `.github/workflows/check.yml`: runs `make check` (Go + Node, no Docker) on PRs and on `main`; the job is named `check` (branch protection requires it). Keep it under ~5 min with Go/npm caching.
  - `web/` Vite + React + TS + Tailwind + React Router + TanStack Query.
  - The Go server serves the embedded SPA, and `/api/healthz` works.
- [x] **F1 Docker Compose deployment** (architecture §10).
  - Root `compose.yml` = `raven` + `raven-db` + `include: deploy/dojo.compose.yml` (DefectDojo 3.5.202, pinned).
  - `deploy/Dockerfile`, multi-stage: web build → Go build → runtime with nmap + nuclei + pinned templates.
  - `.env.example` + `scripts/gen-env.sh`.
  - `raven` gets its Dojo token itself from the admin credentials.
  - `make infra-up` starts everything except `raven`.
  - Done when `docker compose up -d --build` on a clean clone gives a working app on :8000 and Dojo on :8080, with no manual steps.
- [x] **F2 DB baseline.**
  - goose (timestamp names, embedded) + sqlc config; pgx pool with `raven.enc_key` set in `AfterConnect`.
  - Baseline migration: `pgcrypto`, `raven_enc`/`raven_dec`, and **all core tables** from architecture §5, so later tasks rarely touch the same migration.
  - River migrations run on startup.
- [x] **F3 Contracts.**
  - `api/openapi.yaml` with the common schemas (error, pagination, Host, Service, Run, Finding …) and the stubbed paths for every area; TS generation wired up in `make gen`.
  - `internal/scanner` interface + types.
  - `internal/dojo` client interface.
  - `internal/auth/rbac.go` with roles and the permission map.
  - `internal/httpapi/router.go` with one `mount<Area>(r)` call per area.
  - `web/src/routes.tsx` concatenating page modules.
- [x] **F4 Auth & app shell.**
  - Login/logout, sessions, bootstrap admin from env, `auth.Require` middleware, CSRF header.
  - SPA shell per [`docs/design/`](design/README.md): theme tokens in `web/src/theme.css`, self-hosted Roboto, the page frame (top bar with logo and role-filtered nav, black page header with the squares band, footer), login page.
  - Worktree helper `scripts/wt-env.sh` (see AGENTS.md "Parallel worktrees").

## M1 — Walking skeleton (parallel tracks; each needs M0)

**Track S — Scanning**
- [x] **S1 Targets & scope.** Parse manual, CSV and JSON targets (ip / cidr / domain); expand CIDRs; resolve domains (keep the domain→IP map); include/exclude filtering with the global blacklist last; unit tests with large CIDRs (/16).
- [x] **S2 nmap scanner.** Command builder (safe flag allowlist, ports, `--max-rate`), XML → observations parser, `PerIP` filtering, fixture-based tests in `testdata/`.
- [x] **S3 Pipeline v1.** (needs S1, S2) Run → batches (fixed size for now) → River jobs → nmap → ingest into `hosts`/`services`/`run_observations`/`artifacts`; run/batch status and durations.

**Track D — DefectDojo**
- [x] **D1 Dojo client.** API v2: organization/asset/engagement/test get-or-create, `import-scan`/`reimport-scan` (multipart), findings list/patch, notes, tags; retries + concurrency limit; integration test against the compose Dojo (`-tags integration`).
- [x] **D2 Push.** (needs D1, S3) After each batch, for each responding IP: ensure the Asset/Engagement/Test chain and reimport nmap results; "New device found" INFO finding via Generic Findings Import with a stable `unique_id_from_tool`.
- [x] **D3 Sync (pull).** (needs D1) Periodic job → `dojo_assets`/`dojo_findings` mirror tables; API `GET /api/findings` reading the mirror.

**Track W — Web UI**
- [x] **W1 Targets & Scope pages.** (needs S1 API) Manual form, CSV/JSON upload with a preview of parsed entries + errors, black/whitelist editor.
- [x] **W2 Runs page.** (needs S3 API) Start a run for a profile, live progress (polling), batches with durations, stop button.
- [x] **W3 Hosts list + detail.** (needs S3 API) Filterable list (state, port, tech, tag), detail with services and HTTP observations.

## M2 — Scored features

**Track S — Scanning**
- [x] **S7 httpx scanner.** (needs S3; do before S4) Add httpx (pinned release, checksum-verified) to `deploy/Dockerfile`. Command builder with the safe flag set from architecture §3.4, URL building from nmap's HTTP(S) services + known hostnames, JSON parser → `http_observations` (title, status, headers, cookies, TLS cert, redirect chain, favicon hash, technologies), `PerIP` filtering, fixture tests; wire into the pipeline after nmap.
- [x] **S4 nuclei scanner.** (needs S7) Command builder with the template policy (allowed tags, exclusions, `-no-interactsh`, rate limit), run on the URLs httpx found alive; JSONL parser → matches (technologies, panels, signature hits) attached to the service/URL; wire into the pipeline after httpx.
- [x] **S5 Adaptive batching + rate limits.** Batch size from measured throughput, per-profile `--max-rate` / nuclei `-rl`, global concurrency cap.
- [x] **S6 Unstable hosts & lifecycle.** End-of-run re-probe of hosts that were up last run and are down now; `miss_count` and the `active → unstable → inactive` state machine; profile `miss_threshold`.
- [x] **S8 Keep CPEs.** (needs S2) Add `CPE` to `scanner.Observation` (and a `cpe` column on `services`). The nmap parser keeps `<cpe>` values, normalized to `vendor:product` + version. Fixture tests. httpx/nuclei fill it in S7/S4 via the mapping from C3.

**Track D — DefectDojo**
- [x] **D4 Push httpx + nuclei + lifecycle findings.** (needs S7, S4, S6) Reimport httpx ("httpx Scan") and nuclei per IP, one Test per scanner; push "Host offline" once the threshold is hit; tags (`tech:*`, `panel:*`, `env:*`, `host:*`) on Assets.
- [x] **D5 Planned engagements poller.** `RAVEN Planning` asset, poll `Not Started` engagements tagged `raven-profile:<name>` → `schedules(source='dojo')`, update engagement status on run start/finish.
- [x] **D6 Write-through edits.** Finding edits in our API → PATCH Dojo → update the mirror; host user-fields → Asset description/tags.

**Track P — Platform**
- [x] **P1 Scheduler & time windows.** Schedules (frequency + window + timezone) from both sources; start runs in-window; `ctx` deadline at window end → kill, set the batch back to pending, mark the run `suspended`; resume in the next window.
- [x] **P2 RBAC hardening + users admin API.** The four roles enforced on every route (table-driven test that walks all routes × roles); user CRUD; audit log on every mutation.
- [x] **P3 Import/export.** Our JSON/CSV formats for targets and **scan results** (results go through the same ingest + push path as scanner output; use the sample format from the organizers once we have it); import of raw nmap XML / nuclei JSONL and **Nessus `.nessus` files** (pushed to Dojo with the "Tenable Scan" parser into the matching IP's Asset); export of hosts/services/findings/changes to JSON/CSV with the current filters.
- [x] **P4 Encryption audit.** Every sensitive field uses `_enc` + helpers; a test proves the ciphertext in the DB is not plaintext; docs section.

**Track C — Changes & fingerprinting**
- [x] **C1 Run diff.** `internal/changes`: compare two runs → new / gone / changed hosts and services (a changed product/version/title/tech counts as changed); API `GET /api/changes?from=&to=`.
- [x] **C2 Signature validator + built-in pack.** Safe-subset validator (architecture §9) and an API to CRUD, validate and test signatures. A built-in pack of **about 30–40 nuclei templates** in `signatures/`, each with a lab fixture or a recorded response proving it matches:
  - headers: version leaks (`Server`, `X-Powered-By`, `X-AspNet-Version`), `X-Environment`/debug headers, missing HSTS/CSP/X-Frame-Options;
  - cookies: known session cookies (`PHPSESSID`, `JSESSIONID`, `ASP.NET_SessionId`, `laravel_session`, `wordpress_*`), missing Secure/HttpOnly;
  - favicon mmh3 hashes of common panels (Jenkins, Grafana, GitLab, phpMyAdmin, Tomcat manager, Fortinet, Hikvision/Dahua cameras, printers);
  - GET-only admin/login/version paths (`/admin`, `/login`, `/wp-admin/`, `/phpmyadmin/`, `/manager/html`, `/version`, `/actuator/health`, `/server-status`);
  - staging/test markers (title, header, hostname, robots.txt);
  - version string in the page footer;
  - IoT/printer/router page titles.

  **Organizers' format:** when their sample signatures arrive, write a converter to our nuclei subset (or accept their format directly) and add all their samples plus their "interesting artefacts" list to the pack.
- [x] **C3 Offline CVE matching.** (needs S8; uses S7/S4 output once merged) Architecture §11:
  - `make cve-db` fetches NVD CVE 2.0 for the curated `internal/cve/products.txt`, plus CISA KEV and EPSS, into committed gzip data;
  - CPE mapping for httpx/nuclei technology names, and a version-range matcher with table tests (`8.9p1`, `2.4.49`, distro suffixes);
  - confidence and the distro severity cap, with one finding per matched CVE per product instance in the "RAVEN CVE match" Test (Generic Findings Import, one ID in `vulnerability_ids`);
  - feeds the interest score (X2).

**Track W — Web UI**
- [x] **W4 Dashboard.** Key findings by severity, new/gone/changed since the last run, new devices (shadow IT), unstable hosts, top technologies, last runs with durations.
- [x] **W5 Findings page.** Mirror list with filters, inline triage (status, severity, notes) via D6; link out to Dojo.
- [x] **W6 Changes page.** Pick two runs → diff table; per-host timeline.
- [x] **W7 Profiles & Schedules pages.** Profile editor (ports, rates, nuclei tags, miss threshold), schedule editor; Dojo-sourced schedules shown read-only with a badge.
- [x] **W8 Signatures page.** YAML editor, validate button with errors, enable/disable, test against one URL in the lab.
- [x] **W9 Users page + role-aware UI.** User admin; every action button hidden/disabled per role.
- [x] **W10 Host edit.** Edit user-owned fields + overrides; show "edited by user" markers; verify edits survive the next run.
- [x] **W11 Restyle to the design.** (best after W2, W3) Bring the shell and existing pages in line with [`docs/design/`](design/README.md):
  - replace the guessed palette in `web/src/theme.css` with the design tokens (red `#C10D14` primary, black frame) and self-host Roboto / Roboto Mono;
  - replace the sidebar with the black top bar, the black page header with the squares band, and the footer (assets in `docs/design/assets/`);
  - square corners everywhere, and restyle the merged pages (Targets, Runs, Hosts) to their mockups;
  - remove explanatory copy.
- [x] **W12 Import/Export page.** UI for P3: upload scan results (RAVEN JSON/CSV, nmap XML, nuclei JSONL, .nessus) with the import result; export buttons (JSON/CSV with the current filters) on Hosts, Findings, Changes and Targets.

**Track L — Lab**
- [x] **L1 Local test lab.** `compose.lab.yml` on an isolated docker network: WordPress, Joomla or Drupal, nginx with `/admin`, an app with `X-Environment: staging`, Tomcat, a fake IoT banner (e.g. a small Go service), a TLS service with a self-signed/expired cert, **two or three services that only announce known-vulnerable versions** (e.g. a tiny Go server sending `Server: Apache/2.4.49`, an SSH banner `OpenSSH_7.4`) so CVE matching can be demoed without real vulnerable software, and **one flapping container** (toggled by a script) for unstable-host testing. Until the organizers' lab arrives, **all dev scans target only this network.**

## M3 — Polish & extras

- [ ] **X1 Time-of-day presence.** Heatmap of host/service presence by hour from `run_observations`; mark hosts as "time-dependent".
- [ ] **X2 Interestingness score.** Weighted score per host (admin panel, staging, outdated version, new device, CVE match, interesting cookie/header, unusual port); sort the dashboard by it.
- [ ] **X4 Grouping & tags.** Group similar services (same tech + version / same favicon hash / same title); tag management UI.
- [ ] **X5 Export observations to Dojo.** Select observations in the UI → push as INFO findings, with evidence attached.
- [ ] **X6 Demo script + docs.** `scripts/demo.sh` (two runs with a lab change in between), README quickstart, technical docs, ≤10 slides.
- [x] **N1 Rename to RAVEN.** Project, module, binary, env vars, DB helpers, Dojo-facing names, lab and docs renamed from ASI to RAVEN.
- [x] **Q2 Scale test.** Fake-scanner load test of run planning, batching, ingest, Dojo push and the dashboard/hosts APIs at 10k and 65k hosts; bottlenecks fixed; numbers in docs.
- [x] **Q4 Services & technologies page + API follow-ups.** GET /api/services, Services/Technologies page; severity and tags in the signatures API; more findings status filters; "last edited by" on hosts.
- [x] **Q3 Fingerprinting loose ends.** httpx/nuclei technologies get CVE matches via cve.CPEForTech; POST /api/signatures/{id}/test runs the template against one in-scope URL; schedules API has a name and a DefectDojo link.
- [x] **Q1 Acceptance pass + image build in CI.** Fresh-clone deploy, lab attached, two runs with a lab change, all 12 jury test points walked; docs/acceptance.md with results; CI builds the Docker image.
- [x] **U3 Findings layout + active findings counts.** Finding detail opens next to (wide) or under (narrow) the clicked row; active findings on the dashboard, hosts list and host detail.
- [x] **U4 Behaviour fixes.** One Dojo finding per matched CVE; adding an existing target shows "Target already exists"; run comparison only older → newer.
- [x] **U2 Naming & navigation fixes.** User profile page, flat breadcrumbs, clearer labels (intermittent hosts, exclude, signature status, type, profile enabled, batch duration).
- [x] **U1 Sortable columns + instant filters.** Every list view has asc/desc sort on its column headers; filters apply immediately (no Apply button).

**Track WF — Workflows & aggressive preset**
- [x] **WF0 Workflow & aggressive guardrails.** Docs: architecture workflows section and §9 split (always / default / aggressive), AGENTS.md safety rules, roadmap track WF, jury note.
- [x] **WF1 Workflow model.** Stage registry with dependencies; `profiles.stages` (migration: existing profiles → Default); API validation (400 on missing dependency); pipeline runs only enabled stages; runs record executed stages; no Dojo reimport for stages that did not run; Changes compares shared stages only.
- [x] **WF2 Workflow builder UI.** (needs WF1) Stage cards with toggles in the profile editor, Default/Aggressive presets, dependents auto-disabled with a "needs <stage>" label; stage badges on profiles and runs.
- [x] **AG1 Aggressive gating.** (needs WF1) `scan:aggressive` permission (admin), confirmation on start, "Aggressive" badge on profiles/runs, audit_log entries, viewer/editor 403s.
- [x] **AG2 nuclei active.** (needs AG1) intrusive/fuzz templates pinned in an aggressive set, dos excluded, no interactsh; own Dojo test.
- [x] **AG3 nikto.** (needs AG1) Pinned in the image, flag allowlist with limited tuning and rate/time caps, "Nikto Scan" push, lab test.
- [x] **AG4 wpscan.** (needs AG1) Pinned in the image, WordPress URLs only, enumeration without passwords or API token, "Wpscan" push, versions into offline CVE matching, lab test against the lab WordPress.
- [x] **AG5 ZAP.** (needs AG1) ZAP service under compose profile `aggressive`, API-driven spider + capped active scan, "ZAP Scan" push, lab test.

**Track V — vuln_lab (organizers' example lab)** · design and task specs: [`vuln-lab.md`](vuln-lab.md)
- [x] **V0 vuln_lab design + roadmap track V.** Organizers' files kept verbatim in `lab/vuln/organizers/`; `docs/vuln-lab.md` with topology (`raven_vlab`, 10.77.0.0/16), service inventory, scenarios mapped to the jury test points, scale layer, one-command demo, safety, task specs.
- [x] **V1 RAVEN-safe vuln lab.** All four organizers' stacks together on the internal `raven_vlab` network: `compose.vlab.yml` with static IPs, no published ports, pinned images, healthchecks and an init job; `lab/vuln/` attach override, `targets.csv`, `ports.txt`; `scripts/lib/raven-api.sh`; `make vlab-pull/vlab-up/vlab-down/vlab-ps`. (needs V0)
- [x] **V2 Scenario driver.** `scripts/vlab-scenario.sh` with every scenario step (service gone/back, upgrade, new device, host off/on, Toxiproxy toxics, signature, edits, import/export, roles, time window, Dojo planned engagement, `walk`), idempotent, printing what to check. (needs V1)
- [x] **V3 Fingerprint coverage for the vuln lab.** Built-in signatures with recorded fixtures for NPM, Traefik, Toxiproxy, RabbitMQ, Adminer, phpMyAdmin at `/`, DVWA and the Gitea version; CVE aliases (`vsftpd:vsftpd`, …) and `CPEForTech` synonyms; migration adding the lab ports to the default profile. (needs V1)
- [ ] **V4 Scale layer + real-scan measurements.** One multi-address container serving up to 4,096 persona hosts in `10.77.64.0/18`, deterministic churn with expected counts, `scripts/vlab-scale.sh`; real two-run scans at 256 and 1,024 hosts measured into `docs/scale.md`. (needs V1)
- [x] **V5 One-command demo.** `make demo` / `scripts/demo.sh`: gen-env if missing, RAVEN + Dojo + vuln lab up and attached, wait for Dojo, seed blacklist/targets/profiles/demo users through the API, Run 1; `make demo-down`, `make demo-reset`; README Demo section. (needs V1; uses V4's script when present)
- [ ] **V6 Acceptance pass on the vuln lab.** Fresh clone, `make demo`, every scenario step as the jury would, expected-vs-actual tables in `docs/vuln-lab.md`, follow-ups. (needs V2, V3, V4, V5)
- [x] **V7 Response time and slow hosts.** httpx response time stored per HTTP observation and shown; "slow" and "HTTP unresponsive" services in run stats and Changes (organizers' Toxiproxy scenario). (needs V1)
- [ ] **V8 Aggressive stages on the vuln lab.** Admin-made aggressive profile limited to WordPress 4.7.5 and DVWA; nuclei-active/nikto/wpscan/ZAP results documented. (needs V2, AG2–AG5)

## M4 — MCP (last)

- [ ] **MCP1 MCP server.** `internal/mcp` using the official Go MCP SDK, streamable HTTP at `/mcp`, auth by API token (P2), the same RBAC. Read tools: `search_hosts`, `get_host`, `list_findings`, `get_changes`, `list_runs`. Editor tools: `start_scan`, `add_targets`. Admin UI to issue tokens.

---

## Dependency picture

```
M0: F0 → F1 → F2 → F3 → F4
        │
M1:     ├─ S1 ─┬─ S3 ─┬─ D2          W1 (S1)  W2/W3 (S3)
        │  S2 ─┘      │
        └─ D1 ────────┴─ D3
M2:  S7 (S3) → S4 · S5, S6 (S3) · D4 (S7,S4,S6) · S8 (S2) · D5 (D1) · D6 (D3) · P1..P4 · C1 (S3) · C2 · C3 (S8) · W4..W11 · L1 (anytime)
M3:  after the relevant M2 parts     M4: after P2
WF:  WF0 → WF1 → WF2 · AG1 (WF1) → AG2..AG5
V:   V0 → V1 → { V2 · V3 · V4 · V5 · V7 } (parallel; disjoint files) → V6 · V8 (V2, AG2..AG5)
```

L1 (lab) has no dependencies and is a good first task for whoever is free while M0 is being built.
