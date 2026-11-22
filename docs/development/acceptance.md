# Acceptance pass (Q1), run as the jury would

Date: 2026-11-21, against `main` at `da35b21` (Q3, #45). One person, one fresh clone, the local lab only.

The CVE finding titles below reflect the aggregate format observed during Q1. Since U4, Dojo gets one finding per CVE per product instance. [Vulnerability matching architecture](architecture.md#11-vulnerability-matching-offline)

## Environment

- Linux x86_64, Docker Engine with Compose v2. The fresh clone lives in a temp directory, not in a worktree.
- The shared dev stack was already running on this machine (compose project `asi`: ports 8000, 8443, 18080, 127.0.0.1:5433; the `asi-lab` lab on 172.30.0.0/24; another service on 127.0.0.1:8080). It was not touched.
  - So the fresh stack ran as compose project `raven-q1`, with these values in its `.env`: `RAVEN_PORT=18500`, `DD_PORT=18580`, `DD_TLS_PORT=18543`, `RAVEN_DB_PORT=15533` and `RAVEN_DOJO_PUBLIC_URL=http://localhost:18580`. A jury machine won't have this collision (bug m1).
  - The lab ran as project `raven-q1-lab` on network `raven_q1_lab`. It used 172.31.0.0/24 because `asi-lab` holds 172.30.0.0/24. This needed an uncommitted rewrite of `172.30.0.` in five files (bug m2). Every address below is the `172.31.0.x` copy of the documented `172.30.0.x` fixture.
- The UI was driven in the Orca browser and the API with curl, using the same session cookies. Users: `admin` (bootstrap), plus `editor`, `operator` and `viewer`, created on the Users page.
- Orca's synthetic mouse clicks did not reach this tab (it painted no frames). Typing, filling and selecting worked, and buttons were clicked through `element.click()`. This is a harness issue, not a RAVEN issue: the same buttons work, and they trigger the same API calls.

## Steps

1. `git clone https://github.com/WH-HN2026/raven` → `scripts/gen-env.sh` → edit the ports (above) → `docker compose -p raven-q1 up -d --build`.
   - All 9 services started, and the initializer exited 0.
   - RAVEN logged `dojo token obtained with admin credentials` 15 s after start, then `dojo bootstrap done organization=RAVEN planning_asset_id=1`.
   - `/api/healthz` returned `{"status":"ok"}`. No manual step was needed beyond `.env`.
   - The image was also built with `docker build --no-cache -f deploy/Dockerfile .`: exit 0, every stage rebuilt, including the httpx/nuclei downloads with checksum checks.
2. Lab: `docker compose -f compose.lab.yml up -d --build --wait` (all 13 fixtures healthy), then `docker compose -p raven-q1 -f compose.yml -f lab/raven.compose.yml up -d`. Seen from inside `raven`, `wget http://172.31.0.20/` returned `X-Environment: staging`.
3. Admin, Targets page: added the target `172.31.0.16/28` (tag `lab`) and the include `172.31.0.16/28`. Admin, Users page: created the users.
4. **Run 1** (admin, Runs → Start run, profile `default`): done in 41 s, 16 candidates, 13 up, 13 services.
5. Edits as operator:
   - host 172.31.0.19: owner, criticality `high`, notes, and a service product override `nginx (CBI admin portal)`;
   - Findings, Tomcat Manager: severity Medium → High plus a note (Save to DefectDojo).
6. Lab changes:
   - stopped one: `scripts/lab-flap.sh off` (172.31.0.27);
   - added one: `docker run --network raven_q1_lab --ip 172.31.0.30 nginx:stable-alpine`;
   - changed one: `nginx-panel` from `nginx:stable-alpine` to `nginx:mainline-alpine` (1.30.7 → 1.31.9), with the title `RAVEN nginx Lab` → `RAVEN nginx Lab v2`.
7. **Run 2** (editor, Runs → Start run): done in 43 s, 13 up, `reprobed=1`, `became_unstable=1`.
8. Editor, Signatures → New signature: a custom template (header `X-Device-Type: printer` and `LabPrinter`). Validate → Valid → Create → Test against 172.31.0.22 (match), 172.31.0.19 (no match) and 8.8.8.8 (refused).
9. Editor, Profiles → New schedule `q1 evening window`: every 10 min, window 18:55–19:05 Europe/Warsaw. Run #5 started at 19:00:17 with `schedule_id=1`.
10. Import/export:
    - as viewer, exported services CSV (`GET /api/export/services?format=csv`, the Export button's endpoint);
    - added a row for 172.31.0.31 (Jenkins 2.440 on 8443);
    - as editor, Import/Export → upload → Import. Result: run #4, `results-csv`, 15 hosts imported.
11. Lifecycle with a threshold-1 profile `q1-fast` (created in the profile editor UI): flap on → run 7 (up) → flap off → run 8. `became_inactive=1`, and Dojo got `Host Offline: 172.31.0.27`.
12. Window kill: profile `q1-slow` (ports 1-1024, max rate 2) with a schedule `* * * * *`, window 19:06–19:08.
    - Run 9 started at 19:06:17 and was `suspended` at the window end.
    - Its batch went back to `pending`, and no nmap/httpx/nuclei process was left in the container.
13. Viewer, operator and editor: walked every page and called the mutation endpoints directly (table below).

## The 12 test points

| # | Test point | Result | What was done / seen | Gap |
|---|---|---|---|---|
| 1 | Active hosts | **PASS** | Run 1: all 13 fixtures `active`; the 3 empty addresses in the /28 were not created as hosts. Run 2: the new 172.31.0.30 was found and 172.31.0.27 was marked missing. Hosts page and `GET /api/hosts`. | — |
| 2 | Service identification | **PASS** | Every service had a product/version: Apache httpd 2.4.71 (WP, Joomla), nginx 1.30.7, Apache Tomcat 11.0.29, OpenSSH 7.4, MariaDB 11.8.9 ×2, Apache 2.4.49 banner, Golang net/http (Go fixtures). Services page and Dojo `Nmap Scan` tests. | The Go fixtures get CPE `protocol_labs:go-ipfs` from nmap (m5). |
| 3 | HTTP/HTTPS fingerprinting | **PASS** | The host page shows status, title, all headers, cookies and the TLS cert. 172.31.0.24 has `expired:true, self_signed:true, not_after 2020-01-01`; 172.31.0.23 has `self_signed:true`. The favicon hash was collected (Tomcat favicon match). The lab has no redirect to check. | The TLS cert is shown as a raw JSON blob (m6). An expired or self-signed cert raises no finding (m7). |
| 4 | CMS / technologies | **PARTIAL** | WordPress 7.1.5 (+ block/site editor, cookie), Joomla, PHP 8.4.28, Apache, Debian, nginx, Tomcat (nmap + nuclei `Apache Tomcat Favicon`, `Tomcat Manager`), staging (`Non-Production Environment Header`, `Non-Production Page Title`). Dojo Asset tags `tech:*`, `panel:*`, `env:staging`. | The lab printer (IoT, `Server: LabPrinter/1.0`, `X-Device-Type: printer`) is not recognised by the built-in pack (M3). The host technology list keeps old versions (`Nginx:1.30.7` and `Nginx:1.31.9`, m4). |
| 5 | Interesting headers & cookies | **PASS** | Findings: `Non-Production Environment Header` (X-Environment), `X-Powered-by Header Discloses the Stack`, `Server Header Discloses a Version` ×5, missing HSTS/CSP/X-Frame-Options, `Cookies Set Without the Secure Flag` (Joomla), `WordPress Cookie`, `Admin Page at /Admin` (nginx `X-Lab-Panel`). | `X-Device-Type: printer` is only caught with a custom signature (M3). |
| 6 | Custom signatures | **PASS** | Created in the UI as editor; Validate showed "Valid"; Test matched 172.31.0.22 and not 172.31.0.19; 8.8.8.8 was refused (`target URL is out of scope`). In the next real run Dojo got `Lab Printer Device Header` (Low, finding 91). The validator rejects POST, request bodies and the `code` protocol, each with line numbers. | — |
| 7 | Comparison between runs | **PASS** | `GET /api/changes?from=1&to=2` and the Changes page: new 172.31.0.30, gone 172.31.0.27, changed 172.31.0.19:80 with `fields: [version, title, technologies]` (1.30.7 → 1.31.9, title → v2). The dashboard shows the same. | An import run counts as "the last run", so the dashboard then shows spurious changes (M4). |
| 8 | Unstable / changing hosts | **PASS** | Run 2 re-probed 172.31.0.27 → `unstable`, `miss_count=1`. Its Dojo findings stayed active (no reimport of a silent host). With threshold 1: `inactive`, `Host Offline: 172.31.0.27` in Dojo; back on → `active`. | Misses only count for a profile that saw the host up before (by design; not visible in the UI). |
| 9 | Scanner safety | **PASS** | Live command lines: `nmap -sS -sV … --script http-title,http-headers,ssl-cert,banner --max-rate 150 -T3 --max-retries 2`; `httpx … -rl 25 -allow <in-scope IPs>`; `nuclei … -no-interactsh -duc -rl 25 -etags intrusive,dos,fuzz,…,default-login,credential -exclude-type code,headless,javascript`. A port spec `80 --script=vuln` and the nuclei tag `intrusive` were rejected (400). The signature test refuses out-of-scope URLs. The window end kills the scanners. | — |
| 10 | Dashboard / report readability | **PARTIAL** | The dashboard shows key numbers, changes since the previous run, findings by severity, new devices, top technologies, CVE matches, unstable hosts and recent runs. All 15 pages loaded as admin and as viewer with 0 console errors. | CVE findings reach Dojo only on the 5-min CVE pass and the Findings page only on the next 5-min sync, so up to ~10 min after a run (M2). Import runs pollute the "changes" widget (M4). TLS is shown as JSON (m6). |
| 11 | Import & export | **PARTIAL** | Export services CSV as viewer (200) → add 172.31.0.31 → import as editor in the UI. Run #4 `results-csv`, 15 hosts. 172.31.0.31 got a Dojo Asset, `Open Port: 8443/TCP`, `New Device Found: 172.31.0.31` and `Jenkins 2.440: 57 Known CVEs (1 KEV)`. Export of hosts/services/findings/changes/targets is available to every role. | Re-importing our own export writes user overrides into scan-owned columns (M5) and revives an offline host (m8). |
| 12 | Role separation | **PASS** | UI: the viewer sees no mutation controls (signature YAML read-only, Users "No access."). The operator sees host/finding edit only. API (direct calls, see below): viewer 403 on every mutation, export 200; operator 403 on targets/runs/users/signatures, 200 on host and finding edits; editor 200 on runs, 403 on users. | — |

API role matrix (direct calls with each user's session):

| Call | viewer | operator | editor |
|---|---|---|---|
| `POST /api/targets` | 403 | 403 | allowed (400 on my bad body) |
| `POST /api/runs` | 403 | 403 | 200 |
| `PATCH /api/hosts/{ip}` | 403 | 200 | 200 |
| `PATCH /api/findings/{id}` | 403 | 200 | 200 |
| `POST /api/users` | 403 | 403 | 403 |
| `DELETE /api/signatures/{id}` | 403 | 403 | allowed (deleted) |
| `GET /api/export/hosts` | 200 | 200 | 200 |

## Minimum scope and other checks

| Requirement | Result | Evidence |
|---|---|---|
| Import of hosts/ranges | PASS | CIDR target and include via the Targets form; CSV/JSON upload is on the same page |
| Import of scan results JSON/CSV | PASS | Run #4 from CSV (above) |
| Large ranges (>10k) | not re-run | covered by Q2 ([`scale.md`](scale.md)) |
| Window and frequency | PASS | schedule runs #5 (in window) and #9 (suspended at window end) |
| Rate limiting | PASS | `--max-rate`, `-rl` on every scanner command (test 9) |
| Results stored in DB | PASS | Postgres `raven-db` |
| Compare two scans | PASS | test 7 |
| Dashboard of key changes | PARTIAL | test 10 |
| Export JSON/CSV | PASS | test 11 |
| Roles | PASS | test 12 |
| Editing scans/results/config survives rescans | PASS | after Run 2: owner/criticality/notes and the product override on 172.31.0.19 kept (`scan.version` moved to 1.31.9, override kept); the Tomcat Manager triage (High + note) kept in Dojo; the Dojo Asset description carries owner, criticality and notes |
| Encryption at rest | PASS | 7 `_enc` columns; the host notes plaintext `Acceptance` and the header `X-Environment` are absent from the raw bytes of `hosts.notes_enc` and of all 71 `http_observations.headers_enc` |
| Audit log | PASS | 51 rows, 18 actions (`runs.start`, `finding.update`, `host.update`, `user.create`, `signatures.*`, `schedules.create`, `profiles.create`, …) |
| Dojo mapping (architecture §4) | PASS | Organization `RAVEN`; one Asset per IP (16); Engagement `RAVEN: <profile>` (CI/CD) per (IP, profile); Tests `RAVEN: nmap`, `RAVEN: httpx`, `RAVEN: nuclei`, `RAVEN lifecycle` (Generic Findings Import); Asset tags `raven`, `tech:*`, `panel:*`, `env:*` |
| "New device" findings | PASS | 13 in Run 1, `New Device Found: 172.31.0.30` in Run 2, 172.31.0.31 from the import |
| CVE match findings | PASS (late) | `Apache HTTPD 2.4.49: 88 Known CVEs (3 KEV)`, `OpenSSH 7.4: 42 Known CVEs (1 KEV)`, both Critical with `vulnerability_ids`; see M2 |
| Dedup on Run 2 | PASS | Dojo had 83 findings after Run 1 and 90 after Run 2. All 7 new ones belong to the new device 172.31.0.30; 0 duplicates; triage kept |
| Dedup across profiles | FAIL | see M1 |
| Schedule with time window | PASS | steps 9 and 12 |
| UI console errors | PASS | 0 errors on all pages |

## Bugs

No blockers remain: deploying from a clean clone works, and every test point can be completed. The one blocker found (B1) is fixed in this PR.

### Blocker

- **B1 (fixed in this PR): no README.** The repo had no README, so a jury member cloning it found no deploy command and no URLs. The credentials were hard to find too: `gen-env.sh` prints only `wrote .env`, and the admin passwords sit in `.env`. AGENTS.md has the commands but is written for agents. This PR adds `README.md` with deploy, login, port overrides, lab attach and the first scan.

### Major

- **M1: a second profile duplicates every finding.**
  - Repro: Run 1 with `default`, then a run with any other profile on the same hosts.
  - Seen: run 6 (profile `q1-fast`) added 70 Dojo findings (ids 95–164), each a copy of one in the `RAVEN: default` engagement, with `duplicate=false`. Tomcat Manager reappeared as Medium next to the triaged High one.
  - Cause: one Engagement/Test per (IP, profile, scanner) by design (§4), while Dojo deduplication across tests isn't enabled.
  - Proposal: turn on Dojo deduplication (product scope) or use one engagement per IP.
- **M2: CVE findings arrive up to ~10 min after a run.**
  - Matching and push run only on the 5-min `CVESync` ticker (`cmd/raven/main.go`), and the Findings mirror updates on the separate 5-min `dojo sync`.
  - Repro: start a run and open Findings filtered to Critical right after it finishes: 0, until both tickers have passed.
  - Proposal: trigger a CVE pass, then a sync, at run end.
- **M3: the built-in pack misses the lab's IoT printer.**
  - `raven-printer-title` only matches vendor names in `<title>` (HP, Brother, …).
  - Repro: Run 1; 172.31.0.22 (`Server: LabPrinter/1.0`, `X-Device-Type: printer`, title `RAVEN Lab Printer Status`) gets no technology or finding.
  - Proposal: add generic printer/IoT signatures (`X-Device-Type`, `Server: *Printer*`, "printer status" titles).
- **M4: import runs pollute the dashboard and Changes.**
  - A results import creates a completed run of the profile, and the dashboard diffs the latest two runs.
  - Repro: import an exported services CSV. The dashboard shows "10 changed" (`title: RAVEN WordPress Lab → —` …) and the offline host as "new".
  - Proposal: exclude `stats.source = import` runs from the default "latest two runs" diff, or merge import data without blanking HTTP fields.
- **M5: re-importing an export writes user overrides into scan-owned columns.**
  - The services export writes the effective (overridden) product, and the import stores it as scan data.
  - Repro: override the product on 172.31.0.19 → export services CSV → import it. `services.scan.product` becomes `nginx (CBI admin portal)`.
  - Proposal: export the scan values plus the overrides separately, or skip overridden fields on import.

### Minor

- **m1: default ports collide with a dev stack on the same machine.**
  - `RAVEN_DOJO_PUBLIC_URL` must be changed by hand together with `DD_PORT`. `.env.example` sets it to `http://localhost:8080`, which overrides the compose fallback `http://localhost:${DD_PORT}`.
  - Proposal: leave it empty in `.env.example` and fix its comment.
- **m2: the lab subnet can't be moved.**
  - `172.30.0.x` is hardcoded in `compose.lab.yml`, `lab/targets.txt`, `lab/fixtures/certs.go`, `lab/wordpress/apache2-lab-bootstrap` and `lab/tomcat/Dockerfile`, and `raven_lab` is a fixed network name.
  - A second lab copy needs edits to all five files.
- **m3: `docker compose up` prints two warnings, `ports[].mode: host is only honored by the Swarm routing mesh`.** They come from the upstream Dojo nginx port syntax; harmless but noisy.
- **m4: the host technology list keeps every version ever seen.**
  - Repro: Run 2 after the nginx upgrade; 172.31.0.19 shows `Nginx:1.30.7` and `Nginx:1.31.9`.
- **m5: nmap's generic "Golang net/http server" match yields CPE `protocol_labs:go-ipfs`.** This is a wrong CPE, though harmless here (0 CVEs).
- **m6: the host page shows the TLS certificate as a raw JSON string** instead of subject, issuer, validity and the expired/self-signed flags.
- **m7: an expired or self-signed certificate produces no finding.** The profile tag `ssl` exists, but the built-in pack has no TLS template, and httpx's `expired`/`self_signed` flags are not turned into findings.
- **m8: an imported export revives offline hosts.** The services export includes the services of a host that has since gone offline, as `open`, so re-importing it sets the host back to `active`, `miss_count=0`.
- **m9: the Findings page's Source filter offers nmap/nuclei/raven but not httpx**, although httpx findings exist.
- **m10: the dashboard lists an import as "Last run #4 · 3 ms · 15 of 15 hosts up".**

## Dojo objects created

Everything was created in this pass's own DefectDojo, in its own compose project `raven-q1`. It was removed with `docker compose -p raven-q1 down -v` at the end. Nothing was created in the shared dev Dojo (:18080).
