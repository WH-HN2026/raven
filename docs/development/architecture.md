# RAVEN — Architecture

RAVEN (Recon of Assets, Versions, Exposures & Networks) is an attack-surface-intelligence web app that runs safe, recurring discovery scans of large networks (10k+ IPs) for AGH. It fingerprints services and web technologies, tracks changes over time, and uses **DefectDojo** as its deduplication and finding-lifecycle engine.

The brief and the organizers' notes are in [`challenge.md`](challenge.md), and the task breakdown is in [`roadmap.md`](roadmap.md). **This is a hackathon prototype: when in doubt, choose the simpler option.**

## 1. Decisions (settled; don't re-litigate)

| # | Decision |
|---|---|
| D1 | **Web-only.** No CLI. Every "push" action (target entry, CSV/JSON import, starting scans, schedules, signatures) is done in the web UI. |
| D2 | **Go backend in one binary, `raven`.** It contains the HTTP API, the embedded SPA, the scheduler, and the scan workers (goroutines plus a Postgres-backed job queue). |
| D3 | **React SPA** (Vite + TypeScript), built and embedded into the Go binary with `embed`. |
| D4 | **DefectDojo: newest only (3.5.x), API v2, token auth.** One service-account token. Dojo is the dedup and lifecycle engine. RBAC is enforced **only in our app**, because OSS Dojo 3.x has no real roles. |
| D5 | **Host identity = IP address. One Dojo Asset (Product) per IP.** Hostnames are attributes of the IP. |
| D6 | **Scanners: nmap → httpx → nuclei**, each behind a `Scanner` interface. nmap finds hosts and services, httpx collects the HTTP facts (title, status, headers, cookies, TLS, redirects, favicon hash, technologies), and nuclei runs detection templates and our signatures. Results reach Dojo through Dojo's **native parsers** ("Nmap Scan", "httpx Scan", "Nuclei Scan"). Nessus is supported by **importing `.nessus` files** (Dojo's "Tenable Scan" parser), not by running it. The stages a run uses come from its profile's workflow (§3.11); the extra aggressive stages (active nuclei, nikto, wpscan, ZAP) exist only behind the opt-in **Aggressive** preset, never by default (§9). |
| D7 | **Custom signatures = nuclei templates**, restricted to a safe subset by our validator. |
| D8 | **Encryption at rest = Postgres-native `pgcrypto`** on sensitive columns of our DB. Dojo's own DB is stock Postgres 18 and is not encrypted; the docs say so. |
| D9 | **Schedules come from two sources:** our UI, and Dojo Engagements planned ahead (polled and imported into our schedule table). |
| D10 | **MCP server is the last feature.** It is a thin layer over the same service functions and RBAC. |
| D11 | **Vulnerability detection = fingerprints → offline CVE matching + safe signatures.** No active vulnerability checks in the default workflow; only the opt-in Aggressive preset (§9) adds them. CPE + version from nmap/httpx/nuclei is matched against a CVE dataset committed to the repo (§11). |

## 2. System overview

```
                         Browser (React SPA, AGH theme)
                                    │  JSON / session cookie
┌───────────────────────────────────▼─────────────────────────────────────┐
│ raven  (single Go binary)                                                  │
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

Runtime: Docker Compose runs `raven`, `raven-db` (Postgres 18 with pgcrypto) and the stock DefectDojo stack. See §10 for deployment.

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
   - `reimport-scan` the nmap XML, httpx JSON and nuclei JSONL filtered to this IP (one Test per scanner), with `close_old_findings=true`, only for the stages that ran in this run (§3.11);
   - Dojo dedups and marks findings new/closed/reactivated.
8. **Shadow IT / lifecycle.**
   - IP never seen before → the Asset is created with an **INFO finding "New device found"**.
   - IP that didn't respond → **not reimported**; its `miss_count` goes up by one.
   - `miss_count` reaches the profile's threshold (default 3) → push an INFO finding "Host offline" and mark the host `inactive`.
   - A host that responds again resets its counter, and Dojo reactivates its findings on the next reimport.
9. **Unstable hosts.** IPs that were up in the previous run but are down now are re-probed **once more at the end of the run**, before they count as a miss.
10. **Time window.** A batch job runs with `ctx` deadline = window end. On deadline the scanner processes are killed, the batch is set back to `pending`, and the run becomes `suspended`. The next window resumes from the remaining batches of the same run.

### 3.11 Workflows (stages per profile)

Steps 3–5 above are the **Default** workflow. A workflow is a property of a profile: `profiles.stages text[]`, validated against a **stage registry** in Go (`internal/pipeline`). Each stage is one scanner.

| Stage | Needs | Input | Dojo scan type (own per-IP Test) | Set |
|---|---|---|---|---|
| `nmap` | — (always on) | the run's targets | "Nmap Scan" | Default |
| `httpx` | `nmap` | open HTTP(S) ports from nmap | "httpx Scan" | Default |
| `nuclei` | `httpx` | URLs httpx confirmed alive | "Nuclei Scan" | Default |
| `nuclei_active` | `httpx` | URLs httpx confirmed alive | "Nuclei Scan", separate Test title from `nuclei` | aggressive |
| `nikto` | `httpx` | URLs httpx confirmed alive | "Nikto Scan" | aggressive |
| `wpscan` | `httpx` | only URLs where httpx/nuclei detected WordPress | "Wpscan" | aggressive |
| `zap` | `httpx` | URLs httpx confirmed alive | "ZAP Scan" | aggressive |

- **Validation is server-side.** Saving a profile whose stage set has a stage without its dependency → `400`. `nmap` can't be removed.
- **Presets only fill the toggles.** **Default** = `nmap, httpx, nuclei`: existing profiles migrate to it, and it is the default for new profiles. **Aggressive** = Default + `nuclei_active, nikto, wpscan, zap`. Users may switch stages off (e.g. `nmap → httpx`, or plain `nmap`). A profile that has any aggressive stage is an **aggressive profile**, with the gating in §9. The seeded profiles are **Default** (Default preset) and **Aggressive** (Default + `nuclei_active, nikto, wpscan`; `zap` is off in the profile: the ZAP service runs, admins add the `zap` stage in the workflow builder). At run start, stages that aren't available (e.g. `zap` without `RAVEN_ZAP_URL`) are dropped from the run with a run warning.
- **Execution.** The pipeline runs only the enabled stages, in registry order. Each stage gets input only from stages that ran in this run.
- **Dojo (same spirit as step 8).** A stage that didn't run in a run gets **no reimport** of its tool's Test, because `close_old_findings` would close all of that tool's findings. Each run records the stages that actually ran (`runs.stages`). Changes (C1) compares only the stages both runs share.
- **Deployment.** nikto and wpscan are pinned in `deploy/Dockerfile`. ZAP is a separate compose service, always started, driven over its API on the internal network (`RAVEN_ZAP_URL=http://zap:8080`; set it empty to disable the `zap` stage). Its image is large, so it is not in our image (§10).

## 4. DefectDojo mapping

| Dojo object | Our meaning | Notes |
|---|---|---|
| Organization (Product_Type) | `RAVEN` (one, configurable) | created on startup if missing |
| Asset (Product) | one IP, name = the IP | tags: `raven`, `host:<hostname>`, user tags; description = user notes |
| Engagement (per Asset) | `RAVEN: <profile name>`, type CI/CD | one long-lived engagement per (IP, profile) |
| Test | one per (IP, profile, scanner) | reimported every run → Dojo's diff |
| Finding | Dojo native parser output + our INFO findings | our INFO findings use Generic Findings Import with a stable `unique_id_from_tool` |
| Location (URL) | `tcp://ip:port`, `https://host:port/path` | produced by the native parsers |
| Asset `RAVEN Planning` + its Engagements | **planned scans** | engagements tagged `raven-profile:<name>`; their `target_start`/`target_end` become a schedule window |

**Planned engagements (D9).**
- Every 5 min the poller lists engagements of the `RAVEN Planning` asset that have status `Not Started`.
- For each one it upserts a `schedules` row (`source='dojo'`, `dojo_engagement_id`), using the tagged profile and the window from `target_start`–`target_end`.
- It sets the engagement status to `In Progress` when the run starts and `Completed` when it finishes.

**Pull / read-model.** Every 5 min `dojo sync` pages through `/api/v2/findings/?tags=raven` (plus Assets) and upserts them into `dojo_findings` / `dojo_assets`. A full resync is fine at lab scale. A run's last push job (a `dojo_push` / `dojo_host_offline` job whose final outcome finds the run finished and none of its push jobs still waiting in River) also triggers one extra C3 CVE pass, which then triggers one extra sync, so findings show up seconds after a run (D7). The triggers coalesce: overlapping run ends cause at most one extra pass each; the 5-min ticker stays as the fallback. The dashboard reads only our DB and never calls Dojo per request.

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
         miss_threshold, target_batch_seconds, enabled,
         stages text[])                                                -- workflow, §3.11 (WF1)
schedules(id, profile_id, source ui|dojo, dojo_engagement_id NULL,
          cron NULL, window_start, window_end, timezone, enabled)
runs(id, profile_id, schedule_id, status pending|running|suspended|done|failed,
     started_at, finished_at, hosts_total, hosts_up, stats jsonb,
     stages text[])                                                    -- stages that actually ran (WF1)
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
run_observations(run_id, ip, port NULL, up bool, observed_at,          -- diff + time-of-day
                 nuclei_matches jsonb, nuclei_evidence_enc)
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
  - `raven_enc(text) → bytea` = `pgp_sym_encrypt(t, current_setting('raven.enc_key'))`
  - `raven_dec(bytea) → text`
- The key comes from `RAVEN_ENCRYPTION_KEY`. It is set on every pooled connection in pgx `AfterConnect` via `set_config('raven.enc_key', $1, false)`.
- Encrypted columns end in `_enc` and are `bytea`. Queries call `raven_enc(@x)` / `raven_dec(col)`.
- Keep IPs, ports and other filter/join keys **in plaintext**: they are identifiers, not secrets.
- Statement logging must stay off on `raven-db`.

### 5.1 Encryption at rest: what, how, and what not (P4 audit)

**Threat model.** A copy of the `raven-db` volume, a `pg_dump`, or a DB backup leaks without the `.env`. Then the content scanners pulled off the network (banners, HTTP headers and cookies, TLS certs, raw tool output) and the operators' free-text notes stay unreadable. Network facts (which IP has which port open, running which product) stay readable: they are needed for filtering, joins and diffs, and the jury needs them in Dojo anyway. A live attacker who has the app's env or a pooled connection can decrypt; that is out of scope.

**Mechanism.** pgcrypto `pgp_sym_encrypt` (OpenPGP symmetric, AES-128, salted S2K, random salt and IV per value, so equal plaintexts give different ciphertexts) wrapped as `raven_enc(text) → bytea` and `raven_dec(bytea) → text` (baseline migration). The key lives only in the session GUC `raven.enc_key`, which `internal/db.Open` sets in pgx `AfterConnect` with a bound parameter (`set_config('raven.enc_key', $1, false)`), so it never appears in statement text. A connection without the key fails both in `raven_enc` and `raven_dec` (`current_setting` raises); the integration test checks both.

**Key lifecycle.**
- `scripts/gen-env.sh` generates `RAVEN_ENCRYPTION_KEY` (32 random bytes, base64url) into `.env`, which is gitignored; it refuses to overwrite an existing `.env` without `-f`. Dev worktrees get one from `scripts/wt-env.sh` in `.env.local`.
- `internal/config` refuses to start with a key shorter than 32 characters. `compose.yml` passes it to the `raven` container only (`${RAVEN_ENCRYPTION_KEY:?…}`), not to `raven-db`.
- **Losing the key = losing every `_enc` value** (notes, banners, headers, cookies, certs, artifacts). There is no escrow and no recovery. Back up `.env` together with the DB volume, but store them separately.
- **No rotation in the prototype.** Changing the key makes existing ciphertext unreadable (`raven_dec` errors with "Wrong key or corrupt data"). Rotation would be `UPDATE t SET c = pgp_sym_encrypt(pgp_sym_decrypt(c, old), new)` per column in one transaction; not implemented.

**Rules that keep it true (enforced by tests).**
- A column whose name looks sensitive (`note(s)`, `banner`, `header(s)`, `cookie(s)`, `cert`, `content`, `body`, `password`, `token`, `secret`, `key`) must end in `_enc` and be `bytea`, unless it is in the documented allowlist below. `internal/db/encryption_test.go` parses every migration and fails otherwise.
- `internal/db/encryption_integration_test.go` writes a marker into every `_enc` column (banner and artifact through the real `pipeline.Ingest`; notes, HTTP observations and nuclei evidence through the generated queries the host edit and the httpx/nuclei ingest call), reads the raw bytes, asserts the marker is absent and `raven_dec` returns it, and that a connection without the key can neither decrypt nor encrypt. It also fails when the schema gains an `_enc` column the test doesn't cover.
- `audit_log.diff` is plaintext jsonb, so `audit.Log` redacts the values of sensitive keys (`notes`, `banner`, `headers`, `cookies`, `tls_cert`, `cert`, `content`, `password`, `token`, `secret`, `key`, `*_enc`, and `*_<one of those>`) to `"[redacted]"`. Boolean values are kept (`"password_reset": true`). Callers should still log only that a field changed, never its value.
- Decrypted values are never passed to `slog`. As of P4 no log call carries a banner, header, note, artifact or credential: logs carry IDs, IPs, counts and wrapped errors.
- `raven-db` runs with `log_statement=none` and `log_min_duration_statement=-1` (`compose.yml`). Statements use bind parameters, so even error logging (`log_min_error_statement`, default `error`) shows `$n`, not plaintext. `log_parameter_max_length_on_error` stays at its default 0.

**Column audit** (all migrations as of P4; S = sensitive content, I = identifier or fingerprint used for filtering, joins or diffs, M = metadata or counters).

| Table.column | Class | Stored as | Why |
|---|---|---|---|
| `hosts.notes_enc` | S | `_enc` | operator free text |
| `services.banner_enc` | S | `_enc` | raw service banner, can carry internal names and versions beyond the fingerprint |
| `http_observations.headers_enc`, `cookies_enc`, `tls_cert_enc` | S | `_enc` | response headers, session cookies, certificate subject/SANs |
| `artifacts.content_enc` | S | `_enc` | raw nmap/nuclei/httpx output, superset of all of the above |
| `run_observations.nuclei_evidence_enc` | S | `_enc` | nuclei extraction results per open service (S4): can carry tokens, versions, internal names |
| `run_observations.nuclei_matches` | I | plaintext | template id/name/severity/tags, matcher, URL without query, CPE/version: diffed and pushed to Dojo |
| `users.password_hash` | S | plaintext (allowlisted) | argon2id hash; encrypting a hash adds nothing |
| `sessions.token_hash`, `api_tokens.token_hash` | S | plaintext (allowlisted) | SHA-256 of a random token; it's the lookup key |
| `targets.note`, `scope_entries.note` | I | plaintext (allowlisted) | short operator label from the import file, shown in lists like a tag; not meant for secrets |
| `hosts.ip`, `hostnames`, `services.ip/port/proto`, `run_observations.*`, `batches.ips`, `scope_entries.value`, `targets.value`, `dojo_*.ip` | I | plaintext | filter and join keys (architecture §5) |
| `services.name/product/version/cpe`, `http_observations.url/status/title/technologies/favicon_hash`, `run_observations.service_fp` | I | plaintext | fingerprint: filtered, diffed (C1), CPE-matched (§11) |
| `http_observations.redirects` | I | plaintext | redirect chain URLs (S7 drops userinfo, keeps query strings); see follow-up A4 below |
| `hosts.owner/criticality/user_tags`, `*.overrides` | I | plaintext | filter fields and corrections of scan-owned fingerprint fields; notes are not in `overrides` |
| `runs.stats`, `batches.error`, `batches.*` counters | M | plaintext | counters; `error` is a wrapped Go error (nmap's last stderr line, Dojo status), not scan content |
| `profiles.*`, `schedules.*`, `signatures.*` | M | plaintext | configuration; signature templates are not secret |
| `dojo_assets.*`, `dojo_findings.*` | I | plaintext | mirror of Dojo, which is plaintext anyway (D8) |
| `audit_log.diff` | M | plaintext, redacted | see the redaction rule above |
| `users.username`, `audit_log` login-failure `username` | I | plaintext | account names |
| `river_job.args` | M | plaintext (River) | job args hold IDs, IPs, host names, scanner names only (`pipeline.BatchArgs`, `dojo.PushArgs`) |

**Not encrypted, by decision.**
- **DefectDojo's DB (D8).** The raw nmap XML (with banners and `http-headers`/`ssl-cert` script output) is re-imported into Dojo per Asset, and Dojo stores findings, endpoints and the uploaded files in its own stock Postgres and media volume, all plaintext. Protect the Dojo host as you would protect the data; Dojo-side encryption is out of scope.
- **Identifiers and fingerprints**: see the table. Encrypting them would break indexes, filters and diffs, and they are mirrored to Dojo in plaintext anyway.
- **Transport** inside the compose network (`sslmode=disable` to `raven-db`) is plain: both containers sit on one private Docker network.

**Known follow-ups (Person A's code, not changed in P4).**
- A1 `internal/dojo/http.go:200-208`: `HTTPError.Body` keeps up to 512 bytes of Dojo's response. It ends up in logs (`pushjob.go:145,158`) and in `river_job.errors`. A Dojo parser error could echo uploaded scan content. Suggested fix: keep the status and Dojo's `message`/`detail` field only, or cut the body to about 120 chars.
- A2 `internal/scanner/nmap/nmap.go:64`: the last stderr line goes into `batches.error` (plaintext). Today that's nmap's own diagnostics, so it's acceptable. Keep it that way: never put stdout or the XML into errors.
- A3 S7 (httpx) is done right: `internal/db/queries/http_observations.sql` writes `headers_enc`, `cookies_enc` and `tls_cert_enc` with `raven_enc`, the raw httpx JSON goes to `artifacts.content_enc`, and nothing in `internal/pipeline/http.go` or `internal/scanner/httpx` logs them. The integration test writes through this same query (`gen.InsertHTTPObservation`). Nothing to fix.
- A4 `internal/scanner/httpx/parse.go:113-123` (`appendRedirect`): it drops userinfo but keeps the query string and fragment of each redirect target, which lands in plaintext `http_observations.redirects`. Redirect URLs often carry tokens (`?code=`, `?session=`, SSO tickets). Suggested fix: also set `to.RawQuery = ""`, `to.Fragment = ""` there (the full URL stays in the encrypted artifact).

## 6. RBAC

The roles come straight from requirement 13:

| Role | Can |
|---|---|
| `admin` | everything + users, roles, API tokens, Dojo connection, global blacklist, global rate limits |
| `editor` | add / delete / modify: targets, scope, profiles, schedules, signatures, imports, start/stop scans, edit findings and hosts |
| `operator` | modify + read: edit findings and hosts (triage, notes, tags), no create/delete |
| `viewer` | read everything, export |

Permission `scan:aggressive` (**admin only**): create an aggressive profile, add aggressive stages to a profile, or change an aggressive profile (including its scope entries). Editors may still start and stop runs of an existing aggressive profile (`runs:control`).

- One file, `internal/auth/rbac.go`, defines the `Permission` constants and the `role → permissions` map.
- Each handler declares its permission with `auth.Require(perm)`, and the frontend hides what the role can't do.
- The **backend check is the source of truth**; the frontend only hides things.
- Every mutation writes to `audit_log`.

Auth: local users with argon2id passwords. Server-side sessions use an `HttpOnly; SameSite=Strict` cookie, and unsafe methods need a `X-RAVEN-CSRF` header. API tokens (hashed) exist for MCP.

## 7. Backend layout

```
cmd/raven/main.go              wires config → db → services → http server + workers
internal/config/             env config (RAVEN_*)
internal/db/                 pool (with enc key), migrations/, queries/, gen/ (sqlc)
internal/auth/               users, sessions, rbac.go, middleware
internal/httpapi/            router.go (mounts each area), one file per area: targets.go, runs.go …
internal/targets/            parse manual/CSV/JSON, CIDR expand, domain resolve, scope filtering
internal/scanner/            Scanner interface + types
internal/scanner/nmap/       command builder, XML parser → observations
internal/scanner/httpx/      command builder, JSON parser → http_observations
internal/scanner/nuclei/     command builder, JSONL parser, template policy (default + aggressive sets)
internal/scanner/nikto/      (aggressive) command builder, flag allowlist, parser
internal/scanner/wpscan/     (aggressive) command builder, flag allowlist, parser
internal/scanner/zap/        (aggressive) ZAP API client: spider + capped active scan
internal/signatures/         safe-subset validator for nuclei templates
internal/pipeline/           run orchestration: stage registry (§3.11), batching, jobs, ingest, miss counting, re-probe
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

The rules come in three layers. **Always** holds for every workflow. **Default workflow** holds for the Default stages (`nmap`, `httpx`, `nuclei`), in every profile. **Aggressive preset** lists what an aggressive profile may do *in addition*; it never relaxes the other two layers.

### Always (every workflow)

- **Scope:** only in-scope targets of the run's profile are scanned: no target is scanned unless it matches some include entry of that profile. The global blacklist (exclude list) is applied after every expansion step (CIDR, domain resolution, vhost URLs), and exclusions always win.
- **Lab only from dev machines:** Scan targets (dev machines): only (1) our lab (`make lab-up`, raven_lab 172.30.0.0/24), (2) the reference stacks from lab/reference/, reached at the Docker host's bridge address (172.17.0.1), as target 172.17.0.1 with the Default (or Aggressive) profile, or (3) the organizers' lab at the event. Never the internet, other hosts on the LAN, the host's LAN address, or AGH ranges.
- **Reference lab files are verbatim:** never edit anything in `lab/reference/` (`make lab-verify` checks `SHA256SUMS`). Adapt RAVEN around them (ports, profiles, networks), never the other way round.
- **Intensity:** every tool runs with a rate limit and a time cap (the batch `ctx` deadline plus a per-tool limit). Cancelling `ctx` kills the process.
- **Credentials:** no login attempts and no credential or password brute-forcing anywhere (wpscan password attack off, nikto credential tests off).
- **No DoS:** no DoS templates, DoS tuning or flood options.
- **No OAST:** no interactsh or other out-of-band callbacks.
- **No external APIs:** CVE matching is offline only: product/version are matched to CPEs locally (§11). wpscan runs without an API token. Never send our data to external APIs.
- **Flags:** scanner flags come only from the per-tool allowlists in `internal/scanner/*`.

### Default workflow

- **nmap:**
  - no `-A`, no `-sC`, no `--script` outside the allowlist in `internal/scanner/nmap`;
  - `--max-rate` is always set;
  - only the profile's allowed ports.
- **httpx:** one GET per URL (no path brute-forcing, no `-path` lists), rate limit always set.
- **nuclei:** only allowlisted tags plus our signatures; the exclusion flags in §3 step 5 are always applied (`intrusive`, `dos`, `fuzz`, … tags; `code`, `headless`, `javascript` types); `-no-interactsh`; a rate limit is always set.
- **Signatures:** the validator rejects any template that has
  - a method other than GET/HEAD;
  - a request body, payloads/attack/fuzzing;
  - `code`/`headless`/`javascript`/`network` write steps;
  - DSL that could make extra requests;
  - interactsh.
- **Paths:** paths like `/admin`, `/login` and `/version` may be fetched with GET only.

### Aggressive preset (opt-in, never default)

Allowed **in addition**, only in an aggressive profile (§3.11), and still under every "Always" rule:

- **`nuclei_active`:** official templates tagged `intrusive`/`fuzz`, still from a pinned, allowlisted aggressive set; `dos` (and the credential tags) stay excluded; `-no-interactsh`; rate limit set.
- **`nikto`:** tuning limited to the information/misconfiguration categories: no injection, no DoS, no credential tests; rate and time caps set.
- **`wpscan`:** version, plugin and theme enumeration on WordPress URLs only, without passwords and without an API token. The versions it finds feed offline CVE matching (§11).
- **`zap`:** spider + active scan with a capped scan policy and a per-URL time limit.

Gating:

- **Admins only** (`scan:aggressive`, §6) can save a profile with aggressive stages or change an aggressive profile. Editors may still start runs of an existing aggressive profile.
- Every create, change and start of an aggressive profile or run writes `audit_log`.
- The profile's own scope entries are the aggressive scope; there is no separate list.
- The seeded profiles are **Default** (Default workflow) and **Aggressive** (Default + `nuclei_active, nikto, wpscan`; `zap` off by default in the profile, added by an admin in the workflow builder; never the default; not scheduled; admin-only to change). New profiles start with the Default workflow.
- Saving a profile through the API rejects unavailable stages. A stage that becomes unavailable later (e.g. `zap` in a profile, then `RAVEN_ZAP_URL` removed) is skipped at run start with a run warning, and is not in `runs.stages`.

## 10. Deployment (Docker Compose) and configuration

**Deployment is `docker compose up -d --build` from the repo root, and nothing else.** One `compose.yml` serves as both the production deployment and the dev infra: dev just starts a subset of its services.

```
compose.yml                 # the deployment: raven + raven-db + DefectDojo (via include)
deploy/dojo.compose.yml     # DefectDojo 3.5.202 services copied from its repo, images pinned
deploy/Dockerfile           # multi-stage: node (web build) → go (binary) → runtime with nmap + httpx + nuclei + templates (+ nikto, wpscan, pinned; AG3/AG4)
compose.lab.yml             # our test lab (task L1), separate network, never needed in prod
lab/reference/              # the reference lab configs, verbatim (SHA256SUMS), never needed in prod
.env.example                # every variable, with safe defaults; copied to .env
scripts/gen-env.sh          # creates .env with random secrets (encryption key, passwords, Dojo secret key)
```

| Service | Image | Port | Notes |
|---|---|---|---|
| `raven` | built from `deploy/Dockerfile` | 8000 | `cap_add: [NET_RAW, NET_ADMIN]`; on the default network and the lab network; runs migrations on start |
| `raven-db` | `postgres:18` | 5433 (dev only) | volume `raven-db-data`; `log_statement=none`; healthcheck |
| `zap` (AG5) | official ZAP image, pinned tag | none (internal only) | always started; API key required, update checks off; only on the internal `zap-internal` network; `raven` drives it over its API (`RAVEN_ZAP_URL=http://zap:8080`, empty disables the stage); attached to `raven_lab` with `lab/raven.compose.yml` to reach our lab |
| DefectDojo (`nginx`, `uwsgi`, `celeryworker`, `celerybeat`, `initializer`, `postgres`, `valkey`) | official `defectdojo/*:3.5.202` | 18080 (`DD_PORT`) | unchanged from upstream except the pinned tag and `DD_ADMIN_PASSWORD` coming from `.env` |

- **No manual Dojo token.** If `RAVEN_DOJO_TOKEN` is empty, `raven` waits for Dojo to be healthy and gets a token via `POST /api/v2/api-token-auth/` with `DD_ADMIN_USER`/`DD_ADMIN_PASSWORD`. It then creates the `RAVEN` organization and the `RAVEN Planning` asset if they're missing.
- **Startup order:** `depends_on` with `condition: service_healthy` on `raven-db` and `service_started` on `zap` (ZAP boots slowly; `raven` doesn't wait for it). The Dojo wait is a retry loop inside `raven`, because Dojo's first boot (migrations) takes minutes.
- **Dev:** `make infra-up` = `docker compose up -d raven-db nginx uwsgi celeryworker celerybeat initializer postgres valkey` (everything except `raven` and `zap`). The Go binary then runs on the host via `make dev`, with `RAVEN_ZAP_URL` empty (`scripts/wt-env.sh`): the host can't reach ZAP's internal network, so the `zap` stage is unavailable in dev.
- **Dojo host port** defaults to 18080, not 8080: the reference `modern` stack needs 8080 (and 80/81/443). `DD_TLS_PORT` stays 8443.
- **Scanning network:** by default `raven` scans from the bridge network; it is attached to `raven_lab` for our lab (see "Lab scenarios").

### Lab scenarios

Two scenarios, chosen with `make`. Only one lab stack runs at a time.

| | Ours (default, `LAB=ours`) | Reference lab (`LAB=reference`) |
|---|---|---|
| Files | `compose.lab.yml` (task L1) | their files, verbatim, in `lab/reference/` (`README.md`, `quickstart.sh`, `docker-compose-*.yml`, `traefik/`), guarded by `SHA256SUMS` + `make lab-verify` |
| Start / stop | `make lab-up` / `make lab-down` | `make lab-up LAB=reference STACK=quickstart\|custom-network\|modern\|modern-proxy\|vulnerable` (default `quickstart` = their `./quickstart.sh up`), `make lab-down LAB=reference STACK=…`, `make lab-change` (= their `./quickstart.sh change`). Make only `cd`s into `lab/reference/` and runs their own commands; for `modern-proxy`: `cp -n .env.example .env`, then `docker compose --env-file .env -f docker-compose-modern-proxy.yml up -d` (`lab/reference/.env` is gitignored) |
| Network | internal `raven_lab`, 172.30.0.0/24; `raven` is attached to it | their own networks; ports published on the Docker host (0.0.0.0) |
| What RAVEN scans | 172.30.0.0/24 | only 172.17.0.1 (target added in Targets), with the seeded **Default** (or **Aggressive**) profile |

- **Profiles:** there is no lab-specific profile. The operator adds the target `172.17.0.1` once in Targets and runs **Default** (or **Aggressive**: Default + `nuclei_active, nikto, wpscan`, no `zap` unless an admin adds it). A profile without include rules scans every target, so the run also scans every other target in the DB. Default's port list (tasks S3, V3) covers their published ports, and it also contains RAVEN's `8000` and Dojo's TLS `8443`, so a scan of 172.17.0.1 also probes RAVEN and Dojo on the host. This is accepted (no exclusions). Postgres is bound to 127.0.0.1.
- **ZAP** reaches our lab through `lab/raven.compose.yml` (attached to `raven_lab`). ZAP is only on internal networks, so it can't reach the reference stacks on 172.17.0.1: that is LB3's open issue.
- **172.17.0.1** is the `docker0` gateway (check with `docker network inspect bridge`). It is reachable from the `raven` container and from `make dev` on the host.
- **Known risks:** a host firewall may block container→host traffic to 172.17.0.1. Their stacks publish on 0.0.0.0 with default credentials, as their README warns: run them only on a machine that isn't exposed to the network.

Configuration (env, all in `.env`):

```
RAVEN_HTTP_ADDR=:8000
RAVEN_DATABASE_URL=postgres://raven:${RAVEN_DB_PASSWORD}@raven-db:5432/raven
RAVEN_ENCRYPTION_KEY=<32+ random bytes, base64>       # generated by gen-env.sh; losing it = losing encrypted data
RAVEN_DOJO_URL=http://nginx:8080
RAVEN_DOJO_TOKEN=                                      # optional; otherwise obtained with the admin credentials
DD_ADMIN_USER=admin
DD_ADMIN_PASSWORD=<generated>
RAVEN_DOJO_ORGANIZATION=RAVEN
RAVEN_ADMIN_USERNAME / RAVEN_ADMIN_PASSWORD              # bootstrap admin of our app on first start
```

## 11. Vulnerability matching (offline)

Matching fingerprints to known vulnerabilities is allowed (organizers' note 2); sending exploits is not. All matching is local.

- **Identity: CPE.**
  - Every `service`/`tech` observation carries `cpe` (vendor:product) and `version`.
  - nmap gives CPEs directly (`<cpe>` in `-sV` output).
  - httpx technology names map to CPEs through a table generated from Wappalyzer's fingerprint data.
  - nuclei tech templates carry `metadata.vendor/product`.
  - wpscan (aggressive profiles only) reports WordPress core, plugin and theme versions, matched the same way.
- **Data, committed to the repo** (`internal/cve/data/`, gzip, a few MB), regenerated by `make cve-db`. The build and runtime never call external APIs.
  - **NVD CVE 2.0** records for a curated product list (`internal/cve/products.txt`, about 50–100 vendor:product pairs we actually detect: web servers, CMSes, panels, SSH/FTP/mail servers, appliances).
  - **CISA KEV** (known exploited) and **EPSS** scores for prioritization.
  - Regenerate with `make cve-db` (generator `internal/cve/gen`; ≈10 min, as NVD allows one request per 6 s without a key; `NVD_API_KEY` speeds it up) and commit `internal/cve/data/cve.json.gz`. `products.txt` also lists the alias CPEs scanners report (e.g. nmap's `igor_sysoev:nginx` → NVD `f5:nginx`); `cve.CPEForTech` maps httpx/nmap/nuclei technology names to these CPEs.
- **Matching.** Product + version against NVD configuration ranges (`versionStart/End Including/Excluding`), with a version comparator that handles `1.2.3`, `8.9p1` and `2.4.49-r0`.
- **Confidence.**
  - `high`: an exact version from a banner/header with no distro suffix.
  - `low`: the banner shows a distro build (e.g. `OpenSSH 8.9p1 Ubuntu 3ubuntu0.10`, `Debian`, `el8`). Distros backport fixes, so these findings are capped at **Low** severity and tagged `cve:distro-build`.
- **Findings.** Dojo gets one finding for each CVE matched to a product instance (IP, port, protocol, CPE and version).
  - Example title is `CVE-2021-41773 in Apache httpd 2.4.49 (172.30.0.21:80/tcp)`.
  - Severity comes from that CVE's CVSS score, rises one level for a CISA KEV entry, and is capped at Low for distro builds.
  - `vulnerability_ids` contains the single CVE ID. `cvssv3_score`, `epss_score` and `known_exploited` describe that CVE.
  - The description records the CVE ID, instance, scores, KEV status, CPE and confidence, with a backport note for distro builds.

  Generic Findings Import reimports into the IP's "RAVEN CVE match" Test with `unique_id_from_tool = ip:port:cpe:version:proto:CVE` and `close_old_findings=true`. Reimport retains findings with the same ID and closes findings whose IDs are absent from the report. The first per-CVE reimport closes legacy aggregate findings. A version change closes findings for the old version and opens findings for any CVEs that match the new version.

  A pass runs at startup and every 5 min. It rewrites `cve_matches` from the open services, then reimports findings for every **active** IP whose push hash in `cve_push` has changed. The hash includes the report format so the change to per-CVE findings refreshes existing matches. The dashboard and `GET /api/cve-matches?ip=` read `cve_matches`, which groups CVEs by product instance.

## 12. Scale

Load-tested with `make test-scale` (`internal/scaletest`, build-tagged `scaletest`, in-process fake scanners + loopback `httptest` Dojo stub, zero outbound network traffic) across 16,384 IPs (`/18`) and 65,536 IPs (`/16`) with two runs (~30% up, 1–5 services each, ~5% changed on Run 2).

At 65,536 IPs (~20k up hosts, ~60k open services, ~250k `run_observations`, ~256 MB DB after two runs), after fixing `nmap.perIP` buffer over-allocation (7.7 GB → 93 MB peak heap on 4,096-IP adaptive batches), persisting plaintext `run_observations.service_fp` + indexes, bulk `unnest` ingests, subquery-first host pagination, and Dojo HTTP pooling/`test_types` caching:

- Run 1 (256 × 256 IPs): **25.1 s** total (83 ms plan, 24.7 s scan+ingest, 0.30 s Dojo drain).
- Run 2 (16 × 4,096 IPs via S5 adaptive batching): **20.5 s** total, **93 MB** peak heap.
- API latencies at 65k hosts: `GET /api/hosts` **1.7–81 ms** (deep page `offset=5000`: **4.5 ms**), `GET /api/changes` **309 ms**, `GET /api/dashboard` **498 ms**.

Full before/after tables and methodology are in [`scale.md`](scale.md).

## 13. Out of scope (for the hackathon)

Multi-tenant orgs inside our app, SSO/LDAP, HA/clustering, Dojo versions older than 3.5, a CLI, exploitation of any kind, active vulnerability checks outside the opt-in Aggressive preset (§9).
