# Local test lab

Run `make lab-up` from the repository root to build the fixtures and wait for their health checks. Run `make lab-down` to stop the lab. WordPress, Joomla and their databases keep their data across restarts.

The fixtures run on `raven_lab`, an internal Docker bridge with subnet `172.30.0.0/24` and zero published ports. Use this lab as the only target for development scans. The fixture IPs are in `172.30.0.16/28`, away from the bridge gateway (`172.30.0.1`) and the dynamic addresses (`172.30.0.128/25`) used by attached scanners. Start the lab before running any scan.

## Targets and expected observations

Paste or upload [`lab/targets.txt`](../lab/targets.txt) in Targets. Use `172.30.0.16/28` as the profile's include scope. The default profile covers TCP ports `22,80,443,3306,8080`. Include those ports when using a custom profile and keep the configured scan rate limits in effect.

| Address | TCP port | Service | Expected evidence or finding |
| --- | ---: | --- | --- |
| `172.30.0.17` | 80 | WordPress | WordPress generator and `wp-content` resources on `/`, REST API `Link` header |
| `172.30.0.18` | 80 | Joomla | Joomla generator, `RAVEN Joomla Lab` front page and session cookie |
| `172.30.0.19` | 80 | nginx | `Server: nginx`, HTTP 200 and `X-Lab-Panel: admin` at `/admin` |
| `172.30.0.20` | 80 | Staging app | `X-Environment: staging` on `/` |
| `172.30.0.21` | 8080 | Tomcat | Apache Tomcat welcome page, HTTP 401 with a Tomcat Manager authentication challenge at `/manager/html` |
| `172.30.0.22` | 80 | Simulated printer | `Server: LabPrinter/1.0`, `X-Device-Type: printer`, printer status title |
| `172.30.0.23` | 443 | Self-signed TLS | Self-issued certificate for `tls-selfsigned.raven.lab` with the service IP as SAN and a current validity window |
| `172.30.0.24` | 443 | Expired TLS | Self-issued certificate for `tls-expired.raven.lab` with the service IP as SAN and expiry on 2020-01-01 UTC |
| `172.30.0.25` | 80 | Simulated Apache | `Server: Apache/2.4.49` for offline CVE matching |
| `172.30.0.26` | 22 | Simulated SSH | `SSH-2.0-OpenSSH_7.4` for offline CVE matching |
| `172.30.0.27` | 80 | Flapping host | `X-Lab-Host: flap` when on, missing host and service when off |
| `172.30.0.28` | 3306 | WordPress database | MariaDB service banner |
| `172.30.0.29` | 3306 | Joomla database | MariaDB service banner |

The Apache and SSH samples are Go fixtures that announce versions for fingerprinting. The CMS databases use disposable, lab-only credentials. CMS administrator passwords and the two TLS private keys are generated automatically.

## Connect RAVEN

**Docker Compose.** Start the lab first, then add the optional network attachment when starting RAVEN. The override keeps RAVEN on its deployment network for Postgres and DefectDojo.

```sh
test -f .env || scripts/gen-env.sh
docker compose -f compose.yml -f lab/raven.compose.yml up -d --build
```

Before `make lab-down`, detach the running RAVEN container from the lab bridge.

```sh
docker network disconnect raven_lab "$(docker compose ps -q raven)"
```

**`make dev` on native Linux.** With a local, rootful Docker Engine, the host reaches the fixture IPs directly through the Docker bridge. `ip route get 172.30.0.20` should show the Docker bridge and `curl --noproxy '*' -I http://172.30.0.20/` should return `X-Environment: staging`. Start `make dev` with the scanner binaries on `PATH` and raw socket access for nmap SYN scans. Use the Compose attachment on Docker Desktop or with a remote or rootless engine, where the host may lack a direct route to the bridge.

## Toggle the flapping host

Take a baseline scan with the host on. Turn it off before a subsequent scan to produce a miss. Use the profile's miss threshold to determine how many consecutive misses mark the host offline. Turn it back on to verify that it reappears at the same address.

```sh
scripts/lab-flap.sh off
scripts/lab-flap.sh on
scripts/lab-flap.sh toggle
```

## Verify from inside the lab

```sh
docker compose -f compose.lab.yml ps
docker build -t raven-lab-tools:local lab/tools
docker run --rm --network raven_lab raven-lab-tools:local curl -skI http://172.30.0.19/admin
docker run --rm --network raven_lab raven-lab-tools:local nc -w 2 172.30.0.26 22
docker run --rm --network raven_lab raven-lab-tools:local nmap -n -sS -sV \
  --max-rate 100 -p 22,80,443,3306,8080 172.30.0.16/28
```

## Aggressive stage: `nuclei_active`

Reproduce the `nuclei_active` lab test against the three web fixtures (`172.30.0.17` WordPress, `172.30.0.21` Tomcat, `172.30.0.25` simulated Apache 2.4.49) on `raven_lab` only:

1. Start the lab (`make lab-up`) and run the RAVEN image attached to `raven_lab` (and the shared Postgres/DefectDojo network).
2. As `admin`, create an aggressive profile with ports `80,8080`, `nuclei_rate: 150`, and stages `["nmap", "httpx", "nuclei", "nuclei_active"]`.
3. Add profile-level `include` scope entries for `172.30.0.17/32`, `172.30.0.21/32`, and `172.30.0.25/32`, and add those three IPs as targets.
4. Start the run with explicit confirmation (`POST /api/runs` with `{"profile_id": <id>, "confirm_aggressive": true}`).
5. Verify:
   - the run finishes with `status: "done"`, `aggressive: true`, and `stats.nuclei_active_errors: 0`;
   - an encrypted artifact with `scanner = 'nuclei_active'` is stored in `artifacts`;
   - DefectDojo creates a separate `RAVEN: nuclei_active` Test (scan type `Nuclei Scan`) per responding IP alongside `RAVEN: nuclei`, containing findings such as `WordPress REST API User Enumeration` (`172.30.0.17`) and `Tomcat Stack Traces Enabled` (`172.30.0.21`);
   - after Dojo sync, `/api/findings?scanner=nuclei_active` and the Findings UI show those findings with source `nuclei_active`.

## WPScan

The `wpscan` aggressive stage enumerates WordPress core, plugins, themes, config backups, database exports and passive users without password attacks, login attempts or an external API token (`--no-update`, offline metadata DB baked into the RAVEN image). It runs only on live HTTP(S) URLs of the batch where `httpx` or `nuclei` detected WordPress.

To reproduce against the lab:

1. Start the lab (`make lab-up`) and attach RAVEN to `raven_lab`.
2. Add `172.30.0.17` (WordPress) and `172.30.0.18` (Joomla) to Targets.
3. As an `admin` user (`scan:aggressive`), create an aggressive profile with stages `["nmap","httpx","nuclei","wpscan"]`, ports `80`, and include scope `172.30.0.17/32` and `172.30.0.18/32`.
4. Start a run with `"confirm_aggressive": true` (`POST /api/runs`).
5. Verify:
   - Run stats show `"wpscan": "ok"`, `"wpscan_urls": 1`, `"wpscan_errors": 0`.
   - `artifacts` contains a `wpscan` artifact covering only `172.30.0.17`; `172.30.0.18` (Joomla) is skipped.
   - DefectDojo creates a `"RAVEN: wpscan"` Test (`Wpscan` scan type) under Asset `172.30.0.17` with the WordPress interesting findings (and no Wpscan Test on `172.30.0.18`).
   - After sync, the Findings page lists those findings with scanner `wpscan`.
   - Detected WordPress core/component versions are merged into `http_observations` (`wordpress:wordpress:<version>`) for offline CVE matching.

## ZAP (aggressive)

Start the optional `zap` service under the `aggressive` compose profile and attach both `raven` and `zap` to `raven_lab`. Both `zap-internal` and `raven_lab` are internal Docker bridges (`internal: true`), so ZAP can reach only `raven` and the lab targets with no internet egress and no published ports.

```sh
test -f .env || scripts/gen-env.sh
RAVEN_ZAP_URL=http://zap:8080 docker compose -f compose.yml -f lab/raven.compose.yml --profile aggressive up -d --build
```

Create an admin-only aggressive profile scoped strictly to `172.30.0.19/32` (nginx `/admin`) and `172.30.0.20/32` (staging app) with stages `nmap, httpx, nuclei, zap`, then start a run with explicit confirmation (`confirm_aggressive: true`). Without `RAVEN_ZAP_URL`, the `zap` stage stays "Not available".

Before `make lab-down`, detach both `raven` and `zap` from `raven_lab` (or stop the `aggressive` profile first):

```sh
docker compose -f compose.yml -f lab/raven.compose.yml --profile aggressive stop zap
```

## Nikto (aggressive stage)

The `nikto` stage is an admin-only aggressive stage (`scan:aggressive`) that runs Nikto 2.6.1 against httpx-confirmed literal-IP HTTP(S) origins with `-Tuning 123be`, `-Pause` derived from the profile web rate, `-maxtime 300s`, `-timeout 10`, `-Format json`, `-nointeractive`, `-nocheck`, `-ask no`, and `-nolookup` (no credential tests, no evasion/mutation, no update checks).

To reproduce the lab test against the nginx `/admin`, staging, and Tomcat fixtures (`172.30.0.19`, `172.30.0.20`, `172.30.0.21`) from a RAVEN container attached to `raven_lab`:

1. Log in as an `admin` user and add `172.30.0.19`, `172.30.0.20`, and `172.30.0.21` in **Targets**.
2. Create an aggressive profile (e.g. `ag3-nikto-lab`) with ports `80,8080`, stages `nmap`, `httpx`, `nuclei`, `nikto`, and include scope entries `172.30.0.19/32`, `172.30.0.20/32`, `172.30.0.21/32`.
3. Start a run with explicit confirmation (`confirm_aggressive: true`).
4. Verify:
   - `runs.stats` records `nikto_urls: 3` and `nikto_errors: 0`, and `artifacts` contains an encrypted `scanner = 'nikto'` JSON report.
   - DefectDojo creates a `"RAVEN: nikto"` (`Nikto Scan`) Test per responding IP under engagement `RAVEN: <profile>` with tagged findings (`raven`).
   - **Findings** (filtered by `scanner=nikto`) displays the synced Nikto findings.
