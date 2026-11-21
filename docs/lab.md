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
