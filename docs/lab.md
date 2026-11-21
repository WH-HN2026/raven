# Local test lab

Run `make lab-up` from the repository root to build the fixtures and wait for their health checks. Run `make lab-down` to stop the lab. WordPress, Joomla and their databases keep their data across restarts.

The fixtures run on `asi_lab`, an internal Docker bridge with subnet `172.30.0.0/24` and zero published ports. Use this lab as the only target for development scans. The fixture IPs are in `172.30.0.16/28`, away from the bridge gateway (`172.30.0.1`) and the dynamic addresses (`172.30.0.128/25`) used by attached scanners. Start the lab before running any scan.

## Targets and expected observations

Paste or upload [`lab/targets.txt`](../lab/targets.txt) in Targets. Use `172.30.0.16/28` as the profile's include scope. The default profile covers TCP ports `22,80,443,3306,8080`. Include those ports when using a custom profile and keep the configured scan rate limits in effect.

| Address | TCP port | Service | Expected evidence or finding |
| --- | ---: | --- | --- |
| `172.30.0.17` | 80 | WordPress | WordPress generator and `wp-content` resources on `/`, REST API `Link` header |
| `172.30.0.18` | 80 | Joomla | Joomla generator, `ASI Joomla Lab` front page and session cookie |
| `172.30.0.19` | 80 | nginx | `Server: nginx`, HTTP 200 and `X-Lab-Panel: admin` at `/admin` |
| `172.30.0.20` | 80 | Staging app | `X-Environment: staging` on `/` |
| `172.30.0.21` | 8080 | Tomcat | Apache Tomcat welcome page, HTTP 401 with a Tomcat Manager authentication challenge at `/manager/html` |
| `172.30.0.22` | 80 | Simulated printer | `Server: LabPrinter/1.0`, `X-Device-Type: printer`, printer status title |
| `172.30.0.23` | 443 | Self-signed TLS | Self-issued certificate for `tls-selfsigned.asi.lab` with the service IP as SAN and a current validity window |
| `172.30.0.24` | 443 | Expired TLS | Self-issued certificate for `tls-expired.asi.lab` with the service IP as SAN and expiry on 2020-01-01 UTC |
| `172.30.0.25` | 80 | Simulated Apache | `Server: Apache/2.4.49` for offline CVE matching |
| `172.30.0.26` | 22 | Simulated SSH | `SSH-2.0-OpenSSH_7.4` for offline CVE matching |
| `172.30.0.27` | 80 | Flapping host | `X-Lab-Host: flap` when on, missing host and service when off |
| `172.30.0.28` | 3306 | WordPress database | MariaDB service banner |
| `172.30.0.29` | 3306 | Joomla database | MariaDB service banner |

The Apache and SSH samples are Go fixtures that announce versions for fingerprinting. The CMS databases use disposable, lab-only credentials. CMS administrator passwords and the two TLS private keys are generated automatically.

## Connect ASI

**Docker Compose.** Start the lab first, then add the optional network attachment when starting ASI. The override keeps ASI on its deployment network for Postgres and DefectDojo.

```sh
test -f .env || scripts/gen-env.sh
docker compose -f compose.yml -f lab/asi.compose.yml up -d --build
```

Before `make lab-down`, detach the running ASI container from the lab bridge.

```sh
docker network disconnect asi_lab "$(docker compose ps -q asi)"
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
docker build -t asi-lab-tools:local lab/tools
docker run --rm --network asi_lab asi-lab-tools:local curl -skI http://172.30.0.19/admin
docker run --rm --network asi_lab asi-lab-tools:local nc -w 2 172.30.0.26 22
docker run --rm --network asi_lab asi-lab-tools:local nmap -n -sS -sV \
  --max-rate 100 -p 22,80,443,3306,8080 172.30.0.16/28
```
