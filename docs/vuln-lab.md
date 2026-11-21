# vuln_lab: the organizers' example lab, made RAVEN-safe (Track V)

This is the design for roadmap **Track V** (V0 = this document). It turns the organizers' example lab into one isolated network that RAVEN can scan safely, adds a scale layer of thousands of real addresses, and wraps everything in one demo command. The task specs at the end are meant to be pasted into worker specs as they are.

- The organizers' files are kept **verbatim** in [`lab/vuln/organizers/`](../lab/vuln/organizers/) (README in Polish, `.env.example`, `quickstart.sh`, four `docker-compose-*.yml`, `traefik/wordpress.yml`). They are reference material: nothing runs from that folder.
- The L1 lab ([`lab.md`](lab.md), `raven_lab`, 172.30.0.0/24) stays as it is. The vuln lab **complements** it and runs **next to** it.

Facts marked *(trial)* were measured on 2026-11-21: the organizers' images were pulled and started together on a throwaway `internal: true` network (10.77.0.0/16, no published ports), probed with `curl`/`nc`/`openssl` from a container on the same network, then removed. No scanner was run.

## 1. Why the organizers' stacks can't be used as shipped

| Problem | Where | Consequence for RAVEN |
|---|---|---|
| Every service publishes ports on the **host** (`80`, `81`, `443`, `8080`, `21`, `6379`, …) and the README scans `localhost` | all four compose files, `quickstart.sh` | Scanning the host is forbidden (AGENTS.md safety, architecture §9). |
| Host port clashes: `8080` (DefectDojo), `80/443`, `8443`; `docker-compose-modern.yml` takes `80/81/443/8080/8081/6379` | modern, vulnerable | The stack and RAVEN can't run on one machine. |
| The README says "don't run all stacks together" | README | Can't show one rich network or a realistic host count. |
| `:latest` and floating tags (`wordpress:latest`, `phpmyadmin:latest`, `gitea/gitea:latest`, `nginx:alpine`, `rabbitmq:3-management`, …) | all | Fingerprints and CVE matches change from day to day, so expected results can't be written down. |
| Each stack has its own default bridges with egress | all | Lab containers could reach the internet. A scanner on such a bridge could too. |
| Nginx Proxy Manager exits at once without `/data` and `/etc/letsencrypt` volumes; WordPress ×3 and Gitea show their installers | modern, vulnerable, custom *(trial)* | The scanner would fingerprint installers instead of the products. |

## 2. Topology

### 2.1 Network

One network for all four stacks: **`raven_vlab`**, Docker bridge, `internal: true`, subnet **`10.77.0.0/16`**, gateway `10.77.0.1`, Docker's dynamic allocation limited to `ip_range: 10.77.255.0/24`.

Why `10.77.0.0/16`:
- It is **outside Docker's default address pools** (`172.17.0.0/12` in /16s and `192.168.0.0/16` in /20s), so Docker never hands it to another network by itself. `172.31.0.0/16`, suggested in the brief, is in the default pool, and the Q1 acceptance pass already used `172.31.0.0/24` for its L1 copy.
- No overlap with `raven_lab` (`172.30.0.0/24`), `raven_default`, or the Q2 fake ranges (`10.64.0.0/18`, `10.65.0.0/16`, never on the wire).
- A /16 leaves room for the core stacks and a /18 scale layer (16,384 addresses, the size the brief means by ">10k IPs") inside **one** target, because S1 expands targets up to a /16.
- Risk: a VPN or a site network that routes `10.77.0.0/16`. The bridge route is more specific and would shadow it on this machine. `make vlab-up` checks `ip route` and the existing Docker networks first, and stops with a clear message on overlap. There is no subnet override: hardcoded addresses are simpler, and m2 in [`acceptance.md`](acceptance.md) shows that a movable subnet costs edits in many files.

### 2.2 Address plan

| Block | Use | In scope |
|---|---|---|
| `10.77.0.1` | bridge gateway = **the host** | **never: global blacklist** |
| `10.77.1.0/24` | stack *modern* | yes |
| `10.77.2.0/24` | stack *modern-proxy* | yes |
| `10.77.3.0/24` | stack *vulnerable* | yes |
| `10.77.4.0/24` | stack *custom-network* | yes |
| `10.77.9.0/24` | scenario hosts that appear and disappear (shadow IT, import-only host) | yes |
| `10.77.64.0/18` | scale layer (V4): 16,384 addresses, a configurable number of them occupied | yes, scale profile only |
| `10.77.254.0/24` | RAVEN (`10.77.254.10`, static) and lab tooling with static IPs | **never: global blacklist** |
| `10.77.255.0/24` | Docker dynamic range (one-shot init containers, ad-hoc helpers) | **never: global blacklist** |

**Global blacklist for the vuln lab:** `10.77.0.1` and `10.77.254.0/23`. Each stack uses the `.10`–`.29` part of its /24, so most of every scanned /24 is **empty address space**, which tests "no host there" as well as "host there".

### 2.3 Services

One compose file, `compose.vlab.yml` (project `raven-vlab`), at the repo root next to `compose.lab.yml`. Every service has a static IP, **no `ports:`**, a pinned tag and a healthcheck. Lab credentials are the organizers' disposable values, kept in the compose file the way L1 does it, and never used by RAVEN.

| IP | Service (organizers' name) | Image, pinned | Ports (TCP) | Notes |
|---|---|---|---|---|
| 10.77.1.10 | modern `wordpress` | `wordpress:7.1.5-php8.3-apache` | 80 | WordPress 7.1.5, PHP 8.3.37, Apache 2.4.71 (Debian) *(trial)*; installed by the init job (§2.4) |
| 10.77.1.11 | modern `mariadb` | `mariadb:11.8.9` | 3306 | `11.8.9-MariaDB-ubu2404` greeting *(trial)* |
| 10.77.1.12 | modern `phpmyadmin` | `phpmyadmin:5.2.3` | 80 | `PMA_HOST=10.77.1.11` |
| 10.77.1.13 | modern `redis` | `redis:7.4.12` | 6379 | no auth, `redis_version:7.4.12` *(trial)* |
| 10.77.1.14 | modern `nginx-proxy-manager` | `jc21/nginx-proxy-manager:2.17.1` | 80, 81, 443 | needs volumes `/data` and `/etc/letsencrypt` *(trial)*; logs a harmless `EAI_AGAIN` for its IP-range fetch (no egress) |
| 10.77.2.10 | proxy `traefik` | `traefik:v3.1.7` | 80 (→ Toxiproxy → WordPress), 8080 (dashboard + API, `--api.insecure`) | dynamic config from `lab/vuln/traefik/` |
| 10.77.2.11 | proxy `toxiproxy` | `ghcr.io/shopify/toxiproxy:2.12.0` | 8474 (API), 8666 (proxy `wordpress` → 10.77.2.12:80) | the proxy is created by the init job; toxics come only from the scenario driver |
| 10.77.2.12 | proxy `wordpress` | `wordpress:7.1.5-php8.3-apache` | 80 | own DB, installed by the init job |
| 10.77.2.13 | proxy `mariadb` | `mariadb:11.8.9` | 3306 | |
| 10.77.2.14 | proxy `redis` | `redis:7.4.12-alpine` | 6379 | `--appendonly yes` as shipped |
| 10.77.3.10 | vulnerable `wordpress` | `wordpress:4.7.5-php5.6-apache` | 80 | WordPress 4.7.5, PHP 5.6.30, Apache 2.4.10 (Debian) *(trial)*; installed by the init job |
| 10.77.3.11 | vulnerable `mysql` | `mysql:5.7.44` | 3306 | greeting `5.7.44` *(trial)* |
| 10.77.3.12 | vulnerable `adminer` | `adminer:6.3.0` | 8080 | |
| 10.77.3.13 | vulnerable `ftp` | `fauria/vsftpd@sha256:6d71d7c7…c79c177` | 21, 21000–21010 (passive) | banner `220 (vsFTPd 3.0.2)` *(trial)*; `PASV_ADDRESS=10.77.3.13` |
| 10.77.3.14 | vulnerable `dvwa` | `vulnerables/web-dvwa@sha256:dae203fe…337daa7` | 80 | DVWA v1.10, Apache 2.4.25 (Debian 9), PHP 7.0.30 *(trial)*; database setup is **not** run (no POST to the app) |
| 10.77.4.10 | custom `custom-api` | `kennethreitz/httpbin@sha256:599fe5e5…96a72b` | 80 | httpbin 0.9.2, `Server: gunicorn/19.9.0` *(trial)*; the "host off/on" host of the scenarios |
| 10.77.4.11 | custom `postgres` | `postgres:16.16` | 5432 | |
| 10.77.4.12 | custom `rabbitmq` | `rabbitmq:3.13.7-management` | 5672, 15672 (+ 4369, 25672, 15692 if listening; V1 records the real list) | |
| 10.77.4.20 | custom **app host**: `gitea` + `flask-app` | `busybox:1.37` anchor; `gitea/gitea:28.4.0` and `nginx:1.20.0-alpine` share its network namespace (`network_mode: service:apphost`) | 3000 (Gitea), 22 (Gitea's OpenSSH 10.3), **8787** (nginx "flask-app") | rebuilds the organizers' quickstart: **one address** where port 8787 disappears and comes back while the others stay; `GITEA__security__INSTALL_LOCK=true` and sqlite, so Gitea shows its home page instead of the installer |
| 10.77.9.50 | *(scenario)* shadow-IT device | `httpd:2.4.49-alpine` (V1 checks the tag; fallback `httpd:2.4.49`) | 80 | **absent** at baseline; started by `vlab-scenario.sh device-new` |
| 10.77.9.51 | *(scenario)* import-only host | none | — | exists only in the V2 import sample file |
| 10.77.254.10 | RAVEN (attached) | — | — | blacklisted |
| 10.77.254.20 | `tools` (optional, compose profile `tools`) | `raven-lab-tools:local` (`lab/tools`) | — | curl/nc inside the lab for checks; blacklisted |

The digests above are abbreviated. These are the full ones for `compose.vlab.yml`: httpbin `sha256:599fe5e5073102dbb0ee3dbb65f049dab44fa9fc251f6835c9990f8fb196a72b`, DVWA `sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7`, vsftpd `sha256:6d71d7c7f1b0ab2844ec7dc7999a30aef6d758b6d8179cf5967513f87c79c177`, Toxiproxy `sha256:9378ed52a28bc50edc1350f936f518f31fa95f0d15917d6eb40b8e376d1a214e`.

Deliberate differences from the organizers' files:
- one network, one address per service, native ports instead of the remapped host ports (8085, 8088, …): every service sits on its own IP, so nothing collides;
- `flask-app` is pinned to an **old** nginx (1.20.0, CVE-2021-23017) so the "version change" scenario can upgrade it (§4);
- the modern-proxy WordPress keeps its own MariaDB and Redis, as shipped;
- the organizers' `toxiproxy-init` read toxic switches from `.env`. Here the init job only creates the proxy; the toxics are switched at run time through the Toxiproxy API by the scenario driver, so no `.env` is needed and a scan can be repeated with and without them without restarting anything.

### 2.4 Startup, health and resources

- **Init job** (`vlab-init`, one-shot, dynamic IP, `curlimages/curl:8.10.1` or the tools image):
  - installs the three WordPress sites with an HTTP POST to `wp-admin/install.php?step=2` (site titles `RAVEN vlab Modern`, `RAVEN vlab Proxy`, `RAVEN vlab Legacy`; random admin password that is never printed);
  - creates the Toxiproxy proxy `wordpress` (`listen 0.0.0.0:8666`, `upstream 10.77.2.12:80`);
  - is idempotent: it skips WordPress sites that are already installed and recreates the proxy.

  This is lab provisioning, not scanning; RAVEN never sends a POST. The job must not break `up --wait`: V1 checks how Compose treats an exited one-shot, and otherwise runs it with `docker compose run --rm` from `make vlab-up`.
- **Healthchecks:** one per service, using what the image has (`mariadb`/`mysqladmin` ping, `pg_isready`, `redis-cli ping`, `rabbitmq-diagnostics -q ping`, `/toxiproxy-cli list`, PHP or curl for the WordPress/phpMyAdmin/Adminer/DVWA front pages, NPM's `/usr/bin/check-health`, Traefik `--ping`, a bash `/dev/tcp` probe for vsftpd). `make vlab-up` = `docker compose -f compose.vlab.yml up -d --wait`.
- **Trial numbers** (8 vCPU, 16 GB laptop VM):
  - images ≈ **9.6 GB** on disk, ~4 min to pull the first time;
  - `up` until all running ≈ **20 s** after the pull, MySQL 5.7 healthy ≈ 15 s;
  - steady RAM ≈ **1.3 GB** for all four stacks (largest: MySQL 5.7 205 MB, RabbitMQ 160 MB, DVWA 139 MB, Traefik 126 MB).
- **Docker Hub rate limit:** the pull for this design hit `429 Too Many Requests` (unauthenticated pull limit) after ~40 pulls and manifest lookups. `make vlab-pull` pulls once with retries, and the README tells the jury to `docker login` first or to pull ahead of time.

### 2.5 Attaching RAVEN

`lab/vuln/raven.compose.yml` is an override like `lab/raven.compose.yml`. It puts the `raven` service on `raven_vlab` with the **static address `10.77.254.10`** (outside the dynamic range, inside the blacklist) and keeps `default` for Postgres and Dojo:

```sh
docker compose -f compose.yml -f lab/vuln/raven.compose.yml up -d            # vuln lab only
docker compose -f compose.yml -f lab/raven.compose.yml -f lab/vuln/raven.compose.yml up -d   # L1 + vuln lab
```

- `make vlab-down` first disconnects any container still attached to `raven_vlab`, the way [`lab.md`](lab.md) does it for L1, then runs `docker compose -f compose.vlab.yml down` (volumes kept).
- `make dev` on native Linux reaches `10.77.0.0/16` through the bridge. The host's address there is the gateway `10.77.0.1`, which is blacklisted.
- A host with more than about 1,000 live neighbours (scale layer at ≥1,024 hosts): `net.ipv4.neigh.default.gc_thresh*` exist only in the host's namespace (`docker run --sysctl …gc_thresh3` fails, *trial*), so the kernel ARP table is shared and capped at 1,024 entries by default. V4 measures whether `sudo sysctl -w net.ipv4.neigh.default.gc_thresh3=16384` (host-wide, optional) is needed and documents it.

### 2.6 Run the lab (V1)

```sh
docker login                 # optional; Docker Hub allows 100 anonymous pulls per hour per IP
make vlab-pull               # pulls only missing images, 6 attempts 2 min apart
make vlab-up                 # lab/vuln/preflight.sh, up -d --wait, then `run --rm vlab-init`
make vlab-ps
docker compose -f compose.yml -f lab/vuln/raven.compose.yml up -d    # RAVEN as 10.77.254.10
make vlab-down               # disconnects RAVEN and any other attached container, then down (volumes kept)
```

Before any scan: global excludes `10.77.0.1` and `10.77.254.0/23`; targets [`lab/vuln/targets.csv`](../lab/vuln/targets.csv); profile ports [`lab/vuln/ports.txt`](../lab/vuln/ports.txt) (accepted by the profile API). Checks from inside the lab: `docker compose -f compose.vlab.yml --profile tools up -d --wait tools`, then `docker exec raven-vlab-tools-1 curl …`; remove it with `docker compose -f compose.vlab.yml --profile tools rm -sf tools`.

Measured on 2026-11-21 (8 vCPU, 16 GB VM, Docker Compose v5.8.0):

| What | Value |
|---|---|
| images on disk (all services incl. `device` and `vlab-init`) | 10.1 GB |
| `make vlab-up`, images present, fresh volumes (all 21 healthy + init installs) | 29 s |
| `make vlab-up` after `make vlab-down` (volumes kept) | 16 s |
| steady RAM, 21 services | ≈ 1.2 GB (largest: MySQL 5.7 182 MB, RabbitMQ 128 MB, Gitea 103 MB, MariaDB ×2 ~98 MB, DVWA 89 MB) |

Scenario hooks for V2: `VLAB_FLASK_NGINX_TAG` (default `1.20.0-alpine`; upgrade tag `1.30.7-alpine`, the current stable) recreates `flask-app` with another nginx; the shadow-IT `device` is in compose profile `scenario` (`--profile scenario up -d --wait device`, `rm -sf device`); Toxiproxy's API is `http://10.77.2.11:8474`, proxy `wordpress`.

### 2.7 Deviations from §2.1–§2.5 (V1)

- **Service names** carry the stack prefix: `modern-wordpress`, `modern-mariadb`, `modern-phpmyadmin`, `modern-redis`, `modern-npm`, `proxy-traefik`, `proxy-toxiproxy`, `proxy-wordpress`, `proxy-mariadb`, `proxy-redis`, `vuln-wordpress`, `vuln-mysql`, `vuln-adminer`, `vuln-ftp`, `vuln-dvwa`, `custom-api`, `custom-postgres`, `custom-rabbitmq`, `apphost`, `gitea`, `flask-app`, `device` (profile `scenario`), `tools` (profile `tools`), `vlab-init` (profile `init`). Containers are `raven-vlab-<service>-1`.
- **Init job:** with Compose v5.8.0, `up -d --wait` returns 1 (`container raven-vlab-vlab-init-1 exited (0)`) when a one-shot is part of the project, so `vlab-init` is under compose profile `init` and `make vlab-up` runs it with `docker compose run --rm vlab-init` after `--wait`. The script is `lab/vuln/init/vlab-init.sh`; it treats a WordPress site whose `/` returns 200 as installed.
- **WordPress home URL** follows the request's `Host` header (`WP_HOME`/`WP_SITEURL` in `WORDPRESS_CONFIG_EXTRA`), so the proxy site answers 200 directly (10.77.2.12), through Toxiproxy (:8666) and through Traefik (10.77.2.10) without redirects. `WP_HTTP_BLOCK_EXTERNAL` and `AUTOMATIC_UPDATER_DISABLED` are set. WordPress 4.7.5's theme appends the tagline: its title is `RAVEN vlab Legacy – Just another WordPress site`.
- **flask-app** listens on **8787** (`lab/vuln/flask-app.conf`) because it shares 10.77.4.20 with Gitea; 10.77.4.20:80 is closed.
- **Gitea** title comes from the image's `APP_NAME` variable (read when `app.ini` is first written); `GITEA__DEFAULT__APP_NAME` writes a `[DEFAULT]` section that Gitea ignores. The footer shows `Version:` and `28.4.0` on separate lines. Also `OFFLINE_MODE=true` and the update checker off (no egress).
- **Traefik** runs with `--ping` (healthcheck) and `--global.checknewversion=false --global.sendanonymoususage=false`.
- **RabbitMQ** listens on 4369, 5672, 15672, 15692 and 25672 (all in `ports.txt`).
- **vsftpd** passive ports 21000–21010 open only during a transfer; they are not scan targets.
- `httpd:2.4.49-alpine` exists and is used for `device` (`Server: Apache/2.4.49 (Unix)`).
- The subnet preflight is `lab/vuln/preflight.sh`: it fails when `raven_vlab` exists with other settings, another Docker network uses `10.77.x` (or `10.0.0.0/8`), or a host route other than the lab bridge covers or sits inside `10.77.0.0/16`.

## 3. Service inventory: what RAVEN should detect

Status: **today** = expected to work with `main` at V0 (`08678b6`), from the code (`signatures/`, `internal/cve/products.txt` + `CPEForTech`, the nuclei policy in `internal/scanner/nuclei`, the default profile) and the Q1 results; **V***n* = needs that task; **verify** = plausible today but not proven, and V6 confirms it.

Notes that apply to the whole table:
- **Ports:** the seeded `default` profile (S3 migration: nmap's top ~100 ports + 6379, 9200, 27017) **misses 5672, 8474, 8666, 8787, 15672, 4369, 25672, 15692** and the organizers' remapped host ports (2223, 3001, 5673, 8081, 8085–8090, 15432, 15673). The `vuln-lab` profile (V1 port list, seeded by V5) covers them, and V3 extends the default profile with a new migration.
- **Official nuclei templates:** only 8 reviewed templates exist (`internal/scanner/nuclei/templates.go`: WordPress, Joomla, nginx version, Tomcat panel, BunkerWeb, favicon-detect, expired/self-signed TLS). The seeded `default` profile has `nuclei_tags = {}`, so only our signatures run there; the `vuln-lab` profile enables `tech,panel,ssl,waf,favicon`. Panels such as RabbitMQ, Traefik, Adminer and NPM need **our** signatures (V3).
- **CVE findings** reach Dojo on the 5-minute CVE pass, and the Findings page on the next 5-minute sync (Q1 bug M2): count up to ~10 min after a run.
- **Lifecycle:** every host gets **"New device found"** on its first run. A stopped host gets re-probed at the end of the run → `unstable` → `inactive` + **"Host offline"** at the profile's miss threshold (`vuln-lab`: 2). **today**

| IP:port | nmap (service / product / version) | HTTP facts (httpx) | Signatures / nuclei | CVE match | Status |
|---|---|---|---|---|---|
| .1.10:80 | http, Apache httpd 2.4.71 (Debian) | title `RAVEN vlab Modern`, `Server`, `X-Powered-By: PHP/8.3.37`, REST `Link` header, `wordpress_test_cookie` on `/wp-login.php`; tech WordPress 7.1.5, PHP, Apache | `wordpress-detect`, `raven-generator-meta-version`, `raven-x-powered-by-header`, `raven-server-version-header`, `raven-wp-admin`, `raven-cookie-wordpress`, missing HSTS/CSP/XFO | PHP 8.3.37, Apache 2.4.71 (distro build → capped Low), WordPress 7.1.5 (few or none) | today (needs the V1 install; before it: `302 → /wp-admin/install.php`, *trial*) |
| .1.11:3306 | mysql, MariaDB 11.8.9 | — | — | MariaDB 11.8.9 | today (Q1 saw MariaDB 11.8.9) |
| .1.12:80 | http, Apache httpd 2.4.71 | title `phpMyAdmin`, cookies `phpMyAdmin`, `pma_lang` (HttpOnly, no Secure), `X-Frame-Options: DENY`, `X-Powered-By` | `raven-favicon-phpmyadmin` (`/favicon.ico`), `raven-x-powered-by-header`, `raven-cookie-missing-secure`; panel signature at `/` | phpMyAdmin version not shown on the login page → none | favicon: verify; root-path panel: **V3** (`raven-phpmyadmin-path` only checks `/phpmyadmin/`) |
| .1.13:6379 | redis, Redis key-value store 7.4.12 | — | — | Redis 7.4.12 | today (unauthenticated `INFO` → version, *trial*) |
| .1.14:80 | http, OpenResty (no version) | title `Default Site`, `Server: openresty` | — | — | today |
| .1.14:81 | http, OpenResty | title `Nginx Proxy Manager` | admin panel | — | **V3** (signature) |
| .1.14:443 | https; TLS handshake refused without SNI (`unrecognized name`, *trial*) | no certificate | — | — | today (an "open port, no TLS facts" case) |
| .2.10:80 | http, Traefik | title `RAVEN vlab Proxy` via Toxiproxy; **changes to 502** under the `timeout`/`down` toxics; slower under `latency` | WordPress signatures as at .1.10 | WordPress / PHP / Apache as at .1.10 | today; recorded response time: **V7** |
| .2.10:8080 | http, Traefik | **redirect** `301 → /dashboard/`, title `Traefik`; `/api/version` → `{"Version":"3.1.7"}` | `raven-version-endpoint` (`/api/version`, case-insensitive); dashboard panel | Traefik 3.1.7 (through the extracted version) | version endpoint: today; panel + CVE via the extracted version: **V3** |
| .2.11:8474 | http, Go (Toxiproxy API) | `/version` → `{"version": "2.12.0"}`, `X-Toxiproxy-Request-Id` header, 404 on `/` | `raven-version-endpoint`; Toxiproxy API signature | — (not in NVD) | version endpoint: today; product signature: **V3** |
| .2.11:8666 | http (Toxiproxy proxy → WordPress) | same as the WordPress behind it; **no HTTP answer** under the `timeout` toxic while the port stays open | as .2.12 | as .2.12 | today |
| .2.12:80 | http, Apache httpd 2.4.71 | WordPress, title `RAVEN vlab Proxy` | as .1.10 | as .1.10 | today (after the V1 install) |
| .2.13:3306, .2.14:6379 | MariaDB 11.8.9; Redis 7.4.12 | — | — | as .1.11 / .1.13 | today |
| .3.10:80 | http, **Apache httpd 2.4.10 (Debian)** | title `RAVEN vlab Legacy`, `X-Powered-By: PHP/5.6.30`, generator `WordPress 4.7.5` | `wordpress-detect`, `raven-generator-meta-version`, `raven-x-powered-by-header`, `raven-wp-admin`, `raven-cookie-wordpress` | **WordPress 4.7.5** (many, incl. High/Critical), **PHP 5.6.30** (many), Apache 2.4.10 (distro → Low) | today, if the generator meta survives the install; **verify** (Wappalyzer may also report `WordPress:4.7.5`) |
| .3.11:3306 | mysql, **MySQL 5.7.44** | — | — | MySQL 5.7.44 (`mysql:mysql` → `oracle:mysql` alias) | today |
| .3.12:8080 | http, PHP built-in/Adminer | title `Login - Adminer`, cookies `adminer_sid`, `adminer_key` (HttpOnly, SameSite=lax, no Secure), `X-Powered-By: PHP/8.4.28` | Adminer panel; `raven-cookie-missing-secure`, `raven-x-powered-by-header` | Adminer not in `products.txt` (6.3.0: no known CVEs expected) | panel: **V3**; rest today |
| .3.13:21 | ftp, **vsftpd 3.0.2** | — | — | vsftpd 3.0.2 (nmap CPE `vsftpd:vsftpd` is unknown → falls back to the product name → `beasts:vsftpd`) | **verify**; V3 adds the `vsftpd:vsftpd` alias |
| .3.14:80 | http, Apache httpd 2.4.25 (Debian) | **redirect** `302 → login.php`, title `Login :: Damn Vulnerable Web Application (DVWA) v1.10 *Development*`, cookies `PHPSESSID` (no HttpOnly), `security=low` | `raven-cookie-phpsessid`, `raven-cookie-missing-httponly`, `raven-cookie-missing-secure`; DVWA panel + "Development" marker | Apache 2.4.25 (distro → Low) | cookies: today; DVWA/"Development" signatures: **V3**; active checks: **V8** (aggressive, AG2–AG5) |
| .4.10:80 | http, gunicorn 19.9.0 | title `httpbin.org`, `Server: gunicorn/19.9.0` | `raven-server-version-header` | gunicorn 19.9.0 (no matching range) | today |
| .4.11:5432 | postgresql, PostgreSQL (version range only) | — | — | none (no exact version) | today |
| .4.12:5672 | amqp, RabbitMQ 3.13.7 | — | — | RabbitMQ 3.13.7 | verify (port **not** in `default`, in `vuln-lab`) |
| .4.12:15672 | http, Cowboy | title `RabbitMQ Management`, `server: Cowboy` | RabbitMQ management panel | — | **V3** |
| .4.20:3000 | http, Gitea (Go) | title `RAVEN vlab Gitea` (or Gitea's default), cookie `i_like_gitea` (HttpOnly), `_csrf`; footer `Powered by Gitea Version: 28.4.0` | `raven-footer-version` does **not** match `Version: 28.4.0` (colon); Gitea signature with version extractor | Gitea 28.4.0 (via the extracted version) | **V3** |
| .4.20:22 | ssh, OpenSSH 10.3 | — | — | OpenSSH 10.3 (none expected) | today |
| .4.20:8787 | http, **nginx 1.20.0** | title `Welcome to nginx!`, `Server: nginx/1.20.0` | `nginx-version`, `raven-server-version-header` | **nginx 1.20.0 → CVE-2021-23017** and others | today (port not in `default`, in `vuln-lab`) |
| .9.50:80 | http, **Apache httpd 2.4.49** | default `It works!`, `Server: Apache/2.4.49 (Unix)` | `raven-server-version-header` | **Apache 2.4.49 → CVE-2021-41773, CVE-2021-42013 (CISA KEV)** | today (Q1: Apache 2.4.49 banner → 88 CVEs, 3 KEV) |
| scale layer `10.77.64.0/18` | per persona (§5) | per persona | the existing pack (printer/router/camera titles, staging header, Tomcat, Jenkins favicon, …) | per persona (Apache 2.4.49, OpenSSH 7.4, nginx 1.20.0, …) | **V4** |

Organizers' notes worth repeating to the jury:
- default credentials exist (FTP `test/test123`, DVWA `admin/password`, Postgres `appuser/StrongPassword123`, RabbitMQ `guest/guest` local-only); RAVEN **never tries them** (§7);
- `X-Environment`/staging markers don't exist in the organizers' lab; L1 (172.30.0.20) and the scale personas cover them;
- TLS facts: NPM 443 sends no certificate without SNI; L1 (`.23` self-signed, `.24` expired) and the scale TLS persona cover TLS.

## 4. Scenarios → jury test points

All steps run on the vuln lab only. `S` = `scripts/vlab-scenario.sh` (V2). A step that changes the lab prints what to check afterwards. `--run` makes it also start a run of the `vuln-lab` profile and wait for it.

| # | Step | Command | Where to look | Expected outcome |
|---|---|---|---|---|
| 0 | Deploy + seed | `make demo` (V5) | terminal summary; RAVEN login | RAVEN + Dojo + vuln lab up; blacklist, targets, `vuln-lab` profile and demo users seeded; optional Run 1 |
| 1 | **Baseline** (Run 1) | `S baseline --run` | Dashboard, Hosts, Services, Findings, Dojo Assets | **19 hosts** active (the table above without .9.x); empty addresses in the five /24s not created; "New device found" ×19; per-host HTTP facts; signatures; CVE findings within ~10 min |
| 2 | **Service gone** (organizers' quickstart) | `S service-gone`, then a run | Changes (Run 1 → 2), host 10.77.4.20, Dojo | `10.77.4.20:8787` **gone**; 3000 and 22 on the same host unchanged; host stays `active`; the Dojo nmap finding for 8787 closed |
| 3 | **Service back** | `S service-back`, then a run | Changes, Dojo | `10.77.4.20:8787` **new** again; finding reactivated or recreated |
| 4 | **Version change** | `S upgrade` (flask-app nginx 1.20.0 → a current nginx), then a run | Changes; CVE matches of 10.77.4.20:8787; Dojo "RAVEN CVE match" Test | `changed` with `fields: [version, …]`; CVE-2021-23017 & co. **closed** after the next CVE pass; new CVEs, if any, opened. `S downgrade` reverts. |
| 5 | **New device (shadow IT)** | `S device-new`, then a run | Dashboard "new devices", Dojo | `10.77.9.50` new; **"New device found: 10.77.9.50"**; **CVE-2021-41773 (KEV)** Critical |
| 6 | **Host offline** | `S host-off` (stops httpbin 10.77.4.10), then two runs | Hosts (state filter), Run stats `reprobed`/`became_unstable`/`became_inactive`, Dojo | run A: re-probed → `unstable`, `miss_count=1`, no reimport (its findings stay active); run B (threshold 2): `inactive` + **"Host offline: 10.77.4.10"**. `S host-on` + a run → `active` again |
| 7 | **Slow / unstable responses** (Toxiproxy) | `S toxic latency 3000`, `S toxic timeout`, `S toxic slow-close`, `S toxic down`, `S toxic clear` | Run/batch durations, Changes for 10.77.2.10:80 and 10.77.2.11:8666 | latency: the run is slower but complete, same facts (response time recorded: **V7**); timeout/down: Traefik answers **502** → `changed` (status/title), :8666 has no HTTP answer while the port stays open; clear → back to 200 on the next run |
| 8 | **Custom signature** | `S signature` (as editor: creates "DVWA security level cookie" via the API, tests it) | Signatures page; next run's findings | valid; test matches `http://10.77.3.14/` and not `http://10.77.4.10/`; an out-of-scope URL is refused; the next run creates the finding in Dojo |
| 9 | **Edits survive** | `S edit` (as operator: owner/criticality/notes/tags on 10.77.3.14, a service product override, finding severity + note), then a run | Host page, Dojo Asset description, the finding | all edits kept after the run; scan values move underneath the overrides |
| 10 | **Import / export** | `S exchange` (viewer exports hosts/services/findings CSV+JSON; editor imports the sample results with 10.77.9.51) | Import/Export page, Hosts, Dojo | exports 200 for viewer; import creates 10.77.9.51 + "New device found" |
| 11 | **Roles** | `S roles` | printed matrix | viewer 403 on every mutation, 200 on export; operator only host/finding edits; editor no users; admin all |
| 12 | **Time window** | `S window` (profile `vuln-lab-slow`: all ports, rate 2, window now+1 → now+3 min) | Runs | run starts in the window, is `suspended` at its end with the batch back to `pending`, resumes in the next window |
| 13 | **Planned engagement (Dojo)** | `S dojo-plan` | Dojo `RAVEN Planning`; Schedules (source `dojo`) | within 5 min a Dojo-sourced schedule appears and a run of `vuln-lab` starts in its window |
| 14 | **Scale** | `scripts/vlab-scale.sh up` + `make demo` with `--scale`, then two runs with `vlab-scale.sh churn` in between (V4) | Runs (batch sizes, durations), Dashboard, Changes | hosts found == occupied addresses; Changes == the expected churn printed by `vlab-scale.sh expect` |
| 15 | Aggressive (only after AG2–AG5) | admin builds `vuln-lab-aggressive` in the UI (DVWA + WP 4.7 only), confirms the start (V8) | Runs badge, Dojo Nikto/WPScan/ZAP Tests | never seeded, never default (§7) |

Jury test points (challenge §6) → steps:

| # | Test point | Steps |
|---|---|---|
| 1 | Active hosts | 1, 5, 6, 14 |
| 2 | Service identification | 1 (inventory §3), 4 |
| 3 | HTTP/HTTPS fingerprinting | 1 (titles, headers, cookies, **redirects** on .2.10:8080 / .3.14, favicon) + L1 for TLS |
| 4 | CMS / technologies | 1 (WordPress ×3 incl. 4.7.5, phpMyAdmin, Adminer, Gitea, RabbitMQ, Traefik, NPM, DVWA, httpbin) |
| 5 | Interesting headers & cookies | 1 (`X-Powered-By`, `Server` versions, `security=low`, `PHPSESSID` without HttpOnly, `X-Toxiproxy-Request-Id`) |
| 6 | Custom signatures | 8 (+ V3 built-ins in 1) |
| 7 | Comparison between runs | 2, 3, 4, 5, 14 |
| 8 | Unstable / changing hosts | 6, 7 |
| 9 | Scanner safety | §7; the seeded blacklist; command lines in the run logs; 15 stays opt-in |
| 10 | Dashboard / report | after 1 and after 2–7 |
| 11 | Import & export | 10 |
| 12 | Roles | 11 |

Scoring criteria (challenge §8): discovery at scale (30 %) → 1 + 14; changes and unstable hosts (15 %) → 2–7, 14; quality, docs, ease of deployment, import/export, Dojo (20 %) → 0, 10, 13 and this document; safety and intensity control (15 %) → §7, the profile rate limits, 12; fingerprinting (10 %) → 1, 8; roles and data protection (10 %) → 9, 11.

## 5. Scale layer (V4)

Goal: a **real** scan (nmap → httpx → nuclei → Dojo, not the Q2 fakes) over more than 10,000 addresses, with hosts that are interesting to fingerprint and group, on a laptop.

**Why not replicas.** A Linux bridge takes at most 1,024 ports (`BR_MAX_PORTS`), so one container per host stops at ~1,000 hosts per network, and each container costs ≥ 1–5 MB plus Docker bookkeeping. macvlan/ipvlan are not allowed (they leave the internal network).

**Many addresses in one container** *(trial, verified)*: a container on the `internal` bridge with `cap_add: [NET_ADMIN]` can `ip addr add 10.77.x.y/16 dev eth0` for addresses outside Docker's `ip_range`. Other containers on the bridge (RAVEN) reach every added address through normal ARP. The trial added **1,961 addresses in ~2 s** to one nginx container; it used **7.8 MB** RAM, and `curl` reached all of them. All addresses share one MAC, like a router doing proxy ARP; RAVEN's identity is the IP, so that's fine.

Design:
- `compose.vlab-scale.yml` (project `raven-vlab-scale`, network `raven_vlab` declared `external`) runs **one** service, `swarm`, built from `lab/vuln/scale/` (a tiny Go program, standard library only, own `go.mod` like `lab/fixtures`; alpine runtime with `iproute2`). Static IP `10.77.64.1`; `cap_add: [NET_ADMIN]` for this lab container only; `ulimits: nofile: 65536`.
- **Occupancy:** `VLAB_SCALE_HOSTS` (default **256**, max **4096**) addresses out of the 16,382 usable in `10.77.64.0/18`, placed pseudo-randomly from `VLAB_SCALE_SEED` (default 1), so most of the range is **empty address space**. The program adds them in one `ip -batch` call, then **binds a listener per (address, port)** of the address's persona. A port the persona doesn't have is **closed** (RST), not open-and-silent.
- **Personas** (about 12, chosen per address from a hash of the IP and the seed; ports and banners vary within a persona so grouping (X4) has something to group):
  - nginx intranet page, versions 1.18.0 / 1.20.0 / 1.24.0 / 1.26.3, titles `Intranet`, `Wiki`, `Status`;
  - Apache/2.4.49 + `X-Powered-By: PHP/7.4.3` (KEV CVEs);
  - IIS-like `Microsoft-IIS/8.5` + `X-AspNet-Version`, `ASP.NET_SessionId`;
  - Tomcat-like `JSESSIONID`, `/manager/html` 401;
  - Jenkins-like `X-Jenkins: 2.440` + the real Jenkins favicon;
  - staging app `X-Environment: staging`, title `… (staging)`;
  - printer (title matching `raven-printer-title`), camera (Hikvision-style title), router (title matching `raven-router-title`), **plus** `9100/tcp`;
  - TLS on 443 with a self-signed certificate generated at startup;
  - SSH banners only (`OpenSSH_7.4`, `OpenSSH_8.9p1 Ubuntu-3ubuntu0.10` → distro cap);
  - FTP banner only (`220 (vsFTPd 3.0.2)`).

  Personas don't need real software: they answer with the same bytes the products send. Ports used: `21,22,80,443,8080,8443,9100`, which is the `vuln-lab-scale` profile's port list.
- **Churn between runs:** `VLAB_SCALE_EPOCH` (default 0). Epoch *n* vs *n−1*: ~3 % of hosts gone, ~3 % new, ~5 % change version or title, all deterministic. `scripts/vlab-scale.sh churn` recreates the container with epoch+1. `scripts/vlab-scale.sh expect` prints the expected new/gone/changed **host and service counts** for the current epoch vs the previous one, so RAVEN's Changes can be **checked by numbers**.
- `scripts/vlab-scale.sh up [N] | down | churn | expect | status` is the interface V5 calls (`--scale`).

**What V4 measures** and appends to [`scale.md`](scale.md) as "Real scan: vuln lab scale layer". Runs at `VLAB_SCALE_HOSTS` = 256, 1,024 and (if 1,024 extrapolates to under ~1 h including Dojo) 4,096, over the whole /18, two runs each with one `churn` in between:
- correctness: hosts up found vs occupied (exact), services found vs expected, Changes vs `expect`;
- run time: total, planning, per batch, the batch sizes S5 picked in run 1 and run 2, re-probe time;
- intensity: the effective nmap rate vs `nmap_max_rate` (packet counters on the swarm's interface over the run), httpx/nuclei `-rl`;
- resources: RAVEN and `raven-db` CPU/RAM peaks (`docker stats`), DB size after each run, swarm RAM;
- **Dojo:** push/drain time after the run. One Asset per IP with 3–4 reimports each is the expected real bottleneck, because Q2 used a stub;
- API latencies after run 2: `/api/dashboard`, `/api/hosts` (first and deep page), `/api/changes`;
- kernel: `dmesg | grep -i "neighbour table overflow"`, and whether the host `gc_thresh3` sysctl changes the result.

**Laptop budget:** the swarm costs about 10–30 MB at 4,096 hosts, so RAVEN, Postgres and Dojo set the limit. 256 hosts is the default for `make demo --scale`; 1,024 and 4,096 are for the measurement.

## 6. One-command demo (V5)

```sh
git clone https://github.com/WH-HN2026/raven && cd raven
make demo                      # = scripts/demo.sh up
make demo ARGS="--scale"       # + scale layer (256 hosts) and the vuln-lab-scale profile
make demo-down                 # stop everything, keep data
make demo-reset                # delete RAVEN/Dojo/lab volumes and .demo-credentials (asks first; CONFIRM=1 skips)
```

`scripts/demo.sh up [--scale[=N]] [--l1] [--no-run]`, idempotent, safe to re-run:
1. **Preflight:** Docker + Compose v2; free host ports (`RAVEN_PORT`, `DD_PORT`, `DD_TLS_PORT`, `RAVEN_DB_PORT` from `.env` or the defaults); `10.77.0.0/16` free (same check as `make vlab-up`); a warning below 8 GB RAM or 20 GB free disk; a hint to `docker login` because of the pull limit.
2. `.env`: run `scripts/gen-env.sh` only if `.env` is missing; never overwrite it.
3. `make vlab-up` (+ `scripts/vlab-scale.sh up N` with `--scale`, + `make lab-up` with `--l1`).
4. `docker compose -f compose.yml -f lab/vuln/raven.compose.yml [-f lab/raven.compose.yml] up -d --build`.
5. Wait: `GET /api/healthz` 200, then `docker compose logs raven` contains `dojo bootstrap done` (timeout 10 min; prints progress every 15 s).
6. **Seed** through the API as the bootstrap admin (`RAVEN_ADMIN_PASSWORD` from `.env`). Use the session cookie `raven_session` and the header `X-RAVEN-CSRF: 1` on unsafe methods. Check before creating; treat `409` as "exists":
   - **global exclude** entries: `10.77.0.1` (note `vlab gateway = host`), `10.77.254.0/23` (`RAVEN + lab helpers`); with `--l1` also `172.30.0.1` and `172.30.0.128/25`;
   - **targets:** upload `lab/vuln/targets.csv` (tags `vlab` + stack); `--scale` adds `10.77.64.0/18` (tags `vlab;scale`); `--l1` uploads `lab/targets.txt`;
   - **profiles** (create, or `PUT` to bring an existing one back to the seed values):
     - `vuln-lab`: ports from `lab/vuln/ports.txt`, `nmap_max_rate` 300, `nuclei_rate` 25, `nuclei_tags` `tech,panel,ssl,waf,favicon`, `miss_threshold` 2, `target_batch_seconds` 600, include `10.77.0.0/20`;
     - `vuln-lab-scale` (`--scale`): ports `21,22,80,443,8080,8443,9100`, `nmap_max_rate` 1000, include `10.77.64.0/18`;
     - both send `stages: ["nmap","httpx","nuclei"]` (the Default preset, WF1) explicitly;
     - **none of them aggressive**;
   - **users** `demo-editor`, `demo-operator`, `demo-viewer`: created only if missing, with random 24-character passwords written to **`.demo-credentials`** (mode 600, gitignored). An existing user keeps its password.
7. Unless `--no-run`: start Run 1 of `vuln-lab` and wait for `done`, printing hosts up, services and the duration.
8. Print the URLs, where the passwords are (`.env`, `.demo-credentials`), and the next commands (`scripts/vlab-scenario.sh …`).

`demo-down` = `docker compose -f compose.yml -f lab/vuln/raven.compose.yml down` (volumes kept) + `make vlab-down` (+ `vlab-scale.sh down`, `make lab-down` if they are running). `demo-reset` = the same with `-v`, then `rm -f .demo-credentials`; it **keeps `.env`**, so fresh volumes get the same secrets.

The README gets a short **Demo** section with these commands (V5).

### 6.1 Deviations from §6 (V5)

- **Run 1 only once:** step 7 starts a run only when `vuln-lab` has none yet. A re-run of `make demo` waits for a pending/running run, or skips the run when the last one is `done` and prints its numbers; further runs come from `scripts/vlab-scenario.sh … --run` or the Runs page. This keeps a second `make demo` free of side effects.
- **`.demo-credentials` format:** dotenv lines `DEMO_EDITOR_PASSWORD=…`, `DEMO_OPERATOR_PASSWORD=…`, `DEMO_VIEWER_PASSWORD=…` (users `demo-editor`, `demo-operator`, `demo-viewer`), so scripts read them with `RAVEN_ENV_FILE=.demo-credentials raven_env DEMO_VIEWER_PASSWORD`.
- **Pulls:** `make demo` runs `make vlab-pull` (retries on 429) before `make vlab-up`.
- **Ports preflight** checks `RAVEN_PORT`, `DD_PORT`, `DD_TLS_PORT`, `RAVEN_DB_PORT` with `ss` only when the demo's `raven` container isn't already running (on a re-run the ports are its own).
- **`--scale`** fails at preflight with "needs scripts/vlab-scale.sh (V4)" while V4 isn't merged; `demo-down`/`demo-reset` call `vlab-scale.sh down` only when the script exists.
- **`demo-reset`** also runs `down -v` on `compose.vlab.yml` (all profiles) and `compose.lab.yml`.
- **Test hooks** (for running the demo next to a stack that must not be touched; the jury needs none):
  - `COMPOSE_PROJECT_NAME=<name>`: Compose's own variable; it overrides `name: raven` in `compose.yml`, so containers, volumes and the default network are separate;
  - `DEMO_LAB=shared`: use the vuln lab (and L1 / scale layer) that is already running; `up` never runs `vlab-pull`/`vlab-up`/`lab-up`, and `down`/`reset` never stop or delete the labs;
  - `DEMO_COMPOSE_OVERRIDE=<file>`: one extra compose file for the RAVEN stack, e.g. another image tag (instead of `raven:local`) and another RAVEN address in `10.77.254.0/23`.

## 7. Safety

- **Every scanned address is on an `internal: true` bridge.** Docker gives `internal` networks no route out: lab containers can't reach the internet, and RAVEN's traffic to `10.77.0.0/16` never leaves the bridge. RAVEN reaches Dojo and Postgres over its own `default` network; that network is not a scan target.
- **No host exposure:** no lab service publishes a port, so nothing on the host or the LAN reaches the lab, and the lab can't be confused with the host.
- **The gateway rule.** On every Docker bridge, `.1` is **the host** (the same rule as `172.30.0.1` for L1 in [`lab.md`](lab.md)), so scanning it would scan the host. `10.77.0.1` is in the global blacklist that `make demo` seeds, together with `10.77.254.0/23` (RAVEN itself and the lab tooling). Exclusions always win (architecture §9). Targets are only `10.77.1–4.0/24`, `10.77.9.0/24` and, opt-in, `10.77.64.0/18`; the `vuln-lab` include is `10.77.0.0/20`, so a typo in a target can't reach outside it.
- **No credentials are ever tried.** The lab has default credentials (FTP `test/test123`, DVWA `admin/password`, Postgres `appuser/StrongPassword123`, MySQL `wpuser/wppass`, RabbitMQ `guest/guest`). RAVEN sends no login and no POST: nmap runs only the allowlisted scripts (`http-title,http-headers,ssl-cert,banner`), httpx one GET per URL, nuclei excludes `default-login,credential,bruteforce` and every intrusive tag, and the signature validator allows only GET/HEAD. The only POSTs in the lab are the init job's WordPress installs and Toxiproxy API calls, made by lab tooling, not by RAVEN.
- **Intensity:** every profile keeps `nmap_max_rate` and `nuclei_rate`. The scale profile's 1000 pps applies only to `10.77.64.0/18`.
- **Aggressive stages** (V8, after AG2–AG5) run only in an admin-made profile limited to `10.77.3.10` and `10.77.3.14`, with the AG1 confirmation. The demo never creates an aggressive profile.
- **Nothing in the lab is reachable from outside, so the deliberately old software** (WordPress 4.7.5, PHP 5.6, MySQL 5.7, DVWA, Apache 2.4.49) is not exposed. Never add `ports:` to `compose.vlab*.yml`.

## 8. Task specs

Shared contract (every task):
- network `raven_vlab`, `10.77.0.0/16`, the addresses in §2.2–§2.3 (don't move them); blacklist `10.77.0.1`, `10.77.254.0/23`; RAVEN at `10.77.254.10`;
- files V1 publishes: `lab/vuln/targets.csv` (`value,tags,note`, the five /24s), `lab/vuln/ports.txt` (one line, the `vuln-lab` port spec), `lab/vuln/raven.compose.yml`, `scripts/lib/raven-api.sh`;
- **`scripts/lib/raven-api.sh`** (sourced, bash): `raven_url` (default `http://localhost:${RAVEN_PORT:-8000}`), `raven_login <user> <password> [jar]` (POST `/api/auth/login`, cookie jar), `raven_get <path>`, `raven_post|raven_put|raven_patch|raven_delete <path> [json]` (send `X-RAVEN-CSRF: 1`, print the body, return non-zero on 4xx/5xx except an allowed status passed as `RAVEN_OK=409`), `raven_upload <path> <file> [field=value…]`, `raven_wait_run <id> [timeout]`, `raven_env <VAR>` (read one value from `.env` without sourcing it). It needs only `curl` and `jq`;
- **Makefile:** each task adds its own targets **with its own `.PHONY:` line** next to them and doesn't touch the shared `.PHONY` line;
- `docs/vuln-lab.md`: each task edits only its own section (named below) and reports deviations from this design in its PR body. Only V6 edits the §3 inventory status column;
- safety (§7) applies to every task, including tests: scan nothing outside `raven_vlab`, never add `ports:` to a lab service, and never put credentials into RAVEN or a scanner.

### V1 — RAVEN-safe vuln lab compose

- **Goal:** §2 as working files. All four organizers' stacks run **together** on `raven_vlab` with static IPs, no published ports, pinned images, healthchecks and the init job, so RAVEN can attach and scan them.
- **Owns:**
  - `compose.vlab.yml`;
  - `lab/vuln/` except `organizers/`, `scale/` and `scenario/`: `raven.compose.yml`, `targets.csv`, `ports.txt`, `traefik/` (dynamic config; keep the organizers' `PathPrefix` router, upstream `http://10.77.2.11:8666`), `init/` if needed, `README.md` (short, English: how to run, pointer to this doc);
  - `scripts/lib/raven-api.sh`;
  - Makefile `vlab-pull`, `vlab-up` (with the subnet preflight), `vlab-down` (disconnect attached containers first; keep volumes), `vlab-ps`;
  - section "§2" deviations and a new "Run the lab" subsection in this document.
- **Don't touch:** `compose.yml`, `compose.lab.yml`, `lab/vuln/organizers/` (verbatim), Go/web code.
- **Notes:**
  - copy the full digests from §2.3;
  - verify `httpd:2.4.49-alpine` and `nginx:1.20.0-alpine` (and pick the upgrade tag for V2, e.g. the current `nginx:1.30.x-alpine`; put it in `lab/vuln/README.md`);
  - the shadow-IT `device` service is defined in `compose.vlab.yml` under compose profile `scenario`, so plain `up` doesn't start it;
  - the `tools` service sits under compose profile `tools`;
  - the WordPress install must make `/` return 200 with the generator meta;
  - Gitea runs with `INSTALL_LOCK=true`;
  - `ports.txt` = `21,22,80,81,443,2223,3000,3001,3306,4369,5432,5672,5673,6379,8080,8081,8085-8090,8443,8474,8666,8787,8888,15432,15672,15673,15692,25672` (native ports plus the organizers' remapped host ports, so the same profile also fits their as-shipped lab). Check that RAVEN's port validator accepts it.
- **Done when:**
  - `make vlab-up` from a clean state ends with every service healthy (paste `docker compose -f compose.vlab.yml ps`);
  - `docker compose -f compose.vlab.yml config` shows no `ports:`, and `docker network inspect raven_vlab` shows `Internal: true`;
  - from the `tools` container, curl/nc reach every §2.3 address and port (paste the output), and a curl to `1.1.1.1` fails;
  - `docker compose -f compose.yml -f lab/vuln/raven.compose.yml config` is valid, and RAVEN gets `10.77.254.10`. The combined L1 + vlab override form is valid too;
  - `make vlab-down` leaves no container on `raven_vlab`, and the RAM/startup numbers are recorded in "Run the lab";
  - `raven-api.sh`: log in, GET `/api/auth/me`, POST and DELETE one scope entry against `make dev` or compose (paste the output);
  - `make check` is green. **No scanner run is needed**; if you run one, run it only against `raven_vlab` with the blacklist.

### V2 — Scenario driver

- **Goal:** `scripts/vlab-scenario.sh <step> [--run]` with every step of §4 (1–13): `status`, `baseline`, `service-gone`, `service-back`, `upgrade`, `downgrade`, `device-new`, `device-remove`, `host-off`, `host-on`, `toxic latency <ms>|timeout|slow-close|down|clear`, `signature`, `edit`, `exchange`, `roles`, `window`, `dojo-plan`, and `walk` (runs 1→7 in order with runs in between and prints a pass/fail line per expected outcome that can be checked through the API).
  - Each step is idempotent and prints "check: …" lines (page, filter, expected value).
  - `--run` starts a `vuln-lab` run and waits for it.
  - Toxics go to `http://10.77.2.11:8474` from a container on `raven_vlab` (the `tools` service or a one-shot curl container in the dynamic range); never from the host.
  - Role steps read `.demo-credentials`; admin reads `.env`.
  - `dojo-plan` gets a Dojo token with `DD_ADMIN_USER`/`DD_ADMIN_PASSWORD` from `.env` on `localhost:${DD_PORT:-8080}`.
- **Owns:** `scripts/vlab-scenario.sh`; `lab/vuln/scenario/` (the custom signature YAML, the import sample with `10.77.9.51`, any fixtures); the "Scenario driver" section of this document.
- **Uses:** `scripts/lib/raven-api.sh`, the V1 compose services and profiles (`scenario`, `tools`), and the `vuln-lab` profile as seeded by V5. When the profile is missing, the script creates it with the §6 values.
- **Safety:**
  - the signature passes the validator (GET only);
  - `window` creates the non-aggressive `vuln-lab-slow` profile;
  - no step logs in to a lab service.
- **Done when:**
  - every step ran at least once against a fresh `make vlab-up` + RAVEN attached; the PR lists step → output excerpt;
  - `walk` passes end to end;
  - re-running every step twice is harmless;
  - `shellcheck scripts/vlab-scenario.sh` is clean if shellcheck is available, and `make check` is green.

### V3 — Fingerprint coverage for the vuln lab

- **Goal:** every §3 row marked **V3** works with real recorded responses:
  - built-in signatures (safe subset) for:
    - the Nginx Proxy Manager admin (:81);
    - the Traefik dashboard (with a version extractor from `/api/version`);
    - the Toxiproxy API (`X-Toxiproxy-Request-Id` / `/version`);
    - the RabbitMQ management panel;
    - the Adminer login (with version);
    - the phpMyAdmin login at `/`;
    - the DVWA login + the "Development" marker;
    - Gitea with the footer version (`Version: x.y.z`);
  - `products.txt`: alias `vsftpd:vsftpd`, plus Adminer (`adminer:adminer`) if NVD has it. Regenerate `cve.json.gz` with `make cve-db` only if a product was added;
  - `CPEForTech` synonyms for the names the new signatures emit, with table tests in `internal/cve`;
  - a **new migration** (`make db-new name=default_profile_vlab_ports`) adding the ports from `lab/vuln/ports.txt` that the seeded `default` profile lacks, only when `ports` still equals the old default. The column default changes too.
- **Owns:**
  - `signatures/raven-*.yaml` (new files only) + `signatures/testdata/<id>/` + `signatures/README.md` table rows;
  - `internal/cve/products.txt`, `internal/cve/tech.go`, `internal/cve/*_test.go`, `internal/cve/data/` (only if regenerated);
  - the new migration file;
  - nothing else in Go.
- **Fixtures:** record `response.http` from the real services (vuln lab or the pinned image in a throwaway `--network none` / internal-network container), not reconstructions. Note the source image and tag in the README table.
- **Done when:**
  - `go test ./internal/signatures/ ./internal/cve/` pass (pack harness: each new template matches its fixture and not `_neutral`);
  - `signatures/fixsrv/prove.sh` passes for the new templates (paste the summary);
  - a lab run of `vuln-lab` shows each new signature hit on its host and the vsftpd/Traefik/Gitea CVE instances (or "no CVE in range" with the reason), with the Dojo finding titles pasted;
  - `make check` is green.

### V4 — Scale layer + real-scan measurements

- **Goal:** §5.
- **Owns:**
  - `compose.vlab-scale.yml`, `lab/vuln/scale/` (Go program with its own `go.mod`, Dockerfile, persona catalog, unit tests for placement/churn/expect);
  - `scripts/vlab-scale.sh` (`up [N] | down | churn | expect | status`);
  - Makefile `vlab-scale-up`, `vlab-scale-down`;
  - a new section at the end of `docs/scale.md`; the "§5" deviations in this document.
- **Interface for V5:**
  - `scripts/vlab-scale.sh up N` returns once all N addresses answer, and is idempotent;
  - `down` keeps nothing;
  - the scale target is `10.77.64.0/18`, and the profile ports are `21,22,80,443,8080,8443,9100`.
- **Safety:**
  - the swarm adds addresses only inside `10.77.64.0/18` and refuses others;
  - `NET_ADMIN` only on the swarm;
  - no `ports:`;
  - scans only with the `vuln-lab-scale` profile and the blacklist in place.
- **Done when:**
  - `go test` in `lab/vuln/scale` passes;
  - `vlab-scale.sh up 256` + one RAVEN run finds **exactly** 256 hosts;
  - after `churn`, run 2's Changes match `expect` (paste both);
  - the measurement table in `docs/scale.md` covers 256 and 1,024 hosts (4,096 if the budget allows) with every metric in §5, including Dojo drain time and the neighbour-table result;
  - `make check` is green.

### V5 — One-command demo

- **Goal:** §6.
- **Owns:**
  - `scripts/demo.sh`;
  - Makefile `demo`, `demo-down`, `demo-reset`;
  - the README **Demo** section, plus a link to this document in the README Docs line;
  - the "§6" deviations in this document;
  - (`.gitignore` already has `.demo-credentials` from V0).
- **Uses:**
  - `scripts/lib/raven-api.sh`, `lab/vuln/targets.csv`, `lab/vuln/ports.txt`, `lab/vuln/raven.compose.yml`, `make vlab-up/vlab-down` (V1);
  - `scripts/vlab-scale.sh` (V4) **only if present**: `--scale` fails with a clear message otherwise.
- **Safety:**
  - seeds the blacklist **before** any target or profile, and refuses to start a run if the blacklist entries are missing;
  - never creates an aggressive profile.
- **Done when:**
  - from a **fresh clone in a temp dir** with a separate compose project and the ports changed in `.env` (as Q1 did, so the shared dev stack is untouched), `make demo` ends with Run 1 done and the summary printed;
  - a second `make demo` changes nothing and creates no duplicates (show the targets/scope/profile/user counts before and after);
  - `make demo-down` then `make demo` resumes with the data kept;
  - `make demo-reset CONFIRM=1` removes the volumes and `.demo-credentials` but keeps `.env`;
  - `make check` is green.

### V6 — Acceptance pass on the vuln lab

- **Goal:** run §4 steps 0–14 as the jury would (fresh clone, `make demo`, then `scripts/vlab-scenario.sh walk` and the remaining steps by hand in the UI as the matching roles), with V7 if merged.
- **Owns:**
  - this document's §3 status column, flipping "verify"/"V*n*" to observed results;
  - a new "Acceptance results" section with an expected-vs-actual table per step and per jury test point;
  - follow-up tasks appended to Track V in `docs/roadmap.md`.
- **Done when:**
  - every step has an observed result with evidence (page, API response, Dojo finding title);
  - every mismatch is either fixed in a linked PR or listed as a follow-up;
  - the Dojo objects were created only in this pass's own compose project and removed afterwards.

### V7 — Response time and slow hosts

- **Goal:** the organizers' Toxiproxy note says the app "should record a longer response time".
  - Keep httpx's per-URL response time (`time` in its JSON) in a new `http_observations.response_ms` column (new migration);
  - show it on the host page and in the services API;
  - mark a service **slow** when its response time is above a fixed threshold or 3× its previous run's;
  - count a service whose port is open but which gave no HTTP answer this run (it had one last run) as `http_unresponsive` in the run stats and Changes;
  - set httpx `-timeout` explicitly in the allowlisted builder.
- **Owns:** `internal/scanner/httpx`, the HTTP part of `internal/pipeline` (WF1's stage registry is merged; keep to the httpx stage), `internal/changes` (slow / unresponsive), the new migration, `api/openapi.yaml` (services/hosts schema), the host page.
- **Done when:**
  - unit tests with a recorded httpx JSON line that carries `time`;
  - a lab run with `toxic latency 3000` shows ~3000 ms and "slow" on `10.77.2.10:80`, and `toxic timeout` shows `http_unresponsive` on `10.77.2.11:8666`;
  - viewer/admin UI check;
  - `make check` is green.
- **As built:**
  - `http_observations.response_ms` (ms, rounded; NULL when unknown); httpx runs with `-timeout 10`;
  - slow = at least **2000 ms**, or at least **3×** the previous observation's and at least 500 ms (`httpx.Slow`);
  - `GET /api/hosts/{ip}` → `http[].response_ms`, `http[].slow` (against the URL's previous observation); `GET /api/services` → `response_ms`, `slow` (slowest URL of the service's latest HTTP run); the host page shows "Response time" and a SLOW badge;
  - run stats `http_slow` and `http_unresponsive` (open port that answered HTTP in the profile's previous finished run and not in this one); Changes fields `slow` (became slow) and `http_unresponsive`, counted in `summary.services_slow` / `summary.services_http_unresponsive`;
  - lab results (profile with `10.77.2.0/24`, ports `80,8080,8474,8666`): baseline 32–40 ms on 10.77.2.10:80; `latency 3000` → 3033 ms, `slow` on 10.77.2.10:80 and 10.77.2.11:8666, run stats `http_slow: 2`, run 47 s → 69 s; `timeout` → 10.77.2.11:8666 `http_unresponsive` (port open), run 125 s; clear → 40 ms, nothing slow;
  - deviation from §4 step 7: under `timeout`, nmap's probes to Traefik :80 hang, so nmap names it `https` and httpx probes `https://10.77.2.10:80` (Traefik 404 in 3 ms) instead of getting the 502; Changes shows name/product/version/title/technologies changed there, not `http_unresponsive`.

### V8 — Aggressive stages on the vuln lab

- **Goal:** after AG2–AG5:
  - a `walk-aggressive` addition to the scenario docs (not the script's default `walk`) in which an **admin** creates `vuln-lab-aggressive` in the UI, limited to `10.77.3.10/32` and `10.77.3.14/32`;
  - starts it with the confirmation;
  - records the nuclei-active, nikto, wpscan (WordPress 4.7.5 version, plugins and themes, no passwords, no API token) and ZAP results in Dojo.
- **Owns:** a new "Aggressive scenario" section in this document, and `lab/vuln/scenario/aggressive.md` if needed.
- **Done when:**
  - the four tools' Tests exist on those two Assets only;
  - the audit_log entries and the badge are visible;
  - no other address got aggressive traffic (the run's target count = 2).
