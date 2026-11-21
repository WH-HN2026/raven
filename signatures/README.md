# Built-in signature pack

Safe nuclei templates shipped with ASI (architecture D7, §9). On startup `asi` loads them into the `signatures` table as **built-ins**:
- new templates are inserted, enabled;
- changed ones are updated, keeping the user's enabled/disabled choice;
- removed ones are deleted.

Built-ins can be disabled in the API/UI, but not edited or deleted. A user signature with the same id takes precedence.

Every template passes the safe-subset validator (`internal/signatures/validate.go`):
- http only, GET/HEAD only;
- no body, raw, payloads, fuzzing, auth or interactsh;
- DSL helpers from an allowlist;
- at most 3 redirects and 10 paths.

## Proofs

Each template has a recorded response in `testdata/<id>/`:
- `response.http`: status line, headers and body;
- `body.bin` (optional): a binary body that replaces the one in `response.http`;
- `path.txt` (optional): the request path it answers, default `/`. Other paths get 404.

`testdata/_neutral/` is a plain hardened page (HSTS, CSP, XFO, no cookies, title "Welcome") served on every path.

Two independent checks:

1. **Go harness** (`go test ./internal/signatures/`, part of `make check`). `TestBuiltinPack` validates every template and serves each fixture from an `httptest` server on loopback. A small test-only matcher then checks that the template matches its fixture and does **not** match the neutral one. The matcher covers only word/regex/status and the DSL forms the pack uses (`status_code==N`, favicon `mmh3(base64_py(body))`).
2. **Real nuclei** (`signatures/fixsrv/prove.sh [image]`, needs Docker and the `asi` image). Inside **one container with `--network none`**, the script starts `fixsrv` (the same fixtures on loopback ports) and runs the image's nuclei against every fixture and the neutral page. It expects ≥1 hit and 0 hits. Last run: nuclei v3.11.1, 40/40 passed. `nuclei -validate` also accepts all templates.

Fixture provenance:
- Favicon bodies are the real upstream files:
  - Jenkins `war/src/main/webapp/favicon.ico`;
  - Grafana `public/img/fav32.png`;
  - GitLab `app/assets/images/favicon.png`;
  - phpMyAdmin `public/favicon.ico`;
  - Tomcat `webapps/ROOT/favicon.ico`.

  The Jenkins, phpMyAdmin and Tomcat hashes are the same values nuclei-templates' `favicon-detect.yaml` uses. The Grafana and GitLab hashes are computed from the current upstream files, and older releases may serve a different icon.
- Every other `response.http` is a hand-written reconstruction of the product's typical response: the same headers, title and markers that the official nuclei-templates match on.

When the lab (L1) has the real services, replace the reconstructions with recordings from it.

## Templates

| id | category | severity | matches when | fixture |
|---|---|---|---|---|
| `asi-server-version-header` | headers | info | `Server: product/1.2` | Apache/2.4.49 |
| `asi-x-powered-by-header` | headers | info | any `X-Powered-By` | PHP/7.4.3 |
| `asi-aspnet-version-header` | headers | info | `X-AspNet(Mvc)-Version` | IIS + 4.0.30319 |
| `asi-environment-header` | headers / staging | low | `X-Environment` (or Env/App-Env/Stage) = dev/test/staging/qa/uat… | `X-Environment: staging` |
| `asi-debug-header` | headers | low | `X-Debug-Token(-Link)`, `X-Debug…` | Symfony profiler headers |
| `asi-missing-hsts` | headers | info | 200 HTML without `Strict-Transport-Security` | page with CSP+XFO, no HSTS |
| `asi-missing-csp` | headers | info | 200 HTML without `Content-Security-Policy` | page with HSTS+XFO, no CSP |
| `asi-missing-x-frame-options` | headers | info | 200 HTML without XFO or `frame-ancestors` | page with HSTS+CSP (no frame-ancestors) |
| `asi-cookie-phpsessid` | cookies | info | `Set-Cookie: PHPSESSID=` | Apache/PHP |
| `asi-cookie-jsessionid` | cookies | info | `Set-Cookie: JSESSIONID=` | servlet container |
| `asi-cookie-aspnet-session` | cookies | info | `Set-Cookie: ASP.NET_SessionId=` | IIS |
| `asi-cookie-laravel-session` | cookies | info | `Set-Cookie: laravel_session=` | Laravel (XSRF-TOKEN + session) |
| `asi-cookie-wordpress` | cookies | info | `wordpress_*` / `wp-settings-*` cookie on `/` or `/wp-login.php` | `wordpress_test_cookie` |
| `asi-cookie-missing-secure` | cookies | info | cookies set, none with `Secure` | `sid`, `lang` without Secure |
| `asi-cookie-missing-httponly` | cookies | info | cookies set, none with `HttpOnly` | `session` with Secure only |
| `asi-favicon-jenkins` | favicon | info | mmh3 `81586312` at `/favicon.ico` | real Jenkins favicon |
| `asi-favicon-grafana` | favicon | info | mmh3 `2123863676` at `/public/img/fav32.png` or `/favicon.ico` | real Grafana favicon |
| `asi-favicon-gitlab` | favicon | info | mmh3 `1265477436` at `/favicon.ico` (≤2 redirects) | real GitLab favicon |
| `asi-favicon-phpmyadmin` | favicon | info | mmh3 `-476231906` at `/favicon.ico` or `/phpmyadmin/favicon.ico` | real phpMyAdmin favicon |
| `asi-favicon-tomcat` | favicon | info | mmh3 `-297069493` at `/favicon.ico` | real Tomcat favicon |
| `asi-admin-path` | paths | low | `/admin`, `/admin/`, `/administrator/` → 200 + admin/login title | "Administration - Sign in" |
| `asi-login-page` | paths | info | `/login`, `/signin`, `/user/login` → 200 + password input | login form |
| `asi-wp-admin` | paths | info | `/wp-admin/` → 200/301/302 mentioning `wp-login.php` | 302 to wp-login.php |
| `asi-phpmyadmin-path` | paths | medium | `/phpmyadmin/`, `/phpMyAdmin/`, `/pma/` → `<title>phpMyAdmin` | phpMyAdmin login |
| `asi-tomcat-manager` | paths | medium | `/manager/html` → 401/403 "Tomcat Manager" (no credentials sent) | 401 Basic realm |
| `asi-version-endpoint` | paths | info | `/version`, `/api/version` → JSON `"version":"x.y"` | `{"version":"1.4.2"}` |
| `asi-actuator-health` | paths | low | `/actuator/health` → `"status":"UP"` | Spring Boot Actuator |
| `asi-apache-server-status` | paths | low | `/server-status` → "Apache Server Status for" | mod_status page |
| `asi-staging-title` | staging | low | `<title>` contains staging/test/dev/uat/qa/preprod/sandbox | "ACME Customer Portal - STAGING" |
| `asi-staging-hostname` | staging | low | body links to `staging.`/`dev-`/`uat.`… hosts | `https://staging-api.acme.example` |
| `asi-robots-disallow-all` | staging | info | `/robots.txt` = `User-agent: *` + `Disallow: /` | robots.txt |
| `asi-footer-version` | version | info | `<footer>` with `v1.2` / `version 1.2` | "Helpdesk version 3.2.1" |
| `asi-generator-meta-version` | version | info | `<meta name="generator" content="… 1.2">` | WordPress 6.4.2 |
| `asi-powered-by-version` | version | info | "Powered by … Version: 1.2" | Gitea 1.21.0 footer |
| `asi-printer-title` | IoT | info | printer/MFP title (LaserJet, Brother, Kyocera, Ricoh, Xerox…) | HP Color LaserJet MFP |
| `asi-router-title` | IoT | low | router title (RouterOS, TP-Link, Netgear, OpenWrt/LuCI…) | MikroTik RouterOS |
| `asi-hikvision-camera` | IoT | low | `Server: Hikvision-Webs` or `doc/page/login.asp` | Hikvision redirect page |
| `asi-dahua-camera` | IoT | low | `<title>WEB SERVICE</title>` | Dahua login page |
| `asi-bmc-title` | IoT | medium | BMC title (iDRAC, iLO, Supermicro, IPMI) | iDRAC 9 |
| `asi-fortigate-sslvpn` | IoT / VPN | low | `top.location="/remote/login"` | FortiGate landing page |

## Adding a template

1. Add `signatures/<id>.yaml`. The file name must equal the template `id`.
2. Add `signatures/testdata/<id>/response.http`, plus `path.txt` / `body.bin` if needed.
3. Run `go test ./internal/signatures/`. Optionally run `signatures/fixsrv/prove.sh`.

The test fails on:
- a template without a fixture, or a fixture without a template;
- a template that doesn't match its fixture;
- a template that matches the neutral page;
- a template whose matcher type is outside the harness subset.
