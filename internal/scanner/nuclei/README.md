# Nuclei fingerprinting policy

Profiles select from `tech`, `panel`, `ssl`, `waf` and `favicon`. Each tag selects only the reviewed files listed in [templates.go](templates.go). The hashes identify the exact payloads from the template release pinned in the Dockerfile. Updating the release requires checking changes to those files and updating their hashes.

Nuclei receives only the live literal-IP HTTP(S) origins from this batch's httpx output. Nuclei 3.11 has no per-IP allow flag. Hostname URLs remain in httpx observations. Redirects, automatic probing, update checks, OAST and cloud authentication are disabled. The TLS templates only receive confirmed HTTPS origins.

The official template root defaults to `/opt/nuclei-templates`. Set the existing `RAVEN_NUCLEI_TEMPLATES` environment variable on the RAVEN process to point to another copy of the pinned templates. Enabled C2 signatures and optional top-level YAML files from `/opt/raven-signatures` go through the C2 validator before staging in an isolated directory. They run in a separate HTTP pass, even when the profile has no eligible official tags. The same protocol and tag exclusions and rate limit apply to every pass.

Scanner failures are logged with the batch ID. The pipeline can still commit successful nmap and httpx results. A successful nuclei pass records an encrypted artifact even when it finds no matches. HTTP technologies are merged into `http_observations`, and all match metadata is recorded on the service's `run_observations` row. Extracted values are encrypted in matching array order, and complete matched URLs remain in the encrypted JSONL artifact.

## Aggressive `nuclei_active` mode (AG2)

`NewActive` provides the opt-in `nuclei_active` stage for admin-configured Aggressive profiles (architecture §3.11, §9).

- **Template set:** pinned official `nuclei-templates` (`v10.5.2`, tarball SHA-256 `016b7abbf931d4d1a851a5a568e44510dc61691dc8a5202e3b24e701515ec574`, `templates-checksum.txt` SHA-256 `19efd0802f1b22142dea2607e4f863ccf2c2b523a804ac2fda556883478e986f`). Only curated HTTP subdirectories (`http/cves`, `http/exposures`, `http/misconfiguration`, `http/vulnerabilities`, `http/fuzzing`, `http/exposed-panels`, `http/technologies`) are passed via `-t`, excluding `token-spray`, `osint`, `default-logins`, `credential-stuffing`, `takeovers`, `honeypot`, and crawler-dependent `dast` packs.
- **Tag allowlist (`-tags`):** `cve,exposure,misconfig,tech,panel,sqli,xss,lfi,ssrf,xxe,traversal,injection,intrusive,fuzz`.
- **Mandatory exclusions (`-etags` / `-exclude-type`):** `dos,bruteforce,default-login,credential,oast,rce,deserialization,file-upload,token-spray,osint,takeover,login`; types `code,headless,javascript`; `-no-interactsh`, `-disable-update-check`, `-duc`, `-auth=false`, `-no-httpx`, `-disable-redirects`.
- **Limits:** rate limit (`-rl`) from the profile's `nuclei_rate`, `-timeout 5`, `-retries 0`, `-mhe 30`, and a hard per-URL `context.WithTimeout` cap (`DefaultActivePerURLTimeout`). Custom signatures are not re-run in this stage.
- **DefectDojo:** pushed per responding IP to a separate Test titled `RAVEN: nuclei_active` (scan type `Nuclei Scan`) and mirrored with `scanner = "nuclei_active"`.
