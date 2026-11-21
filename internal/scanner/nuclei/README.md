# Nuclei fingerprinting policy

Profiles select from `tech`, `panel`, `ssl`, `waf` and `favicon`. Each tag selects only the reviewed files listed in [templates.go](templates.go). The hashes identify the exact payloads from the template release pinned in the Dockerfile. Updating the release requires checking changes to those files and updating their hashes.

Nuclei receives only the live literal-IP HTTP(S) origins from this batch's httpx output. Nuclei 3.11 has no per-IP allow flag. Hostname URLs remain in httpx observations. Redirects, automatic probing, update checks, OAST and cloud authentication are disabled. The TLS templates only receive confirmed HTTPS origins.

The official template root defaults to `/opt/nuclei-templates`. Set the existing `RAVEN_NUCLEI_TEMPLATES` environment variable on the RAVEN process to point to another copy of the pinned templates. Enabled C2 signatures and optional top-level YAML files from `/opt/raven-signatures` go through the C2 validator before staging in an isolated directory. They run in a separate HTTP pass, even when the profile has no eligible official tags. The same protocol and tag exclusions and rate limit apply to every pass.

Scanner failures are logged with the batch ID. The pipeline can still commit successful nmap and httpx results. A successful nuclei pass records an encrypted artifact even when it finds no matches. HTTP technologies are merged into `http_observations`, and all match metadata is recorded on the service's `run_observations` row. Extracted values are encrypted in matching array order, and complete matched URLs remain in the encrypted JSONL artifact.
