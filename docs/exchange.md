# ASI — Import & Export Formats

ASI supports importing targets and scan results from external tools and exporting normalized views of hosts, services, findings, changes, and targets.

All imports require the `import` permission (`editor` or `admin`), write an `audit_log` entry, enforce upload size limits, and apply the target profile's scope rules plus the **global blacklist** (exclusions always win).

All exports require the `export` permission (every authenticated role, including `viewer`).

---

## 1. Targets (`POST /api/targets/upload`, `GET /api/export/targets`)

Max upload size: **10 MiB** (`targets.MaxUploadBytes`).

### JSON
An array of `{value, kind?, tags?, note?}` objects (`kind` is optional and auto-detected from `value`: `ip`, `cidr`, or `domain`):
```json
[
  {"value": "172.30.0.0/24", "tags": ["lab", "web"], "note": "Local test lab"},
  {"value": "wordpress.lab", "tags": ["cms"]}
]
```

### CSV
Columns `value,tags,note` (header row optional; tags separated by `;` or `|`; blank lines and `#` comments ignored):
```csv
value,tags,note
172.30.0.0/24,lab;web,Local test lab
wordpress.lab,cms,
172.30.0.10
```

---

## 2. Scan Results (`POST /api/import/results`)

Multipart form upload (max **25 MiB**):
- `file` (required): the uploaded file
- `kind` (optional; auto-detected from filename/content if omitted):
  - `results-json` — ASI native scan-results JSON
  - `results-csv` — ASI native scan-results CSV (also accepts exported `services` / `hosts` CSV)
  - `nmap-xml` — raw `nmap -oX` XML
  - `nuclei-jsonl` — raw `nuclei -jsonl` JSON lines
  - `nessus` — Nessus `.nessus` (`NessusClientData_v2` XML)
- `profile` (optional): profile ID or name (defaults to `default`)

Every import creates a completed run (`runs.stats.source = "import"`, `runs.stats.import_kind = "<kind>"`), filters candidate IPs through the profile's include/exclude scope and global blacklist, ingests observations into `hosts`, `services`, `http_observations`, `run_observations`, and encrypted `artifacts`, and triggers DefectDojo push — without running any scanner binary.

### 2.1 ASI Results JSON (`results-json`)

Example fixture: [`internal/exchange/testdata/sample_results.json`](../internal/exchange/testdata/sample_results.json).

```json
{
  "format": "asi-results",
  "version": 1,
  "scanned_at": "2026-11-21T14:00:00Z",
  "hosts": [
    {
      "ip": "172.30.0.10",
      "up": true,
      "hostnames": ["web.lab"],
      "services": [
        {
          "port": 80,
          "proto": "tcp",
          "name": "http",
          "product": "nginx",
          "version": "1.24.0",
          "cpe": "igor_sysoev:nginx:1.24.0",
          "banner": "",
          "http": [
            {
              "url": "http://172.30.0.10:80",
              "status": 200,
              "title": "Welcome to Lab",
              "headers": {"Server": "nginx/1.24.0"},
              "cookies": ["session=abc; HttpOnly"],
              "tls_cert": "",
              "redirects": [],
              "technologies": ["nginx"],
              "favicon_hash": "12345678"
            }
          ],
          "matches": [
            {
              "template_id": "nginx-version-header",
              "name": "Nginx Version Header",
              "severity": "info",
              "tags": ["tech", "nginx"],
              "matcher": "header",
              "url": "http://172.30.0.10:80/",
              "source_url": "http://172.30.0.10:80",
              "tech": "nginx",
              "cpe": "igor_sysoev:nginx",
              "version": "1.24.0",
              "extracted": ["1.24.0"]
            }
          ]
        }
      ]
    }
  ]
}
```

Design notes:
- `version` is currently `1` (omitted defaults to `1`); unknown future fields are ignored for forward compatibility, while `version > 1` is rejected cleanly.
- `up` defaults to `true` if omitted. `proto` defaults to `"tcp"`. `service` is accepted as an alias for `name`.
- A bare JSON array of host objects or exported service objects (`GET /api/export/services?format=json`) is also accepted.
- Sensitive fields (`banner`, `headers`, `cookies`, `tls_cert`, `extracted`, raw upload) are encrypted at rest with `asi_enc`.

### 2.2 ASI Results CSV (`results-csv`)

Example fixture: [`internal/exchange/testdata/sample_results.csv`](../internal/exchange/testdata/sample_results.csv).

Columns are matched case-insensitively by header name (`ip` is required; all other columns are optional; list columns use `;` or `|`):

```csv
ip,up,hostnames,port,proto,name,product,version,cpe,banner,url,http_status,http_title,technologies,favicon_hash,redirects,match_template_id,match_name,match_severity,match_tags,match_matcher,match_url,match_tech,match_extracted
172.30.0.10,true,web.lab,80,tcp,http,nginx,1.24.0,igor_sysoev:nginx:1.24.0,,http://172.30.0.10:80,200,Welcome to Lab,nginx,12345678,,nginx-version-header,Nginx Version Header,info,tech;nginx,header,http://172.30.0.10:80/,nginx,1.24.0
172.30.0.11,true,,22,tcp,ssh,OpenSSH,9.6,openbsd:openssh:9.6,SSH-2.0-OpenSSH_9.6,,,,,,,,,,,,,,
172.30.0.20,false,,,,,,,,,,,,,,,,,,,,,,
```

Multiple rows for the same IP merge into one host; multiple rows for the same `(ip, port, proto)` merge into one service while preserving distinct HTTP observations and matches. Because columns are matched by header name, CSV files produced by `GET /api/export/services?format=csv` or `GET /api/export/hosts?format=csv` can also be re-imported directly.

### 2.3 Raw Scanner Outputs (`nmap-xml`, `nuclei-jsonl`)

- **`nmap-xml`**: parsed with `internal/scanner/nmap.Parse` (same parser as live scans). Populates `hosts`, `services`, `http_observations` (from `http-title`/`http-headers`/`ssl-cert` scripts), `run_observations`, and `artifacts(scanner='nmap')`, and triggers Dojo `"Nmap Scan"` reimport per responding IP.
- **`nuclei-jsonl`**: parsed with `internal/scanner/nuclei.Parse`. Populates `hosts`, `services` (partial import — does not mark other ports gone), `run_observations.nuclei_matches` / `nuclei_evidence_enc`, merges `tech` into `http_observations`, stores raw JSONL in `artifacts(scanner='nuclei')`, and triggers the batch hook with `"Nuclei Scan"`.

### 2.4 Nessus Reports (`nessus`)

Example fixture: [`internal/exchange/testdata/sample.nessus`](../internal/exchange/testdata/sample.nessus).

- Parses `NessusClientData_v2` XML, extracting each `<ReportHost>`'s IP (from `<HostProperties><tag name="host-ip">` or `<ReportHost name="...">`), hostnames, and open ports/services from `<ReportItem>`.
- Filters hosts through the profile's scope and global blacklist, ingests discovered hosts/services into our DB (partial import), stores the raw `.nessus` encrypted in `artifacts(scanner='nessus')`.
- Splits the XML per allowed IP (preserving `<Policy>` and `<Report>` byte-for-byte) and pushes each IP's slice to DefectDojo using the **"Tenable Scan"** parser into Asset `"<ip>"` → Engagement `"ASI: <profile>"` → Test `"ASI: nessus"` (`internal/dojo/nessus.go`).

---

## 3. Exports (`GET /api/export/{kind}?format=json|csv&<filters>`)

| `kind` | Filters (same as list APIs) | JSON shape | CSV columns |
|---|---|---|---|
| `hosts` | `state`, `port`, `tech`, `tag`, `q` | `Host[]` | `ip, hostnames, state, first_seen, last_seen, miss_count, dojo_asset_id, open_service_count, open_ports, technologies, owner, criticality, user_tags` |
| `services` | `port`, `proto`, `state`, `ip`, `product`, `q` | `Service[]` (overrides applied) | `id, ip, port, proto, name, product, version, cpe, state, first_seen, last_seen` |
| `findings` | `severity`, `active`, `ip`, `q`, `scanner` (reads Dojo mirror) | `Finding[]` | `id, asset_id, ip, title, severity, active, verified, false_p, risk_accepted, is_mitigated, tags, scanner, date, dojo_url` |
| `changes` | `from`, `to`, `limit` | `RunDiff` | `from_run_id, to_run_id, category, ip, port, proto, other_run, ports, changed_fields, before_*, after_*` |
| `targets` | — | `Target[]` | `value, tags, note` |
