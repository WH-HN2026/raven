# Scale testing (16k–65k hosts)

`make test-scale` exercises the full scan pipeline, River job queues, Postgres ingest, DefectDojo push, lifecycle re-probing, change detection, and read APIs at **16,384 IPs (`/18`)** and **65,536 IPs (`/16`)** without touching the network or the shared DefectDojo instance.

## Harness design & zero-network guarantee

The load test lives in [`internal/scaletest/`](../internal/scaletest/) behind the `//go:build scaletest` build tag:

- **Impossible to select in production:** none of the fake scanners compile into `cmd/raven` or normal `make check` builds.
- **No external scanner traffic:** `FakeNmap`, `FakeHTTPX`, and `FakeNuclei` implement `scanner.Scanner` in-process with deterministic synthetic results (~30% of IPs up, 1–5 TCP services each, HTTP/HTTPS headers/cookies/TLS/technologies, ~15% nuclei matches, valid nmap XML / httpx JSONL / nuclei JSONL accepted by the real parsers). Scaled-down per-IP delays keep batch `duration_ms > 0` so S5 adaptive batching exercises its real throughput estimator (Run 1 uses `DefaultBatchSize = 256`, Run 2 adapts up to `MaxBatchSize = 4096`).
- **No outbound DNS:** `pipeline.Config.Resolver` is `LocalOnlyResolver`, which blocks any DNS lookup.
- **Loopback-only Dojo stub:** `FakeDojo` is an `httptest.Server` bound to `127.0.0.1` implementing the DefectDojo 3.5 API v2 endpoints used by `dojo.Pusher` and counting requests/reimports without retaining uploaded payloads.
- **Isolated throwaway DB:** `freshScaleDB` reads `RAVEN_DATABASE_URL` (from `scripts/wt-env.sh`), refuses non-loopback hosts or the shared `raven`/`asi` DB name, creates a throwaway `raven_scale_<rand>` database, runs migrations, and drops it on cleanup.

## Bottlenecks found and fixed

1. **7.7 GB heap blowup & O(N²) CPU in `nmap.perIP` (`internal/scanner/nmap/parse.go`):**
   `perIP` previously called `b.Grow(len(raw))` (~1.7 MB for a 4,096-IP batch) and scanned all spans on every responding IP. Because `dojo.PushService.load` retains all per-IP reports in a batch slice, Run 2 (when S5 adaptive batching reached 4,096 IPs/batch) spiked live heap from **85 MB to 7,706 MB** (`8,285 MB` Sys). Precomputing an O(1) IP → span map and the non-host XML envelope once per `Parse` drops `perIP` allocations to exact size (~1.5 KB/IP) and cuts Run 2 peak heap to **93 MB** (**83× lower**).
2. **`GET /api/dashboard` (2.60 s) and `GET /api/changes` (2.32 s) exceeded the 1 s target at 65k hosts:**
   - `changes.LoadSnapshot` decrypted (`pgcrypto`) and XML-parsed every nmap artifact of both runs (~60 MB XML across 272 rows) on every request. Migration `20261121164234_scale_indexes_and_obs_fp.sql` adds plaintext `run_observations.service_fp jsonb` (populated in `pipeline.Ingest`), so `LoadSnapshot` reads per-run fingerprints directly and falls back to artifacts only for legacy/seeded runs lacking `service_fp`.
   - `changes.Diff` called `Snapshot.ports(ip)` inside a loop over all changed hosts, scanning all ~60k services per new/gone host (`O(changed_hosts × total_services)`). Replaced with a single-pass `portsFor` index.
   - Added missing indexes on `http_observations(run_id)`, `http_observations(service_id, url, observed_at DESC, id DESC)`, `hosts(first_seen DESC, ip)`, `run_observations(ip, run_id DESC) WHERE port IS NULL`, `services(port, ip) WHERE state = 'open'`, and `artifacts(batch_id, scanner, id DESC)`.
3. **Deep-page host pagination (`GET /api/hosts?offset=5000` = 103 ms):**
   `internal/hosts/filter.go` previously evaluated the three correlated subqueries (`open_services`, `open_ports`, `technologies`) before applying `LIMIT`/`OFFSET`. Paginating inside a subquery first evaluates them only for the 50 returned rows, dropping deep-page latency from **103 ms to 4.5 ms** (**23× faster**).
4. **Per-row N+1 SQL writes in pipeline ingest and Dojo push:**
   Converted per-host/per-service/per-HTTP/per-nuclei/per-asset loops (`UpsertScannedHosts`, `UpsertScannedServices`, `InsertHTTPObservations`, `RecordNucleiMatchesBatch`, `MergeNucleiTechnologiesBatch`, `SetHostDojoAssets`) to bulk `unnest(...)` SQL statements, cutting Run 1 batch execution sum from **16.5 s to 6.6 s** (**2.5× faster**).
5. **Dojo HTTP client connection churn and uncached `test_types` (`internal/dojo/http.go`):**
   Using the default `http.Transport` (`MaxIdleConnsPerHost = 2`) caused socket churn under concurrent pushes, and `GetOrCreateTest` queried `/api/v2/test_types/` on every test creation (~76k redundant GETs on Run 1). Sizing `MaxIdleConnsPerHost` to concurrency and caching `test_types` IDs eliminated 75,936 HTTP calls and cut post-scan Dojo queue drain at 65k hosts from **18.1 s to 0.30 s**.

## Measurements (before vs after)

Measured on the local dev machine (Postgres 18 in Docker on `127.0.0.1:5433`, 2 scan workers, 8 Dojo HTTP client concurrency, ~30% hosts up, 1–5 services/host, ~5% hosts changed on Run 2).

### 65,536 IPs (`10.65.0.0/16`: ~19.7k–20.3k up hosts, ~60k open services, ~77k HTTP observations, ~250k run observations)

| Metric | Before | After | Change |
|---|---:|---:|---:|
| Run 1 plan (`StartRun`) | 80 ms | 83 ms | ~same |
| Run 1 scan + ingest + lifecycle (256 × 256 IPs) | 33.71 s | 24.72 s | 1.4× faster |
| Run 1 Dojo drain after scan | 18.06 s | 0.30 s | **60× faster** |
| Run 1 total | 51.85 s | 25.11 s | **2.1× faster** |
| Run 1 Dojo HTTP requests | 382,413 | 306,477 | −75,936 reqs |
| Run 2 plan (`StartRun`, S5 adaptive → 4,096 IPs/batch) | 54 ms | 38 ms | 1.4× faster |
| Run 2 scan + ingest + re-probe + lifecycle (16 × 4,096 IPs) | 29.57 s | 19.92 s | 1.5× faster |
| Run 2 Dojo drain after scan | 20.80 s | 0.51 s | **41× faster** |
| Run 2 total | 50.42 s | 20.46 s | **2.5× faster** |
| Run 2 peak heap alloc | **7,705.9 MB** | **93.0 MB** | **82.9× lower** |
| Run 2 peak sys memory | 8,284.9 MB | 294.7 MB | **28.1× lower** |
| DB size after Run 1 / Run 2 | 117.6 / 216.8 MB | 133.8 / 256.4 MB | +18% (indexes + `service_fp`) |
| `GET /api/hosts?limit=50&offset=0` | 4.7 ms | 5.4 ms | < 10 ms |
| `GET /api/hosts?limit=50&offset=5000` | 103.0 ms | **4.5 ms** | **22.9× faster** |
| `GET /api/hosts?state=active&limit=50` | 3.0 ms | 2.9 ms | < 5 ms |
| `GET /api/hosts?state=unstable&limit=50` | 1.5 ms | 2.3 ms | < 5 ms |
| `GET /api/hosts?port=443&limit=50` | 11.8 ms | 15.6 ms | < 20 ms |
| `GET /api/hosts?tech=Nginx:1.24.0&limit=50` | 79.0 ms | 81.3 ms | < 100 ms |
| `GET /api/hosts?q=10.65.0.0/24&limit=50` | 1.6 ms | 1.7 ms | < 5 ms |
| `GET /api/hosts?q=srv-10-65-10-&limit=50` | 15.3 ms | 15.1 ms | < 20 ms |
| `GET /api/hosts/{ip}` | 3.5 ms | 4.2 ms | < 5 ms |
| `GET /api/dashboard` | **2,596.1 ms** | **498.4 ms** | **5.2× faster** |
| `GET /api/changes` | **2,322.3 ms** | **308.6 ms** | **7.5× faster** |
| `GET /api/changes/hosts/{ip}` | 1.5 ms | 1.1 ms | < 5 ms |

### 16,384 IPs (`10.64.0.0/18`: ~4.9k–5.1k up hosts, ~14.9k open services)

| Metric | Before | After | Change |
|---|---:|---:|---:|
| Run 1 total (64 × 256 IPs) | 13.13 s | 6.59 s | **2.0× faster** |
| Run 2 total (4 × 4,096 IPs) | 13.72 s | 4.96 s | **2.8× faster** |
| Run 2 peak heap alloc | **3,735.9 MB** | **67.9 MB** | **55× lower** |
| DB size after Run 2 | 61.6 MB | 69.9 MB | +13% |
| `GET /api/hosts?limit=50&offset=5000` | 95.4 ms | **3.2 ms** | **29.8× faster** |
| `GET /api/dashboard` | 473.9 ms | **108.1 ms** | **4.4× faster** |
| `GET /api/changes` | 502.9 ms | **73.4 ms** | **6.9× faster** |

## Running

```bash
make infra-up
scripts/wt-env.sh
make test-scale
```
