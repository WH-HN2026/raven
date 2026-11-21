-- +goose Up
-- Q2 scale fixes:
--   - store plaintext per-run service fingerprints on run_observations so
--     GET /api/changes and GET /api/dashboard do not decrypt and re-parse every
--     nmap XML artifact on each request;
--   - add missing indexes for dashboard, changes, hosts, lifecycle and Dojo push.
ALTER TABLE run_observations ADD COLUMN service_fp jsonb;

CREATE INDEX http_observations_run_id_idx ON http_observations(run_id) WHERE run_id IS NOT NULL;
CREATE INDEX http_observations_latest_idx ON http_observations(service_id, url, observed_at DESC, id DESC);
CREATE INDEX hosts_first_seen_idx ON hosts(first_seen DESC, ip);
CREATE INDEX run_observations_host_timeline_idx ON run_observations(ip, run_id DESC) WHERE port IS NULL;
CREATE INDEX services_open_port_ip_idx ON services(port, ip) WHERE state = 'open';
CREATE INDEX artifacts_batch_scanner_idx ON artifacts(batch_id, scanner, id DESC) WHERE batch_id IS NOT NULL;

-- +goose Down
DROP INDEX artifacts_batch_scanner_idx;
DROP INDEX services_open_port_ip_idx;
DROP INDEX run_observations_host_timeline_idx;
DROP INDEX hosts_first_seen_idx;
DROP INDEX http_observations_latest_idx;
DROP INDEX http_observations_run_id_idx;
ALTER TABLE run_observations DROP COLUMN service_fp;
