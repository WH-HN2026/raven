-- Ingest of one batch (S3). Only scan-owned columns are written here; owner,
-- criticality, notes_enc, user_tags and overrides belong to user edits.

-- name: UpsertScannedHosts :exec
INSERT INTO hosts (ip, hostnames, state, first_seen, last_seen)
SELECT x.ip,
       COALESCE(ARRAY(SELECT jsonb_array_elements_text(x.hostnames::jsonb)), '{}'::text[]),
       'active', @seen, @seen
FROM (
    SELECT unnest(@ips::inet[]) AS ip,
           unnest(@hostnames_json::text[]) AS hostnames
) AS x
ON CONFLICT (ip) DO UPDATE SET
    hostnames = ARRAY(SELECT DISTINCT h FROM unnest(hosts.hostnames || EXCLUDED.hostnames) AS h ORDER BY h),
    state = 'active',
    miss_count = 0,
    last_seen = EXCLUDED.last_seen;

-- name: UpsertScannedServices :exec
INSERT INTO services (ip, port, proto, name, product, version, cpe, banner_enc, state, first_seen, last_seen)
SELECT s.ip, s.port, s.proto, s.name, s.product, s.version, s.cpe,
       raven_enc(NULLIF(s.banner, '')), 'open', @seen, @seen
FROM (
    SELECT unnest(@ips::inet[]) AS ip,
           unnest(@ports::int[]) AS port,
           unnest(@protos::text[]) AS proto,
           unnest(@names::text[]) AS name,
           unnest(@products::text[]) AS product,
           unnest(@versions::text[]) AS version,
           unnest(@cpes::text[]) AS cpe,
           unnest(@banners::text[]) AS banner
) AS s
ON CONFLICT (ip, port, proto) DO UPDATE SET
    name = EXCLUDED.name,
    product = EXCLUDED.product,
    version = EXCLUDED.version,
    cpe = EXCLUDED.cpe,
    banner_enc = EXCLUDED.banner_enc,
    state = 'open',
    last_seen = EXCLUDED.last_seen;

-- name: ListOpenServicesOf :many
SELECT id, ip, port, proto FROM services
WHERE ip = ANY(@ips::inet[]) AND state = 'open';

-- name: MarkServicesGone :exec
UPDATE services SET state = 'gone' WHERE id = ANY(@ids::bigint[]);

-- name: InsertRunObservations :exec
-- ports: -1 = host-level row (port NULL). service_fps: '' = NULL (host-level or un-fingerprinted).
INSERT INTO run_observations (run_id, ip, port, up, observed_at, service_fp)
SELECT @run_id, o.ip, NULLIF(o.port, -1), o.up, @observed_at, NULLIF(o.service_fp, '')::jsonb
FROM (
    SELECT unnest(@ips::inet[]) AS ip,
           unnest(@ports::int[]) AS port,
           unnest(@ups::boolean[]) AS up,
           unnest(@service_fps::text[]) AS service_fp
) AS o
ON CONFLICT (run_id, ip, COALESCE(port, -1)) DO UPDATE SET
    up = EXCLUDED.up,
    observed_at = EXCLUDED.observed_at,
    service_fp = COALESCE(EXCLUDED.service_fp, run_observations.service_fp);

-- name: InsertArtifact :exec
INSERT INTO artifacts (run_id, batch_id, scanner, content_enc)
VALUES (@run_id, @batch_id, @scanner, raven_enc(@content::text));
