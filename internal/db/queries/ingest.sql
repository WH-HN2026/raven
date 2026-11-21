-- Ingest of one batch (S3). Only scan-owned columns are written here; owner,
-- criticality, notes_enc, user_tags and overrides belong to user edits.

-- name: UpsertScannedHost :exec
INSERT INTO hosts (ip, hostnames, state, first_seen, last_seen)
VALUES (@ip, @hostnames::text[], 'active', @seen, @seen)
ON CONFLICT (ip) DO UPDATE SET
    hostnames = ARRAY(SELECT DISTINCT h FROM unnest(hosts.hostnames || EXCLUDED.hostnames) AS h ORDER BY h),
    state = 'active',
    miss_count = 0,
    last_seen = EXCLUDED.last_seen;

-- name: UpsertScannedService :exec
INSERT INTO services (ip, port, proto, name, product, version, cpe, banner_enc, state, first_seen, last_seen)
VALUES (@ip, @port, @proto, @name, @product, @version, @cpe, raven_enc(NULLIF(@banner::text, '')), 'open', @seen, @seen)
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
-- ports: -1 = host-level row (port NULL).
INSERT INTO run_observations (run_id, ip, port, up, observed_at)
SELECT @run_id, o.ip, NULLIF(o.port, -1), o.up, @observed_at
FROM (SELECT unnest(@ips::inet[]) AS ip, unnest(@ports::int[]) AS port, unnest(@ups::boolean[]) AS up) AS o
ON CONFLICT (run_id, ip, COALESCE(port, -1)) DO UPDATE SET up = EXCLUDED.up, observed_at = EXCLUDED.observed_at;

-- name: InsertArtifact :exec
INSERT INTO artifacts (run_id, batch_id, scanner, content_enc)
VALUES (@run_id, @batch_id, @scanner, raven_enc(@content::text));
