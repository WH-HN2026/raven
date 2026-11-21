-- Hosts read path (W3). The filtered list query is built in internal/hosts
-- (filters are optional); these are the detail queries. Encrypted columns are
-- decrypted here with raven_dec and must never be logged.

-- name: GetHost :one
SELECT ip, hostnames, state, first_seen, last_seen, miss_count, dojo_asset_id,
    owner, criticality, COALESCE(raven_dec(notes_enc), '')::text AS notes, user_tags, overrides
FROM hosts WHERE ip = @ip;

-- name: ListHostServices :many
-- Open services first, then gone ones; by port.
SELECT id, ip, port, proto, name, product, version, cpe,
    COALESCE(raven_dec(banner_enc), '')::text AS banner,
    state, first_seen, last_seen, overrides
FROM services WHERE ip = @ip
ORDER BY state = 'gone', port, proto;

-- name: ListLatestHTTPObservations :many
-- The latest observation per (service, URL) of one host.
SELECT DISTINCT ON (o.service_id, o.url)
    o.id, o.service_id, o.url, o.status, o.title,
    COALESCE(raven_dec(o.headers_enc), '')::text AS headers,
    COALESCE(raven_dec(o.cookies_enc), '')::text AS cookies,
    COALESCE(raven_dec(o.tls_cert_enc), '')::text AS tls_cert,
    o.redirects, o.technologies, o.favicon_hash, o.run_id, o.observed_at
FROM http_observations o
JOIN services s ON s.id = o.service_id
WHERE s.ip = @ip
ORDER BY o.service_id, o.url, o.observed_at DESC, o.id DESC;

-- name: ListHostRunObservations :many
-- Host-level up/down rows (port IS NULL), newest first.
SELECT run_id, up, observed_at FROM run_observations
WHERE ip = @ip AND port IS NULL
ORDER BY observed_at DESC, run_id DESC
LIMIT @max_rows;
