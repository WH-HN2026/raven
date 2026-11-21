-- name: InsertHTTPObservation :execrows
INSERT INTO http_observations (
    service_id, url, status, title, headers_enc, cookies_enc, tls_cert_enc,
    redirects, technologies, cpes, favicon_hash, run_id, observed_at
)
SELECT id, @url, @status, @title, raven_enc(@headers::text), raven_enc(@cookies::text),
       raven_enc(NULLIF(@tls_cert::text, '')), @redirects, @technologies, @cpes, @favicon_hash,
       @run_id, @observed_at
FROM services
WHERE ip = @ip AND port = @port AND proto = 'tcp';

-- name: InsertHTTPObservations :execrows
INSERT INTO http_observations (
    service_id, url, status, title, headers_enc, cookies_enc, tls_cert_enc,
    redirects, technologies, cpes, favicon_hash, response_ms, run_id, observed_at
)
SELECT s.id, o.url, o.status, o.title,
       raven_enc(o.headers), raven_enc(o.cookies), raven_enc(NULLIF(o.tls_cert, '')),
       o.redirects::jsonb,
       COALESCE(ARRAY(SELECT jsonb_array_elements_text(o.technologies::jsonb)), '{}'::text[]),
       COALESCE(ARRAY(SELECT jsonb_array_elements_text(o.cpes::jsonb)), '{}'::text[]),
       o.favicon_hash, NULLIF(o.response_ms, -1), @run_id, o.observed_at
FROM (
    SELECT unnest(@ips::inet[]) AS ip,
           unnest(@ports::int[]) AS port,
           unnest(@urls::text[]) AS url,
           unnest(@statuses::int[]) AS status,
           unnest(@titles::text[]) AS title,
           unnest(@headers::text[]) AS headers,
           unnest(@cookies::text[]) AS cookies,
           unnest(@tls_certs::text[]) AS tls_cert,
           unnest(@redirects::text[]) AS redirects,
           unnest(@technologies_json::text[]) AS technologies,
           unnest(@cpes_json::text[]) AS cpes,
           unnest(@favicon_hashes::text[]) AS favicon_hash,
           unnest(@response_ms::int[]) AS response_ms, -- -1 = unknown
           unnest(@observed_ats::timestamptz[]) AS observed_at
) AS o
JOIN services s ON s.ip = o.ip AND s.port = o.port AND s.proto = 'tcp';

-- name: BackfillServiceCPE :exec
-- Only fills services.cpe when nmap did not report one; never overwrites nmap or user overrides.
UPDATE services
SET cpe = @cpe
WHERE ip = @ip AND port = @port AND proto = 'tcp' AND cpe = '';

-- name: RunHTTPResponses :many
-- V7: per open service of a run, whether httpx answered in this run and in the
-- previous finished run of the same profile, and the slowest URL's response
-- time in each (-1 if unknown).
WITH prev AS (
    SELECT r.id FROM runs r, runs t
    WHERE t.id = @run_id AND r.profile_id = t.profile_id AND r.status = 'done' AND r.id <> t.id
      AND (COALESCE(r.started_at, '-infinity'::timestamptz), r.id)
          < (COALESCE(t.started_at, '-infinity'::timestamptz), t.id)
    ORDER BY r.started_at DESC NULLS LAST, r.id DESC LIMIT 1
)
SELECT c.ip, c.port::int AS port,
    COALESCE(bool_or(o.run_id = @run_id), false)::bool AS cur_http,
    COALESCE(max(o.response_ms) FILTER (WHERE o.run_id = @run_id), -1)::int AS cur_ms,
    COALESCE(bool_or(o.run_id <> @run_id), false)::bool AS prev_http,
    COALESCE(max(o.response_ms) FILTER (WHERE o.run_id <> @run_id), -1)::int AS prev_ms
FROM run_observations c
JOIN services s ON s.ip = c.ip AND s.port = c.port AND s.proto = 'tcp'
JOIN http_observations o ON o.service_id = s.id
WHERE c.run_id = @run_id AND c.port IS NOT NULL AND c.up
  AND (o.run_id = @run_id OR o.run_id = (SELECT id FROM prev))
GROUP BY c.ip, c.port;
