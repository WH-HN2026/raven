-- name: InsertHTTPObservation :execrows
INSERT INTO http_observations (
    service_id, url, status, title, headers_enc, cookies_enc, tls_cert_enc,
    redirects, technologies, favicon_hash, run_id, observed_at
)
SELECT id, @url, @status, @title, raven_enc(@headers::text), raven_enc(@cookies::text),
       raven_enc(NULLIF(@tls_cert::text, '')), @redirects, @technologies, @favicon_hash,
       @run_id, @observed_at
FROM services
WHERE ip = @ip AND port = @port AND proto = 'tcp';

-- name: InsertHTTPObservations :execrows
INSERT INTO http_observations (
    service_id, url, status, title, headers_enc, cookies_enc, tls_cert_enc,
    redirects, technologies, favicon_hash, run_id, observed_at
)
SELECT s.id, o.url, o.status, o.title,
       raven_enc(o.headers), raven_enc(o.cookies), raven_enc(NULLIF(o.tls_cert, '')),
       o.redirects::jsonb,
       COALESCE(ARRAY(SELECT jsonb_array_elements_text(o.technologies::jsonb)), '{}'::text[]),
       o.favicon_hash, @run_id, o.observed_at
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
           unnest(@favicon_hashes::text[]) AS favicon_hash,
           unnest(@observed_ats::timestamptz[]) AS observed_at
) AS o
JOIN services s ON s.ip = o.ip AND s.port = o.port AND s.proto = 'tcp';
