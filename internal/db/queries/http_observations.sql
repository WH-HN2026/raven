-- name: InsertHTTPObservation :execrows
INSERT INTO http_observations (
    service_id, url, status, title, headers_enc, cookies_enc, tls_cert_enc,
    redirects, technologies, favicon_hash, run_id, observed_at
)
SELECT id, @url, @status, @title, asi_enc(@headers::text), asi_enc(@cookies::text),
       asi_enc(NULLIF(@tls_cert::text, '')), @redirects, @technologies, @favicon_hash,
       @run_id, @observed_at
FROM services
WHERE ip = @ip AND port = @port AND proto = 'tcp';
