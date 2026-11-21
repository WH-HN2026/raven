-- Offline CVE matching (task C3, architecture §11).

-- name: ListCVECandidates :many
-- Open services with something to identify the product by. The banner is
-- only used for distro detection and never logged.
SELECT s.ip, s.port, s.proto, s.cpe, s.product, s.version,
       COALESCE(raven_dec(s.banner_enc), '')::text AS banner
FROM services s
WHERE s.state = 'open' AND (s.cpe <> '' OR s.product <> '')
ORDER BY s.ip, s.port, s.proto;

-- name: ListHTTPTechCVECandidates :many
-- Latest HTTP observations per (service, URL) on open services, carrying mapped CPEs and raw technologies.
SELECT DISTINCT ON (ho.service_id, ho.url)
    s.ip, s.port, s.proto, ho.cpes, ho.technologies
FROM http_observations ho
JOIN services s ON s.id = ho.service_id
WHERE s.state = 'open'
  AND (cardinality(ho.cpes) > 0 OR cardinality(ho.technologies) > 0)
ORDER BY ho.service_id, ho.url, ho.observed_at DESC, ho.id DESC;

-- name: ListNucleiCVECandidates :many
-- Latest nuclei matches per open service for CPE+version CVE matching.
SELECT DISTINCT ON (ro.ip, ro.port)
    s.ip, s.port, s.proto, ro.nuclei_matches
FROM run_observations ro
JOIN services s ON s.ip = ro.ip AND s.port = ro.port AND s.proto = 'tcp'
WHERE s.state = 'open'
  AND ro.up
  AND ro.port IS NOT NULL
  AND ro.nuclei_matches <> '[]'::jsonb
ORDER BY ro.ip, ro.port, ro.observed_at DESC;

-- name: UpsertCVEMatch :exec
INSERT INTO cve_matches (ip, port, proto, product, cpe, version, cve_ids, hits, max_cvss, kev,
                         distro, confidence, severity, matched_at, updated_at)
VALUES (@ip, @port, @proto, @product, @cpe, @version, @cve_ids, @hits, @max_cvss, @kev,
        @distro, @confidence, @severity, @now, @now)
ON CONFLICT (ip, port, proto, cpe) DO UPDATE SET
    matched_at = CASE WHEN cve_matches.version = EXCLUDED.version
                      THEN cve_matches.matched_at ELSE EXCLUDED.matched_at END,
    product = EXCLUDED.product, version = EXCLUDED.version,
    cve_ids = EXCLUDED.cve_ids, hits = EXCLUDED.hits, max_cvss = EXCLUDED.max_cvss,
    kev = EXCLUDED.kev, distro = EXCLUDED.distro, confidence = EXCLUDED.confidence,
    severity = EXCLUDED.severity, updated_at = EXCLUDED.updated_at;

-- name: DeleteStaleCVEMatches :execrows
-- Rows the pass at @now didn't produce: the service is gone or no longer matches.
DELETE FROM cve_matches WHERE updated_at < @now;

-- name: ListCVEMatches :many
SELECT * FROM cve_matches
WHERE (sqlc.narg(ip)::inet IS NULL OR ip = sqlc.narg(ip)::inet)
ORDER BY max_cvss DESC, ip, port, cpe;

-- name: ListCVEPushHosts :many
-- Active hosts that have matches or had some pushed before; the caller
-- compares the hash to decide whether to push. Only active (responding)
-- hosts are ever reimported (§3.7).
SELECT h.ip, h.hostnames, COALESCE(p.hash, '')::text AS pushed_hash, (p.ip IS NOT NULL)::bool AS pushed,
       COALESCE((SELECT pr.name FROM run_observations o
                 JOIN runs r ON r.id = o.run_id JOIN profiles pr ON pr.id = r.profile_id
                 WHERE o.ip = h.ip AND o.up ORDER BY o.observed_at DESC LIMIT 1), '')::text AS profile
FROM hosts h
LEFT JOIN cve_push p ON p.ip = h.ip
WHERE h.state = 'active'
  AND (p.ip IS NOT NULL OR EXISTS (SELECT 1 FROM cve_matches m WHERE m.ip = h.ip))
ORDER BY h.ip;

-- name: SetCVEPushed :exec
INSERT INTO cve_push (ip, hash, pushed_at) VALUES (@ip, @hash, @pushed_at)
ON CONFLICT (ip) DO UPDATE SET hash = EXCLUDED.hash, pushed_at = EXCLUDED.pushed_at;
