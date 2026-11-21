-- name: RecordNucleiMatches :execrows
UPDATE run_observations
SET nuclei_matches = @matches::jsonb,
    nuclei_evidence_enc = raven_enc(@evidence::text)
WHERE run_id = @run_id AND ip = @ip AND port = @port AND up;

-- name: RecordNucleiMatchesBatch :execrows
UPDATE run_observations AS ro
SET nuclei_matches = m.matches::jsonb,
    nuclei_evidence_enc = raven_enc(m.evidence)
FROM (
    SELECT unnest(@ips::inet[]) AS ip,
           unnest(@ports::int[]) AS port,
           unnest(@matches::text[]) AS matches,
           unnest(@evidences::text[]) AS evidence
) AS m
WHERE ro.run_id = @run_id AND ro.ip = m.ip AND ro.port = m.port AND ro.up;

-- name: MergeNucleiTechnologies :execrows
UPDATE http_observations AS h
SET technologies = ARRAY(
    SELECT DISTINCT tech FROM unnest(h.technologies || @technologies::text[]) AS tech ORDER BY tech
)
FROM services AS s
WHERE h.service_id = s.id AND s.ip = @ip AND s.port = @port AND s.proto = 'tcp'
    AND h.run_id = @run_id AND h.url = @url;

-- name: MergeNucleiTechnologiesBatch :execrows
UPDATE http_observations AS h
SET technologies = ARRAY(
    SELECT DISTINCT tech
    FROM unnest(h.technologies || COALESCE(ARRAY(SELECT jsonb_array_elements_text(m.technologies::jsonb)), '{}'::text[])) AS tech
    ORDER BY tech
)
FROM (
    SELECT unnest(@ips::inet[]) AS ip,
           unnest(@ports::int[]) AS port,
           unnest(@urls::text[]) AS url,
           unnest(@technologies_json::text[]) AS technologies
) AS m
JOIN services AS s ON s.ip = m.ip AND s.port = m.port AND s.proto = 'tcp'
WHERE h.service_id = s.id AND h.run_id = @run_id AND h.url = m.url;

-- name: MergeNucleiCPEs :execrows
UPDATE http_observations AS h
SET cpes = ARRAY(
    SELECT DISTINCT c FROM unnest(h.cpes || @cpes::text[]) AS c ORDER BY c
)
FROM services AS s
WHERE h.service_id = s.id AND s.ip = @ip AND s.port = @port AND s.proto = 'tcp'
    AND h.run_id = @run_id AND h.url = @url;

-- name: MergeNucleiCPEsBatch :execrows
UPDATE http_observations AS h
SET cpes = ARRAY(
    SELECT DISTINCT c
    FROM unnest(h.cpes || COALESCE(ARRAY(SELECT jsonb_array_elements_text(m.cpes::jsonb)), '{}'::text[])) AS c
    ORDER BY c
)
FROM (
    SELECT unnest(@ips::inet[]) AS ip,
           unnest(@ports::int[]) AS port,
           unnest(@urls::text[]) AS url,
           unnest(@cpes_json::text[]) AS cpes
) AS m
JOIN services AS s ON s.ip = m.ip AND s.port = m.port AND s.proto = 'tcp'
WHERE h.service_id = s.id AND h.run_id = @run_id AND h.url = m.url;
