-- name: RecordNucleiMatches :execrows
UPDATE run_observations
SET nuclei_matches = @matches::jsonb,
    nuclei_evidence_enc = asi_enc(@evidence::text)
WHERE run_id = @run_id AND ip = @ip AND port = @port AND up;

-- name: MergeNucleiTechnologies :execrows
UPDATE http_observations AS h
SET technologies = ARRAY(
    SELECT DISTINCT tech FROM unnest(h.technologies || @technologies::text[]) AS tech ORDER BY tech
)
FROM services AS s
WHERE h.service_id = s.id AND s.ip = @ip AND s.port = @port AND s.proto = 'tcp'
    AND h.run_id = @run_id AND h.url = @url;
