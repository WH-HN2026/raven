-- Run diff and host timeline (C1). Read-only.

-- name: GetChangeRun :one
SELECT id, profile_id, status, started_at, finished_at, stages FROM runs WHERE id = $1;

-- name: LatestDoneRun :one
-- The newest finished run, of one profile when profile_id is given.
SELECT id, profile_id, status, started_at, finished_at, stages FROM runs
WHERE status = 'done'
  AND (sqlc.narg(profile_id)::bigint IS NULL OR profile_id = sqlc.narg(profile_id)::bigint)
ORDER BY started_at DESC NULLS LAST, id DESC LIMIT 1;

-- name: PreviousDoneRun :one
-- The finished run of the same profile right before run before_id.
SELECT r.id, r.profile_id, r.status, r.started_at, r.finished_at, r.stages FROM runs r
WHERE r.status = 'done' AND r.profile_id = @profile_id
  AND (COALESCE(r.started_at, '-infinity'::timestamptz), r.id)
      < (SELECT COALESCE(t.started_at, '-infinity'::timestamptz), t.id FROM runs t WHERE t.id = @before_id)
ORDER BY r.started_at DESC NULLS LAST, r.id DESC LIMIT 1;

-- name: ListRunObservations :many
-- port -1 = host-level row.
SELECT ip, COALESCE(port, -1)::int AS port, up, service_fp FROM run_observations WHERE run_id = $1;

-- name: ListRunNucleiMatches :many
SELECT ip, port::int AS port, nuclei_matches FROM run_observations
WHERE run_id = $1 AND port IS NOT NULL AND up
  AND nuclei_matches IS NOT NULL AND nuclei_matches <> '[]'::jsonb;

-- name: ListRunNmapArtifacts :many
SELECT raven_dec(content_enc)::text AS content FROM artifacts
WHERE run_id = $1 AND scanner = 'nmap' ORDER BY id;

-- name: ListRunHTTPObservations :many
SELECT s.ip, s.port, s.proto, o.url, o.title, o.technologies
FROM http_observations o JOIN services s ON s.id = o.service_id
WHERE o.run_id = $1
ORDER BY s.ip, s.port, s.proto, o.url, o.observed_at DESC;

-- name: HostTimelineRuns :many
-- The last N runs that observed this IP, newest first, with its host-level state.
SELECT r.id, r.profile_id, r.status, r.started_at, r.finished_at, r.stages, o.up, o.observed_at
FROM run_observations o JOIN runs r ON r.id = o.run_id
WHERE o.ip = @ip AND o.port IS NULL
ORDER BY r.id DESC
LIMIT @lim;

-- name: HostTimelinePorts :many
SELECT run_id, port::int AS port, up FROM run_observations
WHERE ip = @ip AND port IS NOT NULL AND run_id = ANY(@run_ids::bigint[])
ORDER BY run_id, port;
