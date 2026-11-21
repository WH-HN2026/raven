-- name: GetProfile :one
SELECT * FROM profiles WHERE id = $1;

-- name: LockProfile :one
-- Serializes run starts of one profile (one active run per profile).
SELECT * FROM profiles WHERE id = $1 FOR NO KEY UPDATE;

-- name: CountActiveRuns :one
SELECT count(*) FROM runs WHERE profile_id = $1 AND status IN ('pending', 'running');

-- name: InsertRun :one
INSERT INTO runs (profile_id, status, created_by, started_at, finished_at, hosts_total, stats, schedule_id, schedule_window_end)
VALUES ($1, $2, $3, $4, $5, $6, $7, sqlc.narg(schedule_id), sqlc.narg(schedule_window_end))
RETURNING *;

-- name: LockRun :one
-- Every batch state change takes this lock first, so "is this the last
-- batch?" is decided by one transaction at a time.
SELECT * FROM runs WHERE id = $1 FOR UPDATE;

-- name: MarkRunRunning :exec
UPDATE runs SET status = 'running', started_at = COALESCE(started_at, now())
WHERE id = $1 AND status = 'pending';

-- name: FinishRun :exec
UPDATE runs SET status = $2, finished_at = $3, hosts_up = $4, stats = stats || sqlc.arg(stats)::jsonb
WHERE id = $1;

-- name: GetRunView :one
SELECT sqlc.embed(r),
    (SELECT count(*) FROM batches b WHERE b.run_id = r.id) AS batches_total,
    (SELECT count(*) FROM batches b WHERE b.run_id = r.id AND b.status = 'done') AS batches_done,
    (SELECT count(*) FROM batches b WHERE b.run_id = r.id AND b.status = 'failed') AS batches_failed
FROM runs r WHERE r.id = $1;

-- name: ListRunViews :many
SELECT sqlc.embed(r),
    (SELECT count(*) FROM batches b WHERE b.run_id = r.id) AS batches_total,
    (SELECT count(*) FROM batches b WHERE b.run_id = r.id AND b.status = 'done') AS batches_done,
    (SELECT count(*) FROM batches b WHERE b.run_id = r.id AND b.status = 'failed') AS batches_failed
FROM runs r
WHERE sqlc.narg(profile_id)::bigint IS NULL OR r.profile_id = sqlc.narg(profile_id)::bigint
ORDER BY r.id DESC
LIMIT $1 OFFSET $2;

-- name: CountRuns :one
SELECT count(*) FROM runs
WHERE sqlc.narg(profile_id)::bigint IS NULL OR profile_id = sqlc.narg(profile_id)::bigint;

-- name: RunBatchStats :one
SELECT count(*) AS total,
    count(*) FILTER (WHERE status = 'done') AS done,
    count(*) FILTER (WHERE status = 'failed') AS failed,
    count(*) FILTER (WHERE status = 'stopped') AS stopped,
    count(*) FILTER (WHERE status IN ('pending', 'running')) AS unfinished,
    COALESCE(sum(duration_ms), 0)::bigint AS duration_ms_sum,
    COALESCE(max(duration_ms), 0)::bigint AS duration_ms_max
FROM batches WHERE run_id = $1;

-- name: RunObservationStats :one
SELECT count(*) FILTER (WHERE port IS NULL) AS hosts_up,
    count(*) FILTER (WHERE port IS NOT NULL) AS services_open
FROM run_observations WHERE run_id = $1 AND up;
