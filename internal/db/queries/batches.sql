-- name: InsertBatch :one
INSERT INTO batches (run_id, seq, ips, hostnames)
VALUES ($1, $2, $3, COALESCE(sqlc.narg(hostnames)::jsonb, '{}'::jsonb)) RETURNING id;

-- name: SetBatchJob :exec
UPDATE batches SET job_id = $2 WHERE id = $1;

-- name: GetBatch :one
SELECT * FROM batches WHERE id = $1;

-- name: ListBatches :many
SELECT * FROM batches WHERE run_id = $1 ORDER BY seq;

-- name: StartBatch :one
-- 'running' is accepted too: a job rescued after a crash starts over.
UPDATE batches SET status = 'running', attempts = attempts + 1, started_at = now(),
    finished_at = NULL, duration_ms = NULL, error = ''
WHERE id = $1 AND status IN ('pending', 'running')
RETURNING *;

-- name: FinishBatch :exec
UPDATE batches SET status = $2, finished_at = $3, duration_ms = $4, hosts_up = $5, error = $6
WHERE id = $1;

-- name: RetryBatch :exec
-- A failed attempt that River will retry: back to pending, keep the error.
UPDATE batches SET status = 'pending', error = $2 WHERE id = $1 AND status = 'running';

-- name: StopUnfinishedBatches :many
UPDATE batches SET status = 'stopped', finished_at = now(),
    duration_ms = (extract(epoch FROM now() - started_at) * 1000)::bigint  -- NULL if it never started
WHERE run_id = $1 AND status IN ('pending', 'running')
RETURNING id, job_id;

-- name: ListProfileBatchSamples :many
SELECT cardinality(b.ips)::integer AS host_count, b.duration_ms
FROM batches b
JOIN runs r ON r.id = b.run_id
WHERE r.profile_id = $1
  AND b.status = 'done'
  AND b.duration_ms IS NOT NULL
  AND b.duration_ms > 0
  AND cardinality(b.ips) > 0
ORDER BY b.finished_at DESC, b.id DESC
LIMIT $2;

-- name: ResetWindowBatches :exec
UPDATE batches SET status = 'pending', job_id = NULL, started_at = NULL
WHERE run_id = $1 AND status IN ('pending', 'running');

-- name: ListPendingBatches :many
SELECT id, hostnames FROM batches WHERE run_id = $1 AND status = 'pending' ORDER BY seq;
