-- name: InsertBatch :one
INSERT INTO batches (run_id, seq, ips) VALUES ($1, $2, $3) RETURNING id;

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
UPDATE batches SET status = 'stopped', finished_at = now()
WHERE run_id = $1 AND status IN ('pending', 'running')
RETURNING id, job_id;
