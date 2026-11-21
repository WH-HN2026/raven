-- name: ListTargets :many
SELECT * FROM targets ORDER BY id LIMIT $1 OFFSET $2;

-- name: CountTargets :one
SELECT count(*) FROM targets;

-- name: ListAllTargets :many
SELECT * FROM targets ORDER BY id;

-- name: UpsertTarget :one
-- Re-adding an existing (kind, value) merges its tags and keeps a non-empty note.
INSERT INTO targets (kind, value, source, tags, note, created_by)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (kind, value) DO UPDATE SET
    tags = ARRAY(SELECT DISTINCT t FROM unnest(targets.tags || EXCLUDED.tags) AS t ORDER BY t),
    note = CASE WHEN EXCLUDED.note <> '' THEN EXCLUDED.note ELSE targets.note END
RETURNING *;

-- name: DeleteTarget :one
DELETE FROM targets WHERE id = $1 RETURNING *;
