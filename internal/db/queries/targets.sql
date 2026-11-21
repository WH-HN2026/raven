-- name: ListTargets :many
SELECT * FROM targets ORDER BY
    CASE WHEN @sort_key::text = 'value_asc' THEN lower(value) END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'value_desc' THEN lower(value) END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'kind_asc' THEN kind END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'kind_desc' THEN kind END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'source_asc' THEN source END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'source_desc' THEN source END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'tags_asc' THEN tags END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'tags_desc' THEN tags END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'note_asc' THEN lower(note) END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'note_desc' THEN lower(note) END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'created_at_asc' THEN created_at END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'created_at_desc' THEN created_at END DESC NULLS LAST,
    id
LIMIT sqlc.arg(lim) OFFSET sqlc.arg(off);

-- name: CountTargets :one
SELECT count(*) FROM targets;

-- name: ListAllTargets :many
SELECT * FROM targets ORDER BY id;

-- name: InsertTarget :one
INSERT INTO targets (kind, value, source, tags, note, created_by)
VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (kind, value) DO NOTHING
RETURNING *;

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
