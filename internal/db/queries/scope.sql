-- name: ListScopeEntries :many
-- profile_id NULL = the global entries.
SELECT * FROM scope_entries
WHERE profile_id IS NOT DISTINCT FROM sqlc.narg(profile_id)::bigint
ORDER BY id LIMIT $1 OFFSET $2;

-- name: CountScopeEntries :one
SELECT count(*) FROM scope_entries
WHERE profile_id IS NOT DISTINCT FROM sqlc.narg(profile_id)::bigint;

-- name: ListEffectiveScope :many
-- Global entries plus the profile's own (what a run of that profile applies).
SELECT * FROM scope_entries
WHERE profile_id IS NULL OR profile_id = sqlc.narg(profile_id)::bigint
ORDER BY id;

-- name: GetScopeEntry :one
SELECT * FROM scope_entries WHERE id = $1;

-- name: InsertScopeEntry :one
INSERT INTO scope_entries (kind, value, list, profile_id, note, created_by)
VALUES ($1, $2, $3, $4, $5, $6)
RETURNING *;

-- name: DeleteScopeEntry :exec
DELETE FROM scope_entries WHERE id = $1;
