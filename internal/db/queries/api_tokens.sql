-- name: CreateAPIToken :one
INSERT INTO api_tokens (user_id, token_hash, name)
VALUES ($1, $2, $3)
RETURNING id, user_id, name, created_at, last_used_at;

-- name: ListAPITokens :many
SELECT t.id, t.user_id, u.username, u.role, t.name, t.created_at, t.last_used_at
FROM api_tokens t
JOIN users u ON u.id = t.user_id
ORDER BY t.created_at DESC, t.id DESC
LIMIT sqlc.arg(lim) OFFSET sqlc.arg(off);

-- name: CountAPITokens :one
SELECT count(*) FROM api_tokens;

-- name: GetAPITokenUser :one
SELECT t.id AS token_id, u.id, u.username, u.role
FROM api_tokens t
JOIN users u ON u.id = t.user_id
WHERE t.token_hash = $1 AND NOT u.disabled;

-- name: TouchAPIToken :exec
UPDATE api_tokens SET last_used_at = now() WHERE id = $1;

-- name: DeleteAPIToken :one
DELETE FROM api_tokens WHERE id = $1
RETURNING id, user_id, name;
