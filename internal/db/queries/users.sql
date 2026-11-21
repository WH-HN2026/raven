-- name: GetUserByUsername :one
SELECT * FROM users WHERE username = $1;

-- name: GetUser :one
SELECT * FROM users WHERE id = $1;

-- name: CreateUser :one
INSERT INTO users (username, password_hash, role)
VALUES ($1, $2, $3)
RETURNING *;

-- name: CountAdmins :one
SELECT count(*) FROM users WHERE role = 'admin' AND NOT disabled;

-- name: ListUsers :many
SELECT id, username, role, disabled, created_at
FROM users
ORDER BY
    CASE WHEN @sort_key::text = 'username_asc' THEN lower(username) END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'username_desc' THEN lower(username) END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'role_asc' THEN role END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'role_desc' THEN role END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'status_asc' THEN disabled END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'status_desc' THEN disabled END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'created_at_asc' THEN created_at END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'created_at_desc' THEN created_at END DESC NULLS LAST,
    CASE WHEN @sort_key::text = '' THEN username END, id
LIMIT sqlc.arg(lim) OFFSET sqlc.arg(off);

-- name: CountUsers :one
SELECT count(*) FROM users;

-- name: GetUserForUpdate :one
SELECT * FROM users WHERE id = $1 FOR UPDATE;

-- name: LockEnabledAdmins :many
-- Locks the enabled admins so concurrent edits can't remove the last one.
SELECT id FROM users WHERE role = 'admin' AND NOT disabled ORDER BY id FOR UPDATE;

-- name: UpdateUser :one
UPDATE users SET role = $2, disabled = $3, password_hash = $4
WHERE id = $1
RETURNING *;

-- name: DeleteUser :exec
DELETE FROM users WHERE id = $1;
