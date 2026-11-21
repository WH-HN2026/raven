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
ORDER BY username
LIMIT $1 OFFSET $2;

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
