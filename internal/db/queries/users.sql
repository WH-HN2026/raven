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
