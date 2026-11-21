-- name: ListProfiles :many
SELECT * FROM profiles ORDER BY name LIMIT $1 OFFSET $2;

-- name: CountProfiles :one
SELECT count(*) FROM profiles;
