-- name: ListProfiles :many
SELECT * FROM profiles ORDER BY name LIMIT $1 OFFSET $2;

-- name: CountProfiles :one
SELECT count(*) FROM profiles;

-- name: CreateProfile :one
INSERT INTO profiles (name, ports, nmap_max_rate, nuclei_rate, nuclei_tags, miss_threshold, target_batch_seconds, enabled)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING *;

-- name: UpdateProfile :one
UPDATE profiles SET name = $2, ports = $3, nmap_max_rate = $4, nuclei_rate = $5,
    nuclei_tags = $6, miss_threshold = $7, target_batch_seconds = $8, enabled = $9
WHERE id = $1
RETURNING *;

-- name: LockProfileForDelete :one
SELECT id FROM profiles WHERE id = $1 FOR UPDATE;

-- name: ProfileHasSchedules :one
SELECT EXISTS (SELECT 1 FROM schedules WHERE profile_id = $1);

-- name: DeleteProfile :exec
DELETE FROM profiles WHERE id = $1;
