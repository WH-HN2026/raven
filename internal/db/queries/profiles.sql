-- name: ListProfiles :many
SELECT * FROM profiles ORDER BY
    CASE WHEN @sort_key::text = 'name_asc' THEN lower(name) END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'name_desc' THEN lower(name) END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'ports_asc' THEN ports END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'ports_desc' THEN ports END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'nmap_rate_asc' THEN nmap_max_rate END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'nmap_rate_desc' THEN nmap_max_rate END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'nuclei_rate_asc' THEN nuclei_rate END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'nuclei_rate_desc' THEN nuclei_rate END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'nuclei_tags_asc' THEN nuclei_tags END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'nuclei_tags_desc' THEN nuclei_tags END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'miss_threshold_asc' THEN miss_threshold END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'miss_threshold_desc' THEN miss_threshold END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'batch_asc' THEN target_batch_seconds END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'batch_desc' THEN target_batch_seconds END DESC NULLS LAST,
    CASE WHEN @sort_key::text = 'enabled_asc' THEN enabled END ASC NULLS LAST,
    CASE WHEN @sort_key::text = 'enabled_desc' THEN enabled END DESC NULLS LAST,
    CASE WHEN @sort_key::text = '' THEN name END, id
LIMIT sqlc.arg(lim) OFFSET sqlc.arg(off);

-- name: CountProfiles :one
SELECT count(*) FROM profiles;

-- name: CreateProfile :one
INSERT INTO profiles (name, ports, nmap_max_rate, nuclei_rate, nuclei_tags, miss_threshold, target_batch_seconds, enabled, stages)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
RETURNING *;

-- name: UpdateProfile :one
UPDATE profiles SET name = $2, ports = $3, nmap_max_rate = $4, nuclei_rate = $5,
    nuclei_tags = $6, miss_threshold = $7, target_batch_seconds = $8, enabled = $9, stages = $10
WHERE id = $1
RETURNING *;

-- name: LockProfileForDelete :one
SELECT id FROM profiles WHERE id = $1 FOR UPDATE;

-- name: ProfileHasSchedules :one
SELECT EXISTS (SELECT 1 FROM schedules WHERE profile_id = $1);

-- name: DeleteProfile :exec
DELETE FROM profiles WHERE id = $1;
