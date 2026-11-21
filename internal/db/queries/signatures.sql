-- name: ListSignatures :many
SELECT * FROM signatures ORDER BY builtin DESC, name LIMIT $1 OFFSET $2;

-- name: CountSignatures :one
SELECT count(*) FROM signatures;

-- name: GetSignature :one
SELECT * FROM signatures WHERE id = $1;

-- name: GetSignatureByName :one
SELECT * FROM signatures WHERE name = $1;

-- name: ListEnabledSignatures :many
-- The templates nuclei runs (S4): enabled implies valid (CHECK constraint).
SELECT * FROM signatures WHERE enabled ORDER BY name;

-- name: InsertSignature :one
INSERT INTO signatures (name, template_yaml, enabled, valid, validation_error, builtin, created_by)
VALUES ($1, $2, $3, $4, $5, $6, $7)
RETURNING *;

-- name: UpdateSignature :one
UPDATE signatures SET name = $2, template_yaml = $3, enabled = $4, valid = $5, validation_error = $6
WHERE id = $1
RETURNING *;

-- name: DeleteSignature :one
DELETE FROM signatures WHERE id = $1 RETURNING *;

-- name: DeleteBuiltinsExcept :many
-- Built-ins that were removed from the pack.
DELETE FROM signatures WHERE builtin AND NOT (name = ANY(@keep::text[])) RETURNING name;
