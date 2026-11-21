-- name: InsertAudit :exec
INSERT INTO audit_log (user_id, action, object, object_id, diff)
VALUES ($1, $2, $3, $4, $5);

-- name: ListAudit :many
SELECT * FROM audit_log ORDER BY id DESC LIMIT $1 OFFSET $2;
