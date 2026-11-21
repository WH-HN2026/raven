-- User edits (task D6): write-through finding triage, host user-owned
-- fields and service overrides. Scans never use these queries; they write
-- only user-owned columns (architecture §5). notes are encrypted with
-- asi_enc and must never be logged.

-- name: GetDojoFinding :one
SELECT id, asset_id, ip, title, severity, active, verified, false_p, risk_accepted, is_mitigated,
    tags, scanner, COALESCE(to_char(date, 'YYYY-MM-DD'), '')::text AS date
FROM dojo_findings WHERE id = @id;

-- name: UpdateDojoFindingTriage :exec
-- Mirror the state Dojo answered with after a PATCH.
UPDATE dojo_findings SET
    severity = @severity, active = @active, verified = @verified, false_p = @false_p,
    risk_accepted = @risk_accepted, is_mitigated = @is_mitigated, tags = @tags,
    last_status_update = sqlc.narg(last_status_update), synced_at = now()
WHERE id = @id;

-- name: GetHostUserFieldsForUpdate :one
SELECT dojo_asset_id, owner, criticality, COALESCE(asi_dec(notes_enc), '')::text AS notes, user_tags
FROM hosts WHERE ip = @ip FOR UPDATE;

-- name: UpdateHostUserFields :exec
-- An empty note clears notes_enc.
UPDATE hosts SET
    owner = @owner, criticality = @criticality, user_tags = @user_tags,
    notes_enc = CASE WHEN @notes::text = '' THEN NULL ELSE asi_enc(@notes::text) END
WHERE ip = @ip;

-- name: GetServiceOverridesForUpdate :one
SELECT ip, overrides FROM services WHERE id = @id FOR UPDATE;

-- name: UpdateServiceOverrides :exec
UPDATE services SET overrides = @overrides WHERE id = @id;

-- name: GetService :one
SELECT id, ip, port, proto, name, product, version, cpe,
    COALESCE(asi_dec(banner_enc), '')::text AS banner,
    state, first_seen, last_seen, overrides
FROM services WHERE id = @id;
