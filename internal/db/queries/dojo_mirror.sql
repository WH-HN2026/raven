-- Dojo read-model (task D3). Written only by the dojo sync (and, later, D6
-- write-through edits); read by the API. The list query with filters is
-- built in internal/dojo/mirror.go.

-- name: UpsertDojoAsset :exec
INSERT INTO dojo_assets (id, name, ip, tags, synced_at)
VALUES (@id, @name, sqlc.narg(ip)::inet, @tags, @synced_at)
ON CONFLICT (id) DO UPDATE SET
    name = EXCLUDED.name, ip = EXCLUDED.ip, tags = EXCLUDED.tags, synced_at = EXCLUDED.synced_at;

-- name: DeleteDojoAssetsNotIn :execrows
DELETE FROM dojo_assets WHERE NOT (id = ANY(@ids::bigint[]));

-- name: UpsertDojoFinding :exec
INSERT INTO dojo_findings (id, asset_id, ip, title, severity, active, verified, false_p,
    risk_accepted, is_mitigated, tags, scanner, date, last_status_update, synced_at)
VALUES (@id, sqlc.narg(asset_id), sqlc.narg(ip)::inet, @title, @severity, @active, @verified, @false_p,
    @risk_accepted, @is_mitigated, @tags, @scanner, sqlc.narg(date)::date, sqlc.narg(last_status_update), @synced_at)
ON CONFLICT (id) DO UPDATE SET
    asset_id = EXCLUDED.asset_id, ip = EXCLUDED.ip, title = EXCLUDED.title,
    severity = EXCLUDED.severity, active = EXCLUDED.active, verified = EXCLUDED.verified,
    false_p = EXCLUDED.false_p, risk_accepted = EXCLUDED.risk_accepted,
    is_mitigated = EXCLUDED.is_mitigated, tags = EXCLUDED.tags, scanner = EXCLUDED.scanner,
    date = EXCLUDED.date, last_status_update = EXCLUDED.last_status_update,
    synced_at = EXCLUDED.synced_at;

-- name: DeleteDojoFindingsNotIn :execrows
DELETE FROM dojo_findings WHERE NOT (id = ANY(@ids::bigint[]));
