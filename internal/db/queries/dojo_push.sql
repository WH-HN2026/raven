-- Dojo push (task D2): reads what a push job needs and writes the scan-owned
-- hosts.dojo_asset_id plus the run's stats.dojo_push counters.

-- name: GetBatchArtifact :one
SELECT asi_dec(content_enc)::text AS content FROM artifacts
WHERE batch_id = @batch_id AND scanner = @scanner
ORDER BY id DESC LIMIT 1;

-- name: ListPushHosts :many
SELECT ip, hostnames, first_seen, dojo_asset_id FROM hosts
WHERE ip = ANY(@ips::inet[]);

-- name: SetHostDojoAsset :exec
UPDATE hosts SET dojo_asset_id = @dojo_asset_id WHERE ip = @ip;

-- name: AddRunDojoPushStats :exec
-- Increments stats.dojo_push {ok, failed}; FinishRun merges its own keys with
-- ||, so neither overwrites the other.
UPDATE runs SET stats = jsonb_set(stats, '{dojo_push}', jsonb_build_object(
    'ok', COALESCE((stats->'dojo_push'->>'ok')::int, 0) + @ok::int,
    'failed', COALESCE((stats->'dojo_push'->>'failed')::int, 0) + @failed::int))
WHERE id = @id;
