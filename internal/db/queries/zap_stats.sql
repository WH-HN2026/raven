-- name: AddRunZapErrors :exec
UPDATE runs SET stats = jsonb_set(
    stats,
    '{zap_errors}',
    to_jsonb(COALESCE((stats->>'zap_errors')::int, 0) + @delta::int),
    true
)
WHERE id = @id;
