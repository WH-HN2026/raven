-- name: AddRunNucleiActiveErrors :exec
UPDATE runs SET stats = jsonb_set(
    stats,
    '{nuclei_active_errors}',
    to_jsonb(COALESCE((stats->>'nuclei_active_errors')::int, 0) + @delta::int),
    true
)
WHERE id = @id;
