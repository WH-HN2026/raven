-- Import/export queries (task P3).

-- name: GetProfileByName :one
SELECT * FROM profiles WHERE name = $1;

-- name: ListServicesForExport :many
-- Filtered services ordered by IP, port, proto. Overrides are layered in Go.
SELECT id, ip, port, proto, name, product, version, cpe, state, first_seen, last_seen, overrides
FROM services
WHERE (sqlc.narg(port)::int IS NULL OR port = sqlc.narg(port)::int)
  AND (sqlc.narg(proto)::text IS NULL OR proto = sqlc.narg(proto)::text)
  AND (sqlc.narg(state)::text IS NULL OR state = sqlc.narg(state)::text)
  AND (sqlc.narg(ip)::text IS NULL OR ip <<= sqlc.narg(ip)::text::inet)
  AND (sqlc.narg(product)::text IS NULL
       OR strpos(lower(COALESCE(NULLIF(overrides->>'product', ''), product)), lower(sqlc.narg(product)::text)) > 0)
  AND (sqlc.narg(q)::text IS NULL
       OR strpos(lower(COALESCE(NULLIF(overrides->>'name', ''), name)), lower(sqlc.narg(q)::text)) > 0
       OR strpos(lower(COALESCE(NULLIF(overrides->>'product', ''), product)), lower(sqlc.narg(q)::text)) > 0
       OR strpos(lower(COALESCE(NULLIF(overrides->>'version', ''), version)), lower(sqlc.narg(q)::text)) > 0
       OR strpos(lower(cpe), lower(sqlc.narg(q)::text)) > 0
       OR starts_with(host(ip), sqlc.narg(q)::text))
ORDER BY ip, port, proto
LIMIT @lim OFFSET @off;
