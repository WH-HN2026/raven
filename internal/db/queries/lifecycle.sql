-- name: ListRunReprobeIPs :many
-- The last batch has not been ingested yet. Its down IPs are supplied alongside
-- the other batches' persisted down observations. Both come from the run scope.
WITH previous_run AS (
    SELECT id FROM runs
    WHERE profile_id = @profile_id AND status = 'done' AND id < @run_id
    ORDER BY id DESC LIMIT 1
)
SELECT prev.ip
FROM run_observations prev JOIN previous_run r ON r.id = prev.run_id
WHERE prev.port IS NULL AND prev.up AND (
    prev.ip = ANY(@last_batch_down::inet[])
    OR EXISTS (
        SELECT 1 FROM run_observations cur
        WHERE cur.run_id = @run_id AND cur.ip = prev.ip AND cur.port IS NULL AND NOT cur.up
    )
)
ORDER BY prev.ip;

-- name: ListRunLifecycleHosts :many
-- A first-time down IP is not a host. Once seen up by this profile, a host can
-- accrue further misses until it responds. A newer sighting by another profile
-- takes precedence over a miss already observed by this run.
SELECT h.ip, h.state, h.miss_count, cur.up
FROM run_observations cur JOIN hosts h ON h.ip = cur.ip
WHERE cur.run_id = @run_id AND cur.port IS NULL
  AND (
      cur.ip = ANY(@recovered::inet[])
      OR (NOT cur.up AND h.last_seen <= cur.observed_at AND EXISTS (
          SELECT 1 FROM run_observations prev JOIN runs r ON r.id = prev.run_id
          WHERE prev.ip = cur.ip AND prev.port IS NULL AND prev.up
            AND r.profile_id = @profile_id AND r.status = 'done' AND r.id < @run_id
      ))
  )
ORDER BY h.ip FOR UPDATE OF h;

-- name: UpdateHostLifecycle :exec
UPDATE hosts h SET state = m.state, miss_count = m.miss_count,
    last_seen = CASE WHEN m.up THEN GREATEST(h.last_seen, @seen::timestamptz) ELSE h.last_seen END
FROM (
    SELECT unnest(@ips::inet[]) AS ip, unnest(@states::text[]) AS state,
        unnest(@miss_counts::int[]) AS miss_count, unnest(@ups::boolean[]) AS up
) AS m
WHERE h.ip = m.ip;
