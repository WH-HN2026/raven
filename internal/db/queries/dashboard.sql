-- Dashboard aggregates (task W4). Read-only.

-- name: DashboardFindingCounts :many
-- Active findings in the Dojo mirror per severity.
SELECT severity, count(*)::int AS n FROM dojo_findings WHERE active GROUP BY severity;

-- name: DashboardHostCounts :one
SELECT count(*) FILTER (WHERE state = 'active')::int   AS active,
       count(*) FILTER (WHERE state = 'unstable')::int AS unstable,
       count(*) FILTER (WHERE state = 'inactive')::int AS inactive,
       (SELECT count(*) FROM services WHERE state = 'open')::int AS services_open
FROM hosts;

-- name: DashboardNewHosts :many
-- Hosts first seen at or after @since (the start of the latest done run).
SELECT h.ip, h.hostnames, h.state, h.first_seen,
       COALESCE((SELECT array_agg(DISTINCT s.port ORDER BY s.port) FROM services s
                 WHERE s.ip = h.ip AND s.state = 'open'), '{}')::int[] AS ports,
       count(*) OVER ()::int AS total
FROM hosts h
WHERE h.first_seen >= @since
ORDER BY h.first_seen DESC, h.ip
LIMIT @lim;

-- name: DashboardUnstableHosts :many
-- Unstable hosts first, then inactive; with their host-level up count over
-- the last 10 runs that scanned them.
SELECT h.ip, h.hostnames, h.state, h.last_seen, h.miss_count,
       COALESCE(r.up_runs, 0)::int AS up_runs, COALESCE(r.seen_runs, 0)::int AS seen_runs
FROM hosts h
LEFT JOIN LATERAL (
    SELECT count(*) FILTER (WHERE o.up) AS up_runs, count(*) AS seen_runs
    FROM (SELECT up FROM run_observations
          WHERE ip = h.ip AND port IS NULL ORDER BY run_id DESC LIMIT 10) o
) r ON true
WHERE h.state IN ('unstable', 'inactive')
ORDER BY (h.state = 'unstable') DESC, h.last_seen DESC, h.ip
LIMIT @lim;

-- name: DashboardTechnologies :many
-- Hosts per technology, from the latest http observation of each open
-- service and URL.
WITH latest AS (
    SELECT DISTINCT ON (o.service_id, o.url) o.service_id, o.technologies
    FROM http_observations o
    ORDER BY o.service_id, o.url, o.observed_at DESC, o.id DESC
)
SELECT t.tech::text AS name, count(DISTINCT s.ip)::int AS hosts
FROM latest l
JOIN services s ON s.id = l.service_id AND s.state = 'open'
CROSS JOIN LATERAL unnest(l.technologies) AS t(tech)
GROUP BY t.tech
ORDER BY 2 DESC, 1
LIMIT @lim;

-- name: DashboardCVEMatches :many
SELECT ip, port, proto, product, version, severity, max_cvss, kev, cardinality(cve_ids)::int AS cves,
       count(*) OVER ()::int AS total
FROM cve_matches
ORDER BY CASE severity WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,
         max_cvss DESC, ip, port
LIMIT @lim;

-- name: DashboardRuns :many
SELECT r.id, r.profile_id, p.name AS profile, r.status, r.created_at, r.started_at, r.finished_at,
       r.hosts_total, r.hosts_up,
       (SELECT count(*) FROM batches b WHERE b.run_id = r.id)::int AS batches_total,
       (SELECT count(*) FROM batches b WHERE b.run_id = r.id AND b.status = 'done')::int AS batches_done
FROM runs r JOIN profiles p ON p.id = r.profile_id
ORDER BY r.id DESC
LIMIT @lim;
