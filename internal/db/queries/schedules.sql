-- Planned engagements poller (task D5): Dojo-sourced schedules and run status sync.

-- name: ListAllProfileNames :many
SELECT id, name FROM profiles ORDER BY id;

-- name: UpsertDojoSchedule :one
INSERT INTO schedules (name, profile_id, source, dojo_engagement_id, cron, window_start, window_end, timezone, enabled)
VALUES (@name, @profile_id, 'dojo', @dojo_engagement_id, NULL, sqlc.narg(window_start), sqlc.narg(window_end), @timezone, true)
ON CONFLICT (dojo_engagement_id) DO UPDATE SET
    name         = EXCLUDED.name,
    profile_id   = EXCLUDED.profile_id,
    cron         = NULL,
    window_start = EXCLUDED.window_start,
    window_end   = EXCLUDED.window_end,
    timezone     = EXCLUDED.timezone,
    enabled      = true
RETURNING *;

-- name: GetScheduleByDojoEngagement :one
SELECT * FROM schedules WHERE dojo_engagement_id = $1;

-- name: DisableStaleDojoSchedules :execrows
UPDATE schedules s
SET enabled = false
WHERE s.source = 'dojo'
  AND s.enabled = true
  AND NOT (s.dojo_engagement_id = ANY(@active_engagement_ids::bigint[]))
  AND NOT EXISTS (SELECT 1 FROM runs r WHERE r.schedule_id = s.id);

-- name: ListDojoScheduleRunStatuses :many
SELECT DISTINCT ON (s.id)
    s.id AS schedule_id,
    s.dojo_engagement_id,
    r.id AS run_id,
    r.status AS run_status,
    COALESCE(r.stats->>'dojo_engagement_status', '')::text AS sent_status
FROM schedules s
JOIN runs r ON r.schedule_id = s.id
WHERE s.source = 'dojo'
  AND s.dojo_engagement_id IS NOT NULL
ORDER BY s.id, r.id DESC;

-- name: SetRunDojoEngagementStatus :exec
UPDATE runs
SET stats = jsonb_set(stats, '{dojo_engagement_status}', to_jsonb(@status::text))
WHERE id = @id;

-- name: GetSchedule :one
SELECT * FROM schedules WHERE id = $1;

-- name: LockSchedule :one
SELECT * FROM schedules WHERE id = $1 FOR UPDATE;

-- name: ListEnabledScheduleIDs :many
SELECT id FROM schedules WHERE enabled ORDER BY id;

-- name: ListSchedules :many
SELECT * FROM schedules ORDER BY id LIMIT $1 OFFSET $2;

-- name: CountSchedules :one
SELECT count(*) FROM schedules;

-- name: CreateSchedule :one
INSERT INTO schedules (name, profile_id, source, cron, window_start, window_end, timezone, enabled)
VALUES (@name, @profile_id, 'ui', sqlc.narg(cron), sqlc.narg(window_start), sqlc.narg(window_end), @timezone, @enabled)
RETURNING *;

-- name: UpdateUISchedule :one
UPDATE schedules SET name = @name, profile_id = @profile_id, cron = sqlc.narg(cron),
    window_start = sqlc.narg(window_start), window_end = sqlc.narg(window_end),
    timezone = @timezone, enabled = @enabled
WHERE id = @id AND source = 'ui'
RETURNING *;

-- name: DeleteUISchedule :exec
DELETE FROM schedules WHERE id = $1 AND source = 'ui';

-- name: GetLatestScheduledRun :one
SELECT * FROM runs WHERE schedule_id = $1 ORDER BY id DESC LIMIT 1;

-- name: HasActiveScheduledRun :one
SELECT EXISTS (SELECT 1 FROM runs WHERE schedule_id = $1
    AND status IN ('pending', 'running', 'suspended'));

-- name: SuspendScheduledRun :exec
UPDATE runs SET status = 'suspended' WHERE id = $1;

-- name: ResumeScheduledRun :exec
UPDATE runs SET status = 'running', schedule_window_end = $2 WHERE id = $1;
