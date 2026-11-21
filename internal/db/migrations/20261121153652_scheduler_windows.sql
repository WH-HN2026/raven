-- +goose Up
ALTER TABLE runs ADD COLUMN schedule_window_end timestamptz;
CREATE INDEX runs_schedule_id_idx ON runs (schedule_id, id DESC) WHERE schedule_id IS NOT NULL;
ALTER TABLE batches ADD COLUMN hostnames jsonb NOT NULL DEFAULT '{}';

-- +goose Down
ALTER TABLE batches DROP COLUMN hostnames;
DROP INDEX runs_schedule_id_idx;
ALTER TABLE runs DROP COLUMN schedule_window_end;
