-- +goose Up
-- V7: httpx's per-URL response time (its JSON `time`), in milliseconds. NULL for
-- observations recorded before V7 or imported without a time.
ALTER TABLE http_observations ADD COLUMN response_ms integer CHECK (response_ms >= 0);

-- +goose Down
ALTER TABLE http_observations DROP COLUMN response_ms;
