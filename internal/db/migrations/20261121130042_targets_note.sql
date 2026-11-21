-- +goose Up
-- S1: the CSV/JSON target formats carry a free-text note per target.
ALTER TABLE targets ADD COLUMN note text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE targets DROP COLUMN note;
