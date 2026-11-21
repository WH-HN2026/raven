-- +goose Up
ALTER TABLE profiles
    ADD COLUMN stages text[] NOT NULL DEFAULT ARRAY['nmap', 'httpx', 'nuclei'];

ALTER TABLE runs
    ADD COLUMN stages text[];

-- +goose Down
ALTER TABLE runs
    DROP COLUMN IF EXISTS stages;

ALTER TABLE profiles
    DROP COLUMN IF EXISTS stages;
