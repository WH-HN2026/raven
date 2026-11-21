-- +goose Up
-- Q4: host "last edited by" tracking and additional Dojo finding mirror flags.
ALTER TABLE hosts
    ADD COLUMN edited_by bigint REFERENCES users(id) ON DELETE SET NULL,
    ADD COLUMN edited_at timestamptz;

ALTER TABLE dojo_findings
    ADD COLUMN out_of_scope boolean NOT NULL DEFAULT false,
    ADD COLUMN duplicate boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE dojo_findings
    DROP COLUMN duplicate,
    DROP COLUMN out_of_scope;

ALTER TABLE hosts
    DROP COLUMN edited_at,
    DROP COLUMN edited_by;
