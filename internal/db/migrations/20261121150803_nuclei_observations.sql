-- +goose Up
ALTER TABLE run_observations
    ADD COLUMN nuclei_matches jsonb NOT NULL DEFAULT '[]',
    ADD COLUMN nuclei_evidence_enc bytea;

-- +goose Down
ALTER TABLE run_observations
    DROP COLUMN nuclei_evidence_enc,
    DROP COLUMN nuclei_matches;
