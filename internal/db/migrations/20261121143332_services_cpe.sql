-- +goose Up
-- S8: normalized CPE ("vendor:product" or "vendor:product:version") for offline CVE matching.
ALTER TABLE services ADD COLUMN cpe text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE services DROP COLUMN cpe;
