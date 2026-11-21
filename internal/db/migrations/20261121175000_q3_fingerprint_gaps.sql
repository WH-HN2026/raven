-- +goose Up
-- Q3: CPEs on HTTP observations, per-product CVE match key, and schedule names.
ALTER TABLE http_observations
    ADD COLUMN cpes text[] NOT NULL DEFAULT '{}';

ALTER TABLE cve_matches DROP CONSTRAINT cve_matches_pkey;
ALTER TABLE cve_matches ADD PRIMARY KEY (ip, port, proto, cpe);

ALTER TABLE schedules
    ADD COLUMN name text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE schedules DROP COLUMN name;

DELETE FROM cve_matches a
USING cve_matches b
WHERE a.ctid < b.ctid AND a.ip = b.ip AND a.port = b.port AND a.proto = b.proto;
ALTER TABLE cve_matches DROP CONSTRAINT cve_matches_pkey;
ALTER TABLE cve_matches ADD PRIMARY KEY (ip, port, proto);

ALTER TABLE http_observations DROP COLUMN cpes;
