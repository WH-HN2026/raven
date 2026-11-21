-- S3: pipeline v1.
--  - profiles.ports gets an explicit TCP port list (nmap's ~100 most common
--    TCP ports written out, plus 6379, 9200, 27017): the old default
--    'top-1000' is not a port spec nmap.CheckPorts accepts;
--  - a 'default' profile is seeded (there is no profile API yet);
--  - runs and batches get a terminal 'stopped' status (POST /runs/{id}/stop);
--  - batches get the River job id (to cancel it), hosts_up and the last error.

-- +goose Up
ALTER TABLE profiles ALTER COLUMN ports SET DEFAULT
    '7,9,13,21-23,25-26,37,53,79-81,88,106,110-111,113,119,135,139,143-144,179,199,389,427,443-445,465,513-515,543-544,548,554,587,631,646,873,990,993,995,1025-1029,1110,1433,1720,1723,1755,1900,2000-2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000-6001,6379,6646,7070,8000,8008-8009,8080-8081,8443,8888,9100,9200,9999-10000,27017,32768,49152-49157';
UPDATE profiles SET ports = DEFAULT WHERE ports = 'top-1000';
INSERT INTO profiles (name) VALUES ('default') ON CONFLICT (name) DO NOTHING;

ALTER TABLE runs DROP CONSTRAINT runs_status_check;
ALTER TABLE runs ADD CONSTRAINT runs_status_check
    CHECK (status IN ('pending', 'running', 'suspended', 'done', 'failed', 'stopped'));

ALTER TABLE batches DROP CONSTRAINT batches_status_check;
ALTER TABLE batches ADD CONSTRAINT batches_status_check
    CHECK (status IN ('pending', 'running', 'done', 'failed', 'stopped'));
ALTER TABLE batches
    ADD COLUMN job_id   bigint,
    ADD COLUMN hosts_up integer NOT NULL DEFAULT 0,
    ADD COLUMN error    text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE batches DROP COLUMN job_id, DROP COLUMN hosts_up, DROP COLUMN error;
UPDATE batches SET status = 'failed' WHERE status = 'stopped';
ALTER TABLE batches DROP CONSTRAINT batches_status_check;
ALTER TABLE batches ADD CONSTRAINT batches_status_check
    CHECK (status IN ('pending', 'running', 'done', 'failed'));
UPDATE runs SET status = 'failed' WHERE status = 'stopped';
ALTER TABLE runs DROP CONSTRAINT runs_status_check;
ALTER TABLE runs ADD CONSTRAINT runs_status_check
    CHECK (status IN ('pending', 'running', 'suspended', 'done', 'failed'));
ALTER TABLE profiles ALTER COLUMN ports SET DEFAULT 'top-1000';
