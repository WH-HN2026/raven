-- LB1: the "Organizers' lab" profile (architecture §10, "Lab scenarios").
-- The organizers' stacks (lab/organizers/, run verbatim with
-- `make lab-up LAB=organizers STACK=…`) publish their ports on the Docker host;
-- RAVEN reaches them at the docker0 gateway 172.17.0.1.
--  - profile: Default stages (column default nmap/httpx/nuclei, NOT aggressive),
--    default rates, exactly their published ports (RAVEN's 8000 and Dojo's
--    port are not in it); no schedule, so it runs only on "Start run";
--  - the profile's include 172.17.0.1;
--  - an exclude 172.17.0.1 on the seeded 'default' profile, which has no
--    includes and would otherwise scan the Docker host on its whole port list.
-- The target 172.17.0.1 itself is NOT seeded: a run scans every target when
-- its profile has no include rules, so a seeded target would be scanned by
-- any such profile. Operators add it in Targets (docs/lab.md).
-- Rows carry note 'Organizers'' lab' so Down removes only what Up inserted.

-- +goose Up
INSERT INTO profiles (name, ports)
VALUES ('Organizers'' lab', '21,80,81,443,2223,3001,5673,6379,8080,8081,8085,8086,8088-8090,8474,8787,8888,15432,15673')
ON CONFLICT (name) DO NOTHING;

INSERT INTO scope_entries (kind, value, list, profile_id, note)
SELECT 'ip', '172.17.0.1', 'include', id, 'Organizers'' lab' FROM profiles WHERE name = 'Organizers'' lab'
UNION ALL
SELECT 'ip', '172.17.0.1', 'exclude', id, 'Organizers'' lab' FROM profiles WHERE name = 'default'
ON CONFLICT DO NOTHING;

-- +goose Down
DELETE FROM scope_entries
WHERE kind = 'ip' AND value = '172.17.0.1' AND note = 'Organizers'' lab'
  AND profile_id IN (SELECT id FROM profiles WHERE name IN ('Organizers'' lab', 'default'));
-- Runs reference profiles without ON DELETE CASCADE: keep the profile if it has runs.
DELETE FROM profiles p
WHERE p.name = 'Organizers'' lab' AND NOT EXISTS (SELECT 1 FROM runs r WHERE r.profile_id = p.id);
