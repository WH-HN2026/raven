-- LB6: the seeded profiles are exactly "Default" and "Aggressive"
-- (architecture §9 Gating, §10 "Lab scenarios").
--  - LB1's "Organizers' lab" seed goes away: its 172.17.0.1 include and the
--    172.17.0.1 exclude it put on 'default' (rows with note 'Organizers'' lab'),
--    and the profile itself unless it has runs or schedules (runs.profile_id has
--    no ON DELETE CASCADE, and schedules are user data): then it is kept as an
--    ordinary profile.
--  - 'default' is renamed "Default" (unless a "Default" already exists).
--  - "Aggressive" copies Default's ports/rates/tags/thresholds, with the
--    Default stages + nuclei_active, nikto, wpscan (pipeline.SeededAggressiveStages();
--    no zap: admins add it in the workflow builder). It is aggressive because
--    its stages are (pipeline.IsAggressive), never the default, not scheduled.
--    Its creation is logged like an API create of an aggressive profile
--    (profiles.create, aggressive: true), by the system (user_id NULL), with
--    seed 'LB6' so Down can find it.

-- +goose Up
DELETE FROM scope_entries
WHERE kind = 'ip' AND value = '172.17.0.1' AND note = 'Organizers'' lab'
  AND profile_id IN (SELECT id FROM profiles WHERE name IN ('Organizers'' lab', 'default'));

DELETE FROM profiles p
WHERE p.name = 'Organizers'' lab'
  AND NOT EXISTS (SELECT 1 FROM runs r WHERE r.profile_id = p.id)
  AND NOT EXISTS (SELECT 1 FROM schedules s WHERE s.profile_id = p.id);

UPDATE profiles SET name = 'Default'
WHERE name = 'default' AND NOT EXISTS (SELECT 1 FROM profiles WHERE name = 'Default');

WITH ins AS (
    INSERT INTO profiles (name, ports, nmap_max_rate, nuclei_rate, nuclei_tags, miss_threshold, target_batch_seconds, stages)
    SELECT 'Aggressive', ports, nmap_max_rate, nuclei_rate, nuclei_tags, miss_threshold, target_batch_seconds,
           ARRAY['nmap', 'httpx', 'nuclei', 'nuclei_active', 'nikto', 'wpscan']
    FROM profiles WHERE name = 'Default'
    ON CONFLICT (name) DO NOTHING
    RETURNING *
)
INSERT INTO audit_log (user_id, action, object, object_id, diff)
SELECT NULL, 'profiles.create', 'profile', ins.id::text,
       to_jsonb(ins) || '{"aggressive": true, "seed": "LB6"}'::jsonb
FROM ins;

-- No "Default" (deleted by a user): seed "Aggressive" with the column defaults.
WITH ins AS (
    INSERT INTO profiles (name, stages)
    VALUES ('Aggressive', ARRAY['nmap', 'httpx', 'nuclei', 'nuclei_active', 'nikto', 'wpscan'])
    ON CONFLICT (name) DO NOTHING
    RETURNING *
)
INSERT INTO audit_log (user_id, action, object, object_id, diff)
SELECT NULL, 'profiles.create', 'profile', ins.id::text,
       to_jsonb(ins) || '{"aggressive": true, "seed": "LB6"}'::jsonb
FROM ins;

-- +goose Down
-- The seeded "Aggressive" goes unless it has runs or schedules; audit rows stay.
DELETE FROM profiles p
WHERE p.name = 'Aggressive'
  AND EXISTS (SELECT 1 FROM audit_log a
              WHERE a.action = 'profiles.create' AND a.object = 'profile'
                AND a.object_id = p.id::text AND a.diff->>'seed' = 'LB6')
  AND NOT EXISTS (SELECT 1 FROM runs r WHERE r.profile_id = p.id)
  AND NOT EXISTS (SELECT 1 FROM schedules s WHERE s.profile_id = p.id);

UPDATE profiles SET name = 'default'
WHERE name = 'Default' AND NOT EXISTS (SELECT 1 FROM profiles WHERE name = 'default');

-- LB1's seed (20261121224954_organizers_lab_profile.sql Up).
INSERT INTO profiles (name, ports)
VALUES ('Organizers'' lab', '21,80,81,443,2223,3001,5673,6379,8080,8081,8085,8086,8088-8090,8474,8787,8888,15432,15673')
ON CONFLICT (name) DO NOTHING;

INSERT INTO scope_entries (kind, value, list, profile_id, note)
SELECT 'ip', '172.17.0.1', 'include', id, 'Organizers'' lab' FROM profiles WHERE name = 'Organizers'' lab'
UNION ALL
SELECT 'ip', '172.17.0.1', 'exclude', id, 'Organizers'' lab' FROM profiles WHERE name = 'default'
ON CONFLICT DO NOTHING;
