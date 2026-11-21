-- Baseline schema (architecture §5). Later tasks add their own migrations; never edit this one once merged.

-- +goose Up
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Encryption helpers (D8). The key is set per connection by the pgx pool:
-- set_config('asi.enc_key', <ASI_ENCRYPTION_KEY>, false).
-- +goose StatementBegin
CREATE FUNCTION asi_enc(t text) RETURNS bytea
LANGUAGE sql VOLATILE AS $$
    SELECT CASE WHEN t IS NULL THEN NULL
                ELSE pgp_sym_encrypt(t, current_setting('asi.enc_key')) END
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION asi_dec(b bytea) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT CASE WHEN b IS NULL THEN NULL
                ELSE pgp_sym_decrypt(b, current_setting('asi.enc_key')) END
$$;
-- +goose StatementEnd

CREATE TABLE users (
    id            bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    username      text NOT NULL UNIQUE,
    password_hash text NOT NULL,
    role          text NOT NULL CHECK (role IN ('admin', 'editor', 'operator', 'viewer')),
    disabled      boolean NOT NULL DEFAULT false,
    created_at    timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE sessions (
    token_hash bytea PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);
CREATE INDEX sessions_user_id_idx ON sessions(user_id);
CREATE INDEX sessions_expires_at_idx ON sessions(expires_at);

CREATE TABLE api_tokens (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id    bigint NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash bytea NOT NULL UNIQUE,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz
);
CREATE INDEX api_tokens_user_id_idx ON api_tokens(user_id);

CREATE TABLE profiles (
    id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name                 text NOT NULL UNIQUE,
    ports                text NOT NULL DEFAULT 'top-1000',  -- nmap port spec from the allowlist
    nmap_max_rate        integer NOT NULL DEFAULT 300 CHECK (nmap_max_rate > 0),
    nuclei_rate          integer NOT NULL DEFAULT 50 CHECK (nuclei_rate > 0),
    nuclei_tags          text[] NOT NULL DEFAULT '{}',
    miss_threshold       integer NOT NULL DEFAULT 3 CHECK (miss_threshold > 0),
    target_batch_seconds integer NOT NULL DEFAULT 600 CHECK (target_batch_seconds > 0),
    enabled              boolean NOT NULL DEFAULT true,
    created_at           timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE scope_entries (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind       text NOT NULL CHECK (kind IN ('ip', 'cidr', 'domain')),
    value      text NOT NULL,
    list       text NOT NULL CHECK (list IN ('include', 'exclude')),
    profile_id bigint REFERENCES profiles(id) ON DELETE CASCADE,  -- NULL = global
    note       text NOT NULL DEFAULT '',
    created_by bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX scope_entries_uniq ON scope_entries(COALESCE(profile_id, 0), list, kind, value);

CREATE TABLE targets (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind       text NOT NULL CHECK (kind IN ('ip', 'cidr', 'domain')),
    value      text NOT NULL,
    source     text NOT NULL CHECK (source IN ('manual', 'csv', 'json', 'dojo')),
    tags       text[] NOT NULL DEFAULT '{}',
    created_by bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (kind, value)
);

CREATE TABLE schedules (
    id                 bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    profile_id         bigint NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
    source             text NOT NULL CHECK (source IN ('ui', 'dojo')),
    dojo_engagement_id bigint UNIQUE,
    cron               text,
    window_start       timestamptz,
    window_end         timestamptz,
    timezone           text NOT NULL DEFAULT 'Europe/Warsaw',
    enabled            boolean NOT NULL DEFAULT true,
    created_at         timestamptz NOT NULL DEFAULT now(),
    CHECK (source <> 'dojo' OR dojo_engagement_id IS NOT NULL),
    CHECK (window_end IS NULL OR window_start IS NULL OR window_end > window_start)
);

CREATE TABLE runs (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    profile_id  bigint NOT NULL REFERENCES profiles(id),
    schedule_id bigint REFERENCES schedules(id) ON DELETE SET NULL,
    status      text NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'running', 'suspended', 'done', 'failed')),
    created_by  bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    started_at  timestamptz,
    finished_at timestamptz,
    hosts_total integer NOT NULL DEFAULT 0,
    hosts_up    integer NOT NULL DEFAULT 0,
    stats       jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX runs_profile_id_idx ON runs(profile_id, created_at DESC);
CREATE INDEX runs_status_idx ON runs(status);

CREATE TABLE batches (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id      bigint NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    seq         integer NOT NULL,
    ips         inet[] NOT NULL,
    status      text NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'running', 'done', 'failed')),
    attempts    integer NOT NULL DEFAULT 0,
    started_at  timestamptz,
    finished_at timestamptz,
    duration_ms bigint,
    UNIQUE (run_id, seq)
);

CREATE TABLE hosts (
    ip            inet PRIMARY KEY,
    -- scan-owned
    hostnames     text[] NOT NULL DEFAULT '{}',
    state         text NOT NULL DEFAULT 'active' CHECK (state IN ('active', 'unstable', 'inactive')),
    first_seen    timestamptz NOT NULL DEFAULT now(),
    last_seen     timestamptz NOT NULL DEFAULT now(),
    miss_count    integer NOT NULL DEFAULT 0,
    dojo_asset_id bigint,
    -- user-owned, never written by scans
    owner         text NOT NULL DEFAULT '',
    criticality   text NOT NULL DEFAULT '' CHECK (criticality IN ('', 'low', 'medium', 'high', 'critical')),
    notes_enc     bytea,
    user_tags     text[] NOT NULL DEFAULT '{}',
    overrides     jsonb NOT NULL DEFAULT '{}'
);
CREATE INDEX hosts_state_idx ON hosts(state);

CREATE TABLE services (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ip         inet NOT NULL REFERENCES hosts(ip) ON DELETE CASCADE,
    port       integer NOT NULL CHECK (port BETWEEN 0 AND 65535),
    proto      text NOT NULL CHECK (proto IN ('tcp', 'udp')),
    name       text NOT NULL DEFAULT '',
    product    text NOT NULL DEFAULT '',
    version    text NOT NULL DEFAULT '',
    banner_enc bytea,
    state      text NOT NULL DEFAULT 'open' CHECK (state IN ('open', 'gone')),
    first_seen timestamptz NOT NULL DEFAULT now(),
    last_seen  timestamptz NOT NULL DEFAULT now(),
    overrides  jsonb NOT NULL DEFAULT '{}',
    UNIQUE (ip, port, proto)
);
CREATE INDEX services_port_idx ON services(port);

CREATE TABLE http_observations (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    service_id   bigint NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    url          text NOT NULL,
    status       integer,
    title        text NOT NULL DEFAULT '',
    headers_enc  bytea,
    cookies_enc  bytea,
    tls_cert_enc bytea,
    redirects    jsonb NOT NULL DEFAULT '[]',
    technologies text[] NOT NULL DEFAULT '{}',
    favicon_hash text NOT NULL DEFAULT '',
    run_id       bigint REFERENCES runs(id) ON DELETE SET NULL,
    observed_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX http_observations_service_idx ON http_observations(service_id, observed_at DESC);
CREATE INDEX http_observations_tech_idx ON http_observations USING gin (technologies);

CREATE TABLE run_observations (
    run_id      bigint NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    ip          inet NOT NULL,
    port        integer CHECK (port BETWEEN 0 AND 65535),  -- NULL = host-level up/down
    up          boolean NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX run_observations_uniq ON run_observations(run_id, ip, COALESCE(port, -1));
CREATE INDEX run_observations_ip_idx ON run_observations(ip, observed_at);

CREATE TABLE signatures (
    id               bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name             text NOT NULL UNIQUE,
    template_yaml    text NOT NULL,
    enabled          boolean NOT NULL DEFAULT false,
    valid            boolean NOT NULL DEFAULT false,
    validation_error text NOT NULL DEFAULT '',
    builtin          boolean NOT NULL DEFAULT false,
    created_by       bigint REFERENCES users(id) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    CHECK (NOT enabled OR valid)
);

CREATE TABLE artifacts (
    id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id      bigint NOT NULL REFERENCES runs(id) ON DELETE CASCADE,
    batch_id    bigint REFERENCES batches(id) ON DELETE CASCADE,
    scanner     text NOT NULL,
    content_enc bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX artifacts_run_idx ON artifacts(run_id);

CREATE TABLE dojo_assets (
    id        bigint PRIMARY KEY,  -- Dojo Asset (Product) id
    name      text NOT NULL,
    ip        inet,
    tags      text[] NOT NULL DEFAULT '{}',
    synced_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX dojo_assets_ip_idx ON dojo_assets(ip);

CREATE TABLE dojo_findings (
    id                 bigint PRIMARY KEY,  -- Dojo Finding id
    asset_id           bigint,              -- no FK: the mirror is synced in pages
    ip                 inet,
    title              text NOT NULL,
    severity           text NOT NULL CHECK (severity IN ('Info', 'Low', 'Medium', 'High', 'Critical')),
    active             boolean NOT NULL,
    verified           boolean NOT NULL DEFAULT false,
    false_p            boolean NOT NULL DEFAULT false,
    risk_accepted      boolean NOT NULL DEFAULT false,
    is_mitigated       boolean NOT NULL DEFAULT false,
    tags               text[] NOT NULL DEFAULT '{}',
    scanner            text NOT NULL DEFAULT '',
    date               date,
    last_status_update timestamptz,
    synced_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX dojo_findings_ip_idx ON dojo_findings(ip);
CREATE INDEX dojo_findings_severity_idx ON dojo_findings(severity) WHERE active;

CREATE TABLE audit_log (
    id        bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id   bigint REFERENCES users(id) ON DELETE SET NULL,  -- NULL = system / anonymous
    action    text NOT NULL,
    object    text NOT NULL,
    object_id text NOT NULL DEFAULT '',
    diff      jsonb NOT NULL DEFAULT '{}',
    at        timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX audit_log_at_idx ON audit_log(at DESC);

-- +goose Down
DROP TABLE audit_log, dojo_findings, dojo_assets, artifacts, signatures, run_observations,
    http_observations, services, hosts, batches, runs, schedules, targets, scope_entries,
    profiles, api_tokens, sessions, users;
DROP FUNCTION asi_dec(bytea);
DROP FUNCTION asi_enc(text);
