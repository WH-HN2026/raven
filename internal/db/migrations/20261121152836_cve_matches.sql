-- +goose Up
-- C3: offline CVE matches, one row per open service whose product+version
-- matches the committed NVD data (architecture §11), and the per-IP hash of
-- what was last pushed to Dojo's "ASI CVE match" test.
CREATE TABLE cve_matches (
    ip         inet NOT NULL REFERENCES hosts(ip) ON DELETE CASCADE,
    port       integer NOT NULL CHECK (port BETWEEN 0 AND 65535),
    proto      text NOT NULL,
    product    text NOT NULL,             -- display name, e.g. "Apache httpd"
    cpe        text NOT NULL,             -- vendor:product
    version    text NOT NULL,             -- matched upstream version
    cve_ids    text[] NOT NULL,           -- by CVSS desc
    hits       jsonb NOT NULL,            -- [{id, cvss, kev, epss}]
    max_cvss   real NOT NULL,
    kev        integer NOT NULL,          -- CVEs in CISA KEV
    distro     boolean NOT NULL,
    confidence text NOT NULL CHECK (confidence IN ('high', 'low')),
    severity   text NOT NULL,
    matched_at timestamptz NOT NULL,      -- first matched with this cpe+version
    updated_at timestamptz NOT NULL,      -- last match pass that produced it
    PRIMARY KEY (ip, port, proto)
);

CREATE TABLE cve_push (
    ip        inet PRIMARY KEY REFERENCES hosts(ip) ON DELETE CASCADE,
    hash      text NOT NULL,              -- of the match set last pushed; '' = empty set
    pushed_at timestamptz NOT NULL
);

-- +goose Down
DROP TABLE cve_push;
DROP TABLE cve_matches;
