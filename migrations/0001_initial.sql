-- Initial FlareForm state. D1 enforces foreign keys by default.
-- Every name/type written to these tables must first pass canonical validation.

CREATE TABLE zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE CHECK(name = lower(name) AND length(name) BETWEEN 1 AND 253),
    cloudflare_zone_id TEXT NOT NULL UNIQUE,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE TABLE repositories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    github_repository_id TEXT NOT NULL UNIQUE,
    github_owner_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    expected_workflow_ref TEXT NOT NULL,
    expected_job_workflow_ref TEXT,
    allowed_ref TEXT NOT NULL DEFAULT 'refs/heads/main',
    allowed_environment TEXT NOT NULL DEFAULT 'production',
    allowed_event TEXT NOT NULL DEFAULT 'push',
    allowed_runner_environment TEXT NOT NULL DEFAULT 'github-hosted',
    allow_prune INTEGER NOT NULL DEFAULT 0 CHECK(allow_prune IN (0, 1)),
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE repository_grants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    zone_id INTEGER NOT NULL REFERENCES zones(id),
    grant_kind TEXT NOT NULL CHECK(grant_kind IN ('exact', 'descendants')),
    hostname_root TEXT NOT NULL CHECK(hostname_root = lower(hostname_root) AND length(hostname_root) BETWEEN 1 AND 253),
    allow_a INTEGER NOT NULL DEFAULT 1 CHECK(allow_a IN (0, 1)),
    allow_aaaa INTEGER NOT NULL DEFAULT 1 CHECK(allow_aaaa IN (0, 1)),
    allow_cname INTEGER NOT NULL DEFAULT 1 CHECK(allow_cname IN (0, 1)),
    allow_srv INTEGER NOT NULL DEFAULT 1 CHECK(allow_srv IN (0, 1)),
    allow_txt INTEGER NOT NULL DEFAULT 0 CHECK(allow_txt IN (0, 1)),
    allow_ns INTEGER NOT NULL DEFAULT 0 CHECK(allow_ns = 0),
    UNIQUE(repository_id, zone_id, grant_kind, hostname_root)
);

CREATE TABLE record_claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    zone_id INTEGER NOT NULL REFERENCES zones(id),
    name TEXT NOT NULL CHECK(name = lower(name) AND length(name) BETWEEN 1 AND 253),
    type TEXT NOT NULL CHECK(type IN ('A', 'AAAA', 'CNAME', 'SRV', 'TXT')),
    state TEXT NOT NULL DEFAULT 'active'
        CHECK(state IN ('reserved', 'active', 'pending_update', 'pending_delete', 'error')),
    version INTEGER NOT NULL DEFAULT 1 CHECK(version >= 1),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(zone_id, name, type),
    UNIQUE(id, repository_id, zone_id)
);

CREATE TABLE managed_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    record_claim_id INTEGER NOT NULL,
    zone_id INTEGER NOT NULL REFERENCES zones(id),
    client_key TEXT NOT NULL,
    cloudflare_record_id TEXT,
    content TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY(record_claim_id, repository_id, zone_id)
        REFERENCES record_claims(id, repository_id, zone_id),
    UNIQUE(repository_id, client_key),
    UNIQUE(zone_id, cloudflare_record_id)
);

CREATE TABLE oidc_jti (
    jti TEXT PRIMARY KEY,
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    expires_at INTEGER NOT NULL,
    used_at TEXT NOT NULL
);

CREATE TABLE plans (
    id TEXT PRIMARY KEY,
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    manifest_sha256 TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    dns_state_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    consumed_at TEXT
);

CREATE TABLE operations (
    id TEXT PRIMARY KEY,
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    github_run_id TEXT NOT NULL,
    github_run_attempt TEXT NOT NULL,
    requested_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL,
    manifest_sha256 TEXT NOT NULL,
    operation_type TEXT NOT NULL,
    UNIQUE(repository_id, github_run_id, github_run_attempt,
           operation_type, manifest_sha256)
);

CREATE TABLE operation_zones (
    operation_id TEXT NOT NULL REFERENCES operations(id),
    zone_id INTEGER NOT NULL REFERENCES zones(id),
    status TEXT NOT NULL,
    error_code TEXT,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(operation_id, zone_id)
);

CREATE TABLE audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    operation_id TEXT REFERENCES operations(id),
    repository_id INTEGER REFERENCES repositories(id),
    action TEXT NOT NULL,
    zone TEXT,
    record_name TEXT,
    record_type TEXT,
    old_value TEXT,
    new_value TEXT,
    success INTEGER NOT NULL CHECK(success IN (0, 1)),
    error_code TEXT,
    github_run_id TEXT,
    github_actor_id TEXT,
    created_at TEXT NOT NULL
);

CREATE INDEX idx_grants_zone_root ON repository_grants(zone_id, hostname_root, grant_kind);
CREATE INDEX idx_claims_owner_state ON record_claims(repository_id, state);
CREATE INDEX idx_records_claim ON managed_records(record_claim_id);
CREATE INDEX idx_jti_expiry ON oidc_jti(expires_at);
CREATE INDEX idx_plans_active_expiry ON plans(expires_at) WHERE consumed_at IS NULL;
CREATE INDEX idx_operations_retry ON operations(status, requested_at);
CREATE INDEX idx_operation_zones_retry ON operation_zones(status, updated_at);
CREATE INDEX idx_audit_operation ON audit_log(operation_id, id);
CREATE INDEX idx_audit_repository_time ON audit_log(repository_id, created_at);
