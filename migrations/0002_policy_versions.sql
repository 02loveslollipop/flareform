-- Policy sync retains immutable, canonical snapshots for rollback/audit.
CREATE TABLE policy_versions (
    version TEXT PRIMARY KEY CHECK(length(version) = 64),
    canonical_json TEXT NOT NULL,
    applied_at TEXT NOT NULL
);

CREATE TABLE policy_state (
    id INTEGER PRIMARY KEY CHECK(id = 1),
    current_version TEXT NOT NULL REFERENCES policy_versions(version),
    updated_at TEXT NOT NULL
);

CREATE TRIGGER immutable_zone_id BEFORE UPDATE OF cloudflare_zone_id ON zones
WHEN NEW.cloudflare_zone_id != OLD.cloudflare_zone_id
BEGIN SELECT RAISE(ABORT, 'zone identity is immutable'); END;

CREATE TRIGGER immutable_repository_owner BEFORE UPDATE OF github_owner_id ON repositories
WHEN NEW.github_owner_id != OLD.github_owner_id
BEGIN SELECT RAISE(ABORT, 'repository owner identity is immutable'); END;
