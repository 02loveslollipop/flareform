-- D1 is the sole FlareForm persistence layer. Audit events remain relational,
-- and scheduled inventory/ownership evidence is stored in immutable SQL rows.

DROP TABLE audit_exports;

CREATE TRIGGER immutable_audit_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;

CREATE TRIGGER immutable_audit_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit events are immutable'); END;

CREATE TABLE maintenance_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scheduled_at TEXT NOT NULL UNIQUE,
    cleanup_jtis INTEGER NOT NULL CHECK(cleanup_jtis >= 0),
    cleanup_plans INTEGER NOT NULL CHECK(cleanup_plans >= 0),
    inventory_complete INTEGER NOT NULL CHECK(inventory_complete IN (0, 1)),
    ownership_complete INTEGER NOT NULL CHECK(ownership_complete IN (0, 1)),
    ownership_healthy INTEGER NOT NULL CHECK(ownership_healthy >= 0),
    ownership_findings INTEGER NOT NULL CHECK(ownership_findings >= 0),
    success INTEGER NOT NULL CHECK(success IN (0, 1)),
    created_at TEXT NOT NULL
);

CREATE TABLE inventory_zone_snapshots (
    maintenance_run_id INTEGER NOT NULL REFERENCES maintenance_runs(id),
    zone TEXT NOT NULL,
    complete INTEGER NOT NULL CHECK(complete IN (0, 1)),
    error_code TEXT,
    PRIMARY KEY(maintenance_run_id, zone)
);

CREATE TABLE inventory_record_snapshots (
    maintenance_run_id INTEGER NOT NULL REFERENCES maintenance_runs(id),
    zone TEXT NOT NULL,
    cloudflare_record_id TEXT NOT NULL,
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    content_json TEXT NOT NULL CHECK(json_valid(content_json)),
    proxied INTEGER NOT NULL CHECK(proxied IN (0, 1)),
    ttl INTEGER,
    comment TEXT,
    tags_json TEXT NOT NULL CHECK(json_valid(tags_json)),
    classification TEXT NOT NULL,
    service TEXT,
    github_repository TEXT,
    deployment_platform TEXT,
    mirrored_domain TEXT,
    PRIMARY KEY(maintenance_run_id, zone, cloudflare_record_id)
);
CREATE INDEX idx_inventory_record_identity
ON inventory_record_snapshots(zone, name, type, maintenance_run_id);

CREATE TABLE ownership_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    maintenance_run_id INTEGER NOT NULL REFERENCES maintenance_runs(id),
    finding TEXT NOT NULL,
    zone TEXT,
    name TEXT,
    type TEXT,
    repository_id TEXT,
    client_key TEXT,
    cloudflare_record_id TEXT,
    d1_row_id INTEGER
);
CREATE INDEX idx_ownership_finding_run
ON ownership_findings(maintenance_run_id, finding);

CREATE TRIGGER immutable_maintenance_run_update BEFORE UPDATE ON maintenance_runs
BEGIN SELECT RAISE(ABORT, 'maintenance runs are immutable'); END;

CREATE TRIGGER immutable_maintenance_run_delete BEFORE DELETE ON maintenance_runs
BEGIN SELECT RAISE(ABORT, 'maintenance runs are immutable'); END;

CREATE TRIGGER immutable_inventory_zone_update BEFORE UPDATE ON inventory_zone_snapshots
BEGIN SELECT RAISE(ABORT, 'inventory snapshots are immutable'); END;

CREATE TRIGGER immutable_inventory_zone_delete BEFORE DELETE ON inventory_zone_snapshots
BEGIN SELECT RAISE(ABORT, 'inventory snapshots are immutable'); END;

CREATE TRIGGER immutable_inventory_record_update BEFORE UPDATE ON inventory_record_snapshots
BEGIN SELECT RAISE(ABORT, 'inventory snapshots are immutable'); END;

CREATE TRIGGER immutable_inventory_record_delete BEFORE DELETE ON inventory_record_snapshots
BEGIN SELECT RAISE(ABORT, 'inventory snapshots are immutable'); END;

CREATE TRIGGER immutable_ownership_finding_update BEFORE UPDATE ON ownership_findings
BEGIN SELECT RAISE(ABORT, 'ownership findings are immutable'); END;

CREATE TRIGGER immutable_ownership_finding_delete BEFORE DELETE ON ownership_findings
BEGIN SELECT RAISE(ABORT, 'ownership findings are immutable'); END;
