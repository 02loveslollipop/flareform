-- M4 admission is atomic: a logical operation, token use, affected record-set
-- locks, zone checkpoints, and any destructive plan are admitted together.
ALTER TABLE operations ADD COLUMN policy_version TEXT;
ALTER TABLE operation_zones ADD COLUMN dns_state_sha256 TEXT;
ALTER TABLE audit_log ADD COLUMN github_run_attempt TEXT;
ALTER TABLE audit_log ADD COLUMN workflow_ref TEXT;

CREATE TABLE audit_exports (
    audit_id INTEGER PRIMARY KEY REFERENCES audit_log(id),
    object_key TEXT NOT NULL UNIQUE,
    exported_at TEXT NOT NULL
);

CREATE TABLE operation_locks (
    zone_id INTEGER NOT NULL REFERENCES zones(id),
    name TEXT NOT NULL,
    type TEXT NOT NULL,
    operation_id TEXT NOT NULL REFERENCES operations(id),
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    created_at TEXT NOT NULL,
    PRIMARY KEY(zone_id, name, type)
);
CREATE INDEX idx_operation_locks_operation ON operation_locks(operation_id);

CREATE TRIGGER validate_operation_lock BEFORE INSERT ON operation_locks
BEGIN
    SELECT (CASE WHEN EXISTS (
        SELECT 1 FROM record_claims c
        WHERE c.zone_id = NEW.zone_id AND c.name = NEW.name AND c.type = NEW.type
          AND (c.repository_id <> NEW.repository_id OR c.state <> 'active')
    ) THEN RAISE(ABORT, 'claim not available') END);
END;

CREATE TABLE plan_admissions (
    plan_id TEXT PRIMARY KEY REFERENCES plans(id),
    operation_id TEXT NOT NULL UNIQUE REFERENCES operations(id),
    repository_id INTEGER NOT NULL REFERENCES repositories(id),
    manifest_sha256 TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    dns_state_sha256 TEXT NOT NULL,
    reserved_epoch INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TRIGGER validate_plan_admission BEFORE INSERT ON plan_admissions
BEGIN
    SELECT (CASE WHEN NOT EXISTS (
        SELECT 1 FROM plans p JOIN operations o ON o.id = NEW.operation_id
        WHERE p.id = NEW.plan_id
          AND p.repository_id = NEW.repository_id
          AND o.repository_id = NEW.repository_id
          AND o.manifest_sha256 = NEW.manifest_sha256
          AND p.manifest_sha256 = NEW.manifest_sha256
          AND p.policy_version = NEW.policy_version
          AND p.dns_state_sha256 = NEW.dns_state_sha256
          AND p.consumed_at IS NULL
          AND p.expires_at > NEW.reserved_epoch
    ) THEN RAISE(ABORT, 'plan precondition failed') END);
END;

-- A sent request is ambiguous after process loss or provider failure. It may
-- only be confirmed by the original execution path or resolved by an operator.
CREATE TABLE mutation_intents (
    operation_id TEXT NOT NULL REFERENCES operations(id),
    zone_id INTEGER NOT NULL REFERENCES zones(id),
    client_key TEXT NOT NULL,
    record_name TEXT NOT NULL,
    record_type TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('create', 'update', 'delete')),
    cloudflare_record_id TEXT,
    confirmed_record_id TEXT,
    status TEXT NOT NULL DEFAULT 'prepared'
        CHECK(status IN ('prepared', 'sent', 'confirmed', 'indeterminate', 'resolved')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(operation_id, client_key),
    CHECK((action = 'create' AND cloudflare_record_id IS NULL) OR
          (action IN ('update', 'delete') AND cloudflare_record_id IS NOT NULL))
);
CREATE INDEX idx_mutation_intents_status ON mutation_intents(status, updated_at);

CREATE TRIGGER validate_mutation_intent BEFORE INSERT ON mutation_intents
BEGIN
    SELECT (CASE WHEN NOT EXISTS (
        SELECT 1 FROM operation_locks l
        WHERE l.operation_id = NEW.operation_id AND l.zone_id = NEW.zone_id
          AND l.name = NEW.record_name AND l.type = NEW.record_type
    ) THEN RAISE(ABORT, 'mutation lock missing') END);
END;

CREATE TRIGGER validate_mutation_status BEFORE UPDATE OF status ON mutation_intents
BEGIN
    SELECT (CASE WHEN NOT (
        (OLD.status = 'prepared' AND NEW.status = 'sent') OR
        (OLD.status = 'sent' AND NEW.status IN ('confirmed', 'indeterminate')) OR
        (OLD.status = 'indeterminate' AND NEW.status = 'resolved')
    ) THEN RAISE(ABORT, 'invalid mutation transition') END);
END;

CREATE TRIGGER validate_mutation_confirmation BEFORE UPDATE OF status ON mutation_intents
WHEN NEW.status = 'confirmed'
BEGIN
    SELECT (CASE WHEN NEW.action IN ('create', 'update') AND NOT EXISTS (
        SELECT 1 FROM managed_records m JOIN operation_locks l
          ON l.operation_id = NEW.operation_id AND l.zone_id = NEW.zone_id
         AND l.name = NEW.record_name AND l.type = NEW.record_type
        WHERE m.repository_id = l.repository_id AND m.client_key = NEW.client_key
          AND m.zone_id = NEW.zone_id
          AND m.cloudflare_record_id = NEW.confirmed_record_id
    ) THEN RAISE(ABORT, 'record confirmation missing') END);
    SELECT (CASE WHEN NEW.action = 'delete' AND EXISTS (
        SELECT 1 FROM managed_records m JOIN operation_locks l
          ON l.operation_id = NEW.operation_id AND l.zone_id = NEW.zone_id
         AND l.name = NEW.record_name AND l.type = NEW.record_type
        WHERE m.repository_id = l.repository_id AND m.client_key = NEW.client_key
    ) THEN RAISE(ABORT, 'record deletion unconfirmed') END);
END;

CREATE TRIGGER validate_lock_release BEFORE DELETE ON operation_locks
BEGIN
    SELECT (CASE WHEN EXISTS (
        SELECT 1 FROM mutation_intents m
        WHERE m.operation_id = OLD.operation_id AND m.zone_id = OLD.zone_id
          AND m.status NOT IN ('confirmed', 'resolved')
    ) THEN RAISE(ABORT, 'mutation unresolved') END);
END;
