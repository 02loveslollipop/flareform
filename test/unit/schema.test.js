import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { requireD1 } from "../../src/db/connection.js";

const migration = readFileSync(
  new URL("../../migrations/0001_initial.sql", import.meta.url),
  "utf8",
);
const now = "2026-09-11T00:00:00Z";

function database(t) {
  const db = new DatabaseSync(":memory:");
  db.exec("PRAGMA foreign_keys = ON");
  db.exec(migration);
  t.after(() => db.close());
  return db;
}

function seed(db) {
  const zone = db.prepare(
    "INSERT INTO zones(name, cloudflare_zone_id, created_at) VALUES (?, ?, ?)",
  );
  zone.run("example.com", "zone-a", now);
  zone.run("example.net", "zone-b", now);
  const repository = db.prepare(`
    INSERT INTO repositories(github_repository_id, github_owner_id, display_name,
      expected_workflow_ref, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)
  `);
  repository.run(
    "100",
    "10",
    "A",
    "owner/a/.github/workflows/deploy.yml@refs/heads/main",
    now,
    now,
  );
  repository.run(
    "200",
    "20",
    "B",
    "owner/b/.github/workflows/deploy.yml@refs/heads/main",
    now,
    now,
  );
}

function claim(db, repo, zone, name = "api.example.com", type = "A") {
  return db
    .prepare(
      `
    INSERT INTO record_claims(repository_id, zone_id, name, type, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `,
    )
    .run(repo, zone, name, type, now, now);
}

function record(db, repo, claimId, zone, key, cfId) {
  return db
    .prepare(
      `
    INSERT INTO managed_records(repository_id, record_claim_id, zone_id, client_key,
      cloudflare_record_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)
  `,
    )
    .run(repo, claimId, zone, key, cfId, now, now);
}

test("DB-SCHEMA-001 initial SQL creates every planned table and critical index", (t) => {
  const db = database(t);
  const tables = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table'")
    .all()
    .map((row) => row.name);
  for (const name of [
    "zones",
    "repositories",
    "repository_grants",
    "record_claims",
    "managed_records",
    "oidc_jti",
    "plans",
    "operations",
    "operation_zones",
    "audit_log",
  ])
    assert.ok(tables.includes(name), name);
  const indexes = db
    .prepare("SELECT name FROM sqlite_master WHERE type = 'index'")
    .all()
    .map((row) => row.name);
  for (const name of [
    "idx_jti_expiry",
    "idx_plans_active_expiry",
    "idx_operations_retry",
    "idx_audit_operation",
  ]) {
    assert.ok(indexes.includes(name), name);
  }
});

test("DB-SCHEMA-002 test connection explicitly enforces foreign keys", (t) => {
  const db = database(t);
  assert.equal(db.prepare("PRAGMA foreign_keys").get().foreign_keys, 1);
  assert.throws(() => claim(db, 999, 999), /FOREIGN KEY/);
});

test("DB-SCHEMA-002 runtime D1 binding rejects disabled or unreadable foreign keys", async () => {
  const enabled = {
    prepare: () => ({ first: async () => ({ foreign_keys: 1 }) }),
  };
  const disabled = {
    prepare: () => ({ first: async () => ({ foreign_keys: 0 }) }),
  };
  const broken = {
    prepare: () => ({
      first: async () => {
        throw new Error("not available");
      },
    }),
  };
  assert.equal(await requireD1({ DB: enabled }), enabled);
  await assert.rejects(requireD1({ DB: disabled }), { code: "DATABASE_ERROR" });
  await assert.rejects(requireD1({ DB: broken }), { code: "DATABASE_ERROR" });
  await assert.rejects(requireD1({}), { code: "DATABASE_ERROR" });
});

test("DB-SCHEMA-003 duplicate zone name and Cloudflare zone ID fail", (t) => {
  const db = database(t);
  seed(db);
  const insert = db.prepare(
    "INSERT INTO zones(name, cloudflare_zone_id, created_at) VALUES (?, ?, ?)",
  );
  assert.throws(() => insert.run("example.com", "zone-c", now), /UNIQUE/);
  assert.throws(() => insert.run("elsewhere.example", "zone-a", now), /UNIQUE/);
  assert.throws(() => insert.run("UPPER.example", "zone-c", now), /CHECK/);
});

test("DB-SCHEMA-004 duplicate immutable GitHub repository ID fails", (t) => {
  const db = database(t);
  seed(db);
  assert.throws(
    () =>
      db
        .prepare(
          `
    INSERT INTO repositories(github_repository_id, github_owner_id, display_name,
      expected_workflow_ref, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)
  `,
        )
        .run("100", "other-owner", "Other", "workflow", now, now),
    /UNIQUE/,
  );
});

test("DB-SCHEMA-005 claim ownership is unique per zone/name/type", (t) => {
  const db = database(t);
  seed(db);
  claim(db, 1, 1);
  assert.throws(() => claim(db, 2, 1), /UNIQUE/);
  assert.doesNotThrow(() => claim(db, 2, 1, "api.example.com", "AAAA"));
  assert.doesNotThrow(() => claim(db, 2, 2, "api.example.com", "A"));
});

test("DB-SCHEMA-006 managed record must match claim owner and zone", (t) => {
  const db = database(t);
  seed(db);
  const id = Number(claim(db, 1, 1).lastInsertRowid);
  assert.throws(
    () => record(db, 2, id, 1, "other-owner", "cf-other"),
    /FOREIGN KEY/,
  );
  assert.throws(
    () => record(db, 1, id, 2, "other-zone", "cf-other"),
    /FOREIGN KEY/,
  );
  assert.doesNotThrow(() => record(db, 1, id, 1, "correct", "cf-correct"));
});

test("DB-SCHEMA-007 logical keys and Cloudflare IDs are unique while multi-value sets work", (t) => {
  const db = database(t);
  seed(db);
  const id = Number(claim(db, 1, 1).lastInsertRowid);
  record(db, 1, id, 1, "address-one", "cf-1");
  record(db, 1, id, 1, "address-two", "cf-2");
  assert.equal(
    db
      .prepare(
        "SELECT count(*) AS n FROM managed_records WHERE record_claim_id = ?",
      )
      .get(id).n,
    2,
  );
  assert.throws(() => record(db, 1, id, 1, "address-one", "cf-3"), /UNIQUE/);
  assert.throws(() => record(db, 1, id, 1, "address-three", "cf-1"), /UNIQUE/);
});

test("DB-SCHEMA-008 invalid grant, claim state/type, and NS permission fail", (t) => {
  const db = database(t);
  seed(db);
  const grant = db.prepare(`
    INSERT INTO repository_grants(repository_id, zone_id, grant_kind, hostname_root, allow_ns)
    VALUES (1, 1, ?, 'example-app.example.com', ?)
  `);
  assert.throws(() => grant.run("wildcard", 0), /CHECK/);
  assert.throws(() => grant.run("exact", 1), /CHECK/);
  assert.doesNotThrow(() => grant.run("descendants", 0));
  assert.throws(() => claim(db, 1, 1, "api.example.com", "NS"), /CHECK/);
  const id = Number(claim(db, 1, 1).lastInsertRowid);
  assert.throws(
    () =>
      db
        .prepare("UPDATE record_claims SET state = 'unknown' WHERE id = ?")
        .run(id),
    /CHECK/,
  );
});
