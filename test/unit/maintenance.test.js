import assert from "node:assert/strict";
import test from "node:test";
import {
  cleanupEphemeralState,
  runScheduledMaintenance,
  storeMaintenanceRun,
} from "../../src/operations/maintenance.js";
import { DnsRepository } from "../../src/db/repository.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";

test("OIDC-REPLAY-003/OPS maintenance deletes only expired unreferenced ephemeral state", async (t) => {
  const location = sqliteD1();
  t.after(location.close);
  const sql = location.sqlite;
  sql
    .prepare(
      "INSERT INTO zones(name,cloudflare_zone_id,created_at) VALUES(?,?,?)",
    )
    .run("example.com", "zone", "now");
  sql
    .prepare(
      `INSERT INTO repositories(github_repository_id,github_owner_id,display_name,expected_workflow_ref,created_at,updated_at) VALUES(?,?,?,?,?,?)`,
    )
    .run(
      "1",
      "2",
      "repo",
      "owner/repo/.github/workflows/dns.yml@refs/heads/main",
      "now",
      "now",
    );
  sql.prepare("INSERT INTO oidc_jti VALUES(?,?,?,?)").run("old", 1, 99, "now");
  sql
    .prepare("INSERT INTO oidc_jti VALUES(?,?,?,?)")
    .run("boundary", 1, 100, "now");
  sql
    .prepare(
      "INSERT INTO plans(id,repository_id,manifest_sha256,policy_version,dns_state_sha256,created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
    )
    .run("old", 1, "m", "p", "d", "now", 99);
  sql
    .prepare(
      "INSERT INTO plans(id,repository_id,manifest_sha256,policy_version,dns_state_sha256,created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
    )
    .run("boundary", 1, "m", "p", "d", "now", 100);
  await cleanupEphemeralState(location.db, 100);
  assert.deepEqual(
    sql
      .prepare("SELECT jti FROM oidc_jti ORDER BY jti")
      .all()
      .map((row) => row.jti),
    ["boundary"],
  );
  assert.deepEqual(
    sql
      .prepare("SELECT id FROM plans ORDER BY id")
      .all()
      .map((row) => row.id),
    ["boundary"],
  );
});

test("maintenance cleanup rejects an invalid clock without touching state", async (t) => {
  const location = sqliteD1();
  t.after(location.close);
  await assert.rejects(cleanupEphemeralState(location.db, -1), TypeError);
});

test("OPS-D1-001 maintenance evidence is relational, immutable, and atomic", async (t) => {
  const location = sqliteD1();
  t.after(location.close);
  const event = {
    event: "scheduled_security_maintenance",
    success: false,
    cleanup: { jtis: 2, plans: 1 },
    inventory_complete: true,
    ownership_complete: true,
    ownership_findings: 1,
    scheduled_at: "2026-09-15T03:17:00.000Z",
  };
  const inventory = {
    complete: true,
    zones: [
      {
        zone: "example.com",
        complete: true,
        records: [
          {
            zone: "example.com",
            cloudflare_record_id: "record-1",
            name: "app.example.com",
            type: "A",
            content: "192.0.2.1",
            proxied: false,
            ttl: 300,
            comment: null,
            tags: ["managed-by:flareform"],
            classification: "unknown",
            service: null,
            github_repository: null,
            deployment_platform: null,
            mirrored_domain: null,
          },
        ],
      },
    ],
  };
  const ownership = {
    complete: true,
    healthy: 0,
    findings: [
      {
        finding: "missing_record",
        zone: "example.com",
        name: "app.example.com",
        type: "A",
        repository_id: "100",
        client_key: "app",
      },
    ],
  };

  await storeMaintenanceRun(location.db, { event, inventory, ownership });
  assert.equal(
    location.sqlite.prepare("SELECT count(*) AS n FROM maintenance_runs").get()
      .n,
    1,
  );
  assert.deepEqual(
    {
      ...location.sqlite
        .prepare(
          "SELECT zone,name,type,json_extract(content_json, '$') AS content FROM inventory_record_snapshots",
        )
        .get(),
    },
    {
      zone: "example.com",
      name: "app.example.com",
      type: "A",
      content: "192.0.2.1",
    },
  );
  assert.equal(
    location.sqlite.prepare("SELECT finding FROM ownership_findings").get()
      .finding,
    "missing_record",
  );
  assert.throws(
    () => location.sqlite.exec("UPDATE maintenance_runs SET success = 1"),
    /immutable/,
  );
  await assert.rejects(
    storeMaintenanceRun(location.db, { event, inventory, ownership }),
    { code: "DATABASE_ERROR" },
  );
  assert.equal(
    location.sqlite.prepare("SELECT count(*) AS n FROM maintenance_runs").get()
      .n,
    1,
  );
});

test("OPS-D1-002 scheduled maintenance needs no object store and retries idempotently", async (t) => {
  const location = sqliteD1();
  t.after(location.close);
  let inventoryCalls = 0;
  let ownershipCalls = 0;
  const options = {
    db: location.db,
    token: "runtime-token",
    scheduledTime: 1_757_903_820_000,
    inventoryFactory: async () => {
      inventoryCalls++;
      return { complete: true, zones: [] };
    },
    ownershipFactory: async () => {
      ownershipCalls++;
      return { complete: true, healthy: 0, findings: [] };
    },
    emit: () => {},
  };
  const first = await runScheduledMaintenance(options);
  const retry = await runScheduledMaintenance(options);
  assert.deepEqual(retry, first);
  assert.equal(inventoryCalls, 1);
  assert.equal(ownershipCalls, 1);
  assert.equal(first.success, true);
});

test("AUD-D1-001 operational audit rows are append-only", async (t) => {
  const location = sqliteD1();
  t.after(location.close);
  const repo = new DnsRepository(location.db);
  await repo.appendAudit({ action: "test", success: true, now: "now" });
  assert.throws(
    () => location.sqlite.exec("UPDATE audit_log SET action = 'changed'"),
    /immutable/,
  );
  assert.throws(
    () => location.sqlite.exec("DELETE FROM audit_log"),
    /immutable/,
  );
});
