import assert from "node:assert/strict";
import test from "node:test";
import {
  inspectIndeterminate,
  resolveIndeterminate,
} from "../../src/admin/reconcile.js";
import { DnsRepository } from "../../src/db/repository.js";
import { managedMetadata } from "../../src/dns/state.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";

const now = "2026-09-14T00:00:00Z";
const name = "example-app.example.com";
async function fixture(t) {
  const location = sqliteD1();
  t.after(location.close);
  const { sqlite, db } = location;
  sqlite
    .prepare(
      "INSERT INTO zones(name,cloudflare_zone_id,created_at) VALUES (?,?,?)",
    )
    .run("example.com", "a".repeat(32), now);
  sqlite
    .prepare(
      "INSERT INTO repositories(github_repository_id,github_owner_id,display_name,expected_workflow_ref,created_at,updated_at) VALUES (?,?,?,?,?,?)",
    )
    .run("100", "200", "repo", "workflow", now, now);
  const repo = new DnsRepository(db);
  await repo.reserveOperation({
    operation: {
      id: "ffop_test",
      repositoryId: 1,
      githubRunId: "500",
      githubRunAttempt: "1",
      operationType: "keep",
      manifestSha256: "digest",
    },
    jti: "jti",
    jtiExpiresAt: 2000000000,
    claims: [{ zoneId: 1, name, type: "A" }],
    locks: [{ zoneId: 1, name, type: "A" }],
    zoneIds: [1],
    now,
  });
  await repo.beginMutationIntent({
    operationId: "ffop_test",
    repositoryId: 1,
    zoneId: 1,
    zoneName: "example.com",
    clientKey: "main",
    recordName: name,
    recordType: "A",
    action: "create",
    newRecord: { name, type: "A", content: "192.0.2.1" },
    now,
  });
  await repo.markMutationSent("ffop_test", "main", now);
  await repo.markMutationIndeterminate({
    operationId: "ffop_test",
    repositoryId: 1,
    zoneId: 1,
    zoneName: "example.com",
    clientKey: "main",
    recordName: name,
    recordType: "A",
    errorCode: "CLOUDFLARE_API_ERROR",
    now,
  });
  return { ...location, repo };
}

test("REC-001 inspection is read-only, redacted, and requires explicit resolution", async (t) => {
  const f = await fixture(t);
  const provider = [
    {
      id: "c".repeat(32),
      name,
      type: "A",
      content: "192.0.2.1",
      ttl: 60,
      proxied: false,
      ...managedMetadata("100", "main"),
    },
  ];
  const cloudflare = { listRecords: async () => provider };
  const inspected = await inspectIndeterminate({
    db: f.db,
    cloudflare,
    operationId: "ffop_test",
    clientKey: "main",
  });
  assert.equal(inspected.exact.length, 1);
  assert.ok(inspected.auditCount >= 2);
  assert.equal(
    (await f.repo.getMutationIntent("ffop_test", "main")).status,
    "indeterminate",
  );
  await assert.rejects(
    resolveIndeterminate({
      db: f.db,
      cloudflare,
      operationId: "ffop_test",
      clientKey: "main",
      decision: "guess",
      operatorId: "900",
    }),
    {
      code: "INVALID_REQUEST",
    },
  );
  const resolved = await resolveIndeterminate({
    db: f.db,
    cloudflare,
    operationId: "ffop_test",
    clientKey: "main",
    decision: "confirm-provider",
    operatorId: "900",
    now: Date.parse(now),
  });
  assert.equal(resolved.resolved, true);
  assert.equal(
    (await f.repo.getManagedRecord(1, "main")).cloudflare_record_id,
    "c".repeat(32),
  );
  assert.equal(
    (await f.repo.listOperationLocks("ffop_test")).results.length,
    0,
  );
  assert.equal((await f.repo.getOperation("ffop_test")).status, "reconciled");
  assert.equal(
    f.sqlite.prepare("SELECT action FROM audit_log ORDER BY id DESC").get()
      .action,
    "admin_reconcile:confirm-provider",
  );
});

test("REC-002 ambiguous or unmanaged provider evidence cannot be resolved", async (t) => {
  const f = await fixture(t);
  for (const records of [
    [
      {
        id: "c".repeat(32),
        name,
        type: "A",
        content: "192.0.2.1",
        ttl: 60,
        tags: [],
        comment: "",
      },
    ],
    [
      {
        id: "c".repeat(32),
        name,
        type: "A",
        content: "192.0.2.1",
        ttl: 60,
        ...managedMetadata("100", "main"),
      },
      {
        id: "d".repeat(32),
        name,
        type: "A",
        content: "192.0.2.1",
        ttl: 60,
        ...managedMetadata("100", "main"),
      },
    ],
  ])
    await assert.rejects(
      resolveIndeterminate({
        db: f.db,
        cloudflare: { listRecords: async () => records },
        operationId: "ffop_test",
        clientKey: "main",
        decision: "confirm-provider",
        operatorId: "900",
      }),
      { code: "STATE_INDETERMINATE" },
    );
  assert.equal(
    (await f.repo.listOperationLocks("ffop_test")).results.length,
    1,
  );
});
