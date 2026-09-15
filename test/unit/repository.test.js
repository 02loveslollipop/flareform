import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DnsRepository } from "../../src/db/repository.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";

const now = "2026-09-11T00:00:00Z";

function fixture(t) {
  const location = sqliteD1();
  t.after(location.close);
  const { sqlite } = location;
  sqlite
    .prepare(
      "INSERT INTO zones(name,cloudflare_zone_id,created_at) VALUES (?,?,?)",
    )
    .run("example.com", "zone-a", now);
  sqlite
    .prepare(
      "INSERT INTO zones(name,cloudflare_zone_id,created_at) VALUES (?,?,?)",
    )
    .run("example.net", "zone-b", now);
  for (const [id, name] of [
    ["100", "A"],
    ["200", "B"],
  ])
    sqlite
      .prepare(
        "INSERT INTO repositories(github_repository_id,github_owner_id,display_name,expected_workflow_ref,created_at,updated_at) VALUES (?,?,?,?,?,?)",
      )
      .run(
        id,
        "10",
        name,
        "owner/repo/.github/workflows/deploy.yml@refs/heads/main",
        now,
        now,
      );
  return { ...location, repository: new DnsRepository(location.db) };
}

const operation = (id, repositoryId = 1, manifestSha256 = "hash") => ({
  id,
  repositoryId,
  githubRunId: "run",
  githubRunAttempt: "1",
  operationType: "apply",
  manifestSha256,
});

test("DB-REPO-001 CRUD round trips canonical names, types, grants and audit", async (t) => {
  const { sqlite, repository } = fixture(t);
  assert.equal((await repository.getZone("example.com")).name, "example.com");
  assert.equal((await repository.listZones()).results.length, 2);
  assert.equal((await repository.getRepository("100")).github_owner_id, "10");
  assert.equal((await repository.listRepositories()).results.length, 2);
  sqlite
    .prepare(
      "INSERT INTO repository_grants(repository_id,zone_id,grant_kind,hostname_root) VALUES (?,?,?,?)",
    )
    .run(1, 1, "exact", "api.example.com");
  assert.equal((await repository.listGrants(1)).results.length, 1);
  const reserved = await repository.reserveOperation({
    operation: operation("op1"),
    jti: "jti1",
    jtiExpiresAt: 99,
    claims: [{ zoneId: 1, name: "api.example.com", type: "A" }],
    now,
  });
  assert.equal(reserved.reused, false);
  assert.equal((await repository.getJti("jti1")).repository_id, 1);
  const claim = await repository.getClaim(1, "api.example.com", "A");
  assert.equal(claim.state, "reserved");
  await repository.upsertManagedRecord({
    repositoryId: 1,
    claimId: claim.id,
    zoneId: 1,
    clientKey: "key",
    cloudflareRecordId: "cf1",
    content: "192.0.2.1",
    now,
  });
  assert.equal(
    (await repository.getManagedRecord(1, "key")).cloudflare_record_id,
    "cf1",
  );
  assert.equal((await repository.listManagedRecords(1)).results.length, 1);
  await repository.appendAudit({
    operationId: "op1",
    repositoryId: 1,
    action: "reserve",
    success: true,
    now,
  });
  assert.equal(
    sqlite.prepare("SELECT old_value,new_value FROM audit_log").get().old_value,
    null,
  );
  await repository.deleteManagedRecord(1, "key");
  assert.equal(await repository.getManagedRecord(1, "key"), null);
  await repository.updateOperation({
    id: "op1",
    repositoryId: 1,
    status: "complete",
    completedAt: now,
  });
  assert.equal((await repository.getOperation("op1")).status, "complete");
});

test("DB-REPO-003/004 and CONC-001 reservation is all-or-nothing with one owner", async (t) => {
  const { sqlite, repository } = fixture(t);
  const first = repository.reserveOperation({
    operation: operation("op1"),
    jti: "jti1",
    jtiExpiresAt: 99,
    claims: [{ zoneId: 1, name: "api.example.com", type: "A" }],
    now,
  });
  const second = repository.reserveOperation({
    operation: operation("op2", 2, "other"),
    jti: "jti2",
    jtiExpiresAt: 99,
    claims: [{ zoneId: 1, name: "api.example.com", type: "A" }],
    now,
  });
  const results = await Promise.allSettled([first, second]);
  assert.equal(
    results.filter((result) => result.status === "fulfilled").length,
    1,
  );
  assert.equal(
    results.filter((result) => result.status === "rejected").length,
    1,
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM record_claims").get().n,
    1,
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM operations").get().n,
    1,
  );
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM oidc_jti").get().n, 1);
  await assert.rejects(
    repository.reserveOperation({
      operation: operation("op3", 2, "third"),
      jti: "jti3",
      jtiExpiresAt: 99,
      claims: [{ zoneId: 999, name: "bad.example.com", type: "A" }],
      now,
    }),
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM operations").get().n,
    1,
  );
  assert.equal(await repository.getJti("jti3"), null);
});

test("DB-REPO-004 failures at operation, JTI, and claim stages roll back", async (t) => {
  const { sqlite, repository } = fixture(t);
  await repository.reserveOperation({
    operation: operation("seed"),
    jti: "used",
    jtiExpiresAt: 99,
    claims: [],
    now,
  });
  for (const [op, jti, claims] of [
    [operation("bad-owner", 999, "one"), "new1", []],
    [operation("bad-jti", 1, "two"), "used", []],
    [
      operation("bad-claim", 1, "three"),
      "new3",
      [{ zoneId: 999, name: "api.example.com", type: "A" }],
    ],
  ]) {
    await assert.rejects(
      repository.reserveOperation({
        operation: op,
        jti,
        jtiExpiresAt: 99,
        claims,
        now,
      }),
    );
    assert.equal(await repository.getOperation(op.id), null);
    assert.equal(
      sqlite.prepare("SELECT count(*) AS n FROM operations").get().n,
      1,
    );
  }
  assert.equal(await repository.getJti("new1"), null);
  assert.equal(await repository.getJti("new3"), null);
});

test("DB-REPO-002 idempotency uses logical run key, not the fresh JTI", async (t) => {
  const { sqlite, repository } = fixture(t);
  const first = await repository.reserveOperation({
    operation: operation("op1"),
    jti: "jti1",
    jtiExpiresAt: 99,
    claims: [],
    now,
  });
  const second = await repository.reserveOperation({
    operation: operation("op2"),
    jti: "fresh-jti",
    jtiExpiresAt: 99,
    claims: [],
    now,
  });
  assert.equal(second.reused, true);
  assert.equal(second.operation.id, first.operation.id);
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM oidc_jti").get().n, 2);
});

test("DB-REPO-005 stale compare-and-set fails", async (t) => {
  const { repository } = fixture(t);
  await repository.reserveOperation({
    operation: operation("op1"),
    jti: "jti1",
    jtiExpiresAt: 99,
    claims: [{ zoneId: 1, name: "api.example.com", type: "A" }],
    now,
  });
  const claim = await repository.getClaim(1, "api.example.com", "A");
  assert.equal(
    (
      await repository.compareAndSetClaim({
        id: claim.id,
        repositoryId: 1,
        version: 1,
        state: "active",
        now,
      })
    ).version,
    2,
  );
  assert.equal(
    await repository.compareAndSetClaim({
      id: claim.id,
      repositoryId: 1,
      version: 1,
      state: "pending_delete",
      now,
    }),
    null,
  );
});

test("DB-REPO-006 plan consumption is one-time and expires", async (t) => {
  const { repository } = fixture(t);
  await repository.createPlan({
    id: "plan1",
    repositoryId: 1,
    manifestSha256: "m",
    policyVersion: "v",
    dnsStateSha256: "s",
    createdAt: now,
    expiresAt: 100,
  });
  assert.equal((await repository.getPlan("plan1")).policy_version, "v");
  assert.equal((await repository.getActivePlan("plan1", 1, 50)).id, "plan1");
  assert.equal(await repository.getActivePlan("plan1", 2, 50), null);
  const [one, two] = await Promise.all([
    repository.consumePlan({
      id: "plan1",
      repositoryId: 1,
      nowEpoch: 50,
      consumedAt: now,
    }),
    repository.consumePlan({
      id: "plan1",
      repositoryId: 1,
      nowEpoch: 50,
      consumedAt: now,
    }),
  ]);
  assert.equal([one, two].filter(Boolean).length, 1);
  await repository.createPlan({
    id: "plan2",
    repositoryId: 1,
    manifestSha256: "m",
    policyVersion: "v",
    dnsStateSha256: "s",
    createdAt: now,
    expiresAt: 100,
  });
  assert.equal(
    await repository.consumePlan({
      id: "plan2",
      repositoryId: 1,
      nowEpoch: 100,
      consumedAt: now,
    }),
    null,
  );
});

test("DB-REPO-007 checkpoints survive repository instance and database restart", async (t) => {
  const dir = await mkdtemp(join(tmpdir(), "flareform-repo-test-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const file = join(dir, "db.sqlite");
  const first = sqliteD1(file);
  first.sqlite
    .prepare(
      "INSERT INTO zones(name,cloudflare_zone_id,created_at) VALUES (?,?,?)",
    )
    .run("example.com", "z", now);
  first.sqlite
    .prepare(
      "INSERT INTO repositories(github_repository_id,github_owner_id,display_name,expected_workflow_ref,created_at,updated_at) VALUES (?,?,?,?,?,?)",
    )
    .run(
      "1",
      "1",
      "A",
      "owner/repo/.github/workflows/deploy.yml@refs/heads/main",
      now,
      now,
    );
  first.sqlite
    .prepare(
      "INSERT INTO operations(id,repository_id,github_run_id,github_run_attempt,requested_at,status,manifest_sha256,operation_type) VALUES (?,?,?,?,?,?,?,?)",
    )
    .run("op", 1, "run", "1", now, "running", "m", "apply");
  await new DnsRepository(first.db).upsertCheckpoint({
    operationId: "op",
    zoneId: 1,
    status: "done",
    now,
  });
  first.close();
  const second = sqliteD1(file, false);
  t.after(second.close);
  assert.equal(
    (await new DnsRepository(second.db).getCheckpoint("op", 1)).status,
    "done",
  );
});
