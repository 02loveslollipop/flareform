import assert from "node:assert/strict";
import test from "node:test";
import { DnsRepository } from "../../src/db/repository.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";

const now = "2026-09-12T00:00:00Z";
const zoneId = "a".repeat(32);
function fixture(t) {
  const location = sqliteD1();
  t.after(location.close);
  const { sqlite, db } = location;
  sqlite
    .prepare(
      "INSERT INTO zones(name, cloudflare_zone_id, created_at) VALUES (?, ?, ?)",
    )
    .run("example.com", zoneId, now);
  sqlite
    .prepare(
      "INSERT INTO zones(name, cloudflare_zone_id, created_at) VALUES (?, ?, ?)",
    )
    .run("example.net", "b".repeat(32), now);
  for (const id of ["100", "200"])
    sqlite
      .prepare(
        "INSERT INTO repositories(github_repository_id,github_owner_id,display_name,expected_workflow_ref,created_at,updated_at) VALUES (?,?,?,?,?,?)",
      )
      .run(
        id,
        "10",
        id,
        "owner/repo/.github/workflows/deploy.yml@refs/heads/main",
        now,
        now,
      );
  return { sqlite, repository: new DnsRepository(db) };
}
const op = (id, repositoryId = 1, hash = "hash") => ({
  id,
  repositoryId,
  githubRunId: id,
  githubRunAttempt: "1",
  operationType: "apply",
  manifestSha256: hash,
});
const lock = { zoneId: 1, name: "example-app.example.com", type: "A" };
const reserve = (repository, operation, jti, options = {}) =>
  repository.reserveOperation({
    operation,
    jti,
    jtiExpiresAt: 2000000000,
    now,
    nowEpoch: 100,
    ...options,
  });

test("OP-IDEM-001/CONC-001 operation, JTI, checkpoints and set locks commit atomically", async (t) => {
  const { sqlite, repository } = fixture(t);
  const first = await reserve(repository, op("ffop_first"), "jti-one", {
    claims: [lock],
    locks: [lock],
    zoneIds: [1, 2],
  });
  assert.equal(first.reused, false);
  assert.equal(
    (await repository.listCheckpoints(first.operation.id)).results.length,
    2,
  );
  assert.equal(
    (await repository.listOperationLocks(first.operation.id)).results.length,
    1,
  );
  assert.equal(
    (await repository.getClaim(1, lock.name, lock.type)).repository_id,
    1,
  );
  await assert.rejects(
    reserve(repository, op("ffop_other", 2), "jti-two", {
      locks: [lock],
      zoneIds: [1],
    }),
    {
      code: "OPERATION_IN_PROGRESS",
    },
  );
  assert.equal(await repository.getJti("jti-two"), null);
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM operations").get().n,
    1,
  );
  const retry = await reserve(
    repository,
    { ...op("ffop_retry"), githubRunId: "ffop_first" },
    "jti-three",
    { locks: [lock] },
  );
  assert.equal(retry.reused, true);
  assert.equal(retry.operation.id, first.operation.id);
  assert.equal((await repository.getJti("jti-three")).repository_id, 1);
  await assert.rejects(reserve(repository, op("ffop_replay"), "jti-three"), {
    code: "OIDC_TOKEN_REPLAYED",
  });
});

test("PRUNE-PRE-001/CONC-PLAN-001 plan is consumed with operation or not at all", async (t) => {
  const { sqlite, repository } = fixture(t);
  await repository.createPlan({
    id: "plan-one",
    repositoryId: 1,
    manifestSha256: "hash",
    policyVersion: "policy-v1",
    dnsStateSha256: "state-v1",
    createdAt: now,
    expiresAt: 200,
  });
  const plan = {
    id: "plan-one",
    policyVersion: "policy-v1",
    dnsStateSha256: "state-v1",
  };
  await assert.rejects(
    reserve(repository, op("ffop_bad", 1, "altered"), "jti-bad", { plan }),
    {
      code: "PLAN_PRECONDITION_FAILED",
    },
  );
  assert.equal(await repository.getJti("jti-bad"), null);
  assert.equal((await repository.getPlan("plan-one")).consumed_at, null);
  const admitted = await reserve(repository, op("ffop_good"), "jti-good", {
    plan,
    locks: [lock],
    claims: [lock],
    zoneIds: [1],
  });
  assert.equal(admitted.reused, false);
  assert.equal((await repository.getPlan("plan-one")).consumed_at, now);
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM plan_admissions").get().n,
    1,
  );
  await assert.rejects(
    reserve(repository, op("ffop_second"), "jti-fresh", { plan }),
    {
      code: "PLAN_PRECONDITION_FAILED",
    },
  );
  assert.equal(await repository.getJti("jti-fresh"), null);
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM operations").get().n,
    1,
  );
});

test("SEC-PLAN-001 cross-repository, stale state and expired plan never reserve", async (t) => {
  const { sqlite, repository } = fixture(t);
  await repository.createPlan({
    id: "plan-two",
    repositoryId: 1,
    manifestSha256: "hash",
    policyVersion: "policy-v1",
    dnsStateSha256: "state-v1",
    createdAt: now,
    expiresAt: 200,
  });
  const cases = [
    [
      op("ffop_cross", 2),
      {
        id: "plan-two",
        policyVersion: "policy-v1",
        dnsStateSha256: "state-v1",
      },
      100,
    ],
    [
      op("ffop_state"),
      { id: "plan-two", policyVersion: "policy-v1", dnsStateSha256: "changed" },
      100,
    ],
    [
      op("ffop_policy"),
      { id: "plan-two", policyVersion: "changed", dnsStateSha256: "state-v1" },
      100,
    ],
    [
      op("ffop_expired"),
      {
        id: "plan-two",
        policyVersion: "policy-v1",
        dnsStateSha256: "state-v1",
      },
      200,
    ],
  ];
  for (const [operation, plan, nowEpoch] of cases)
    await assert.rejects(
      reserve(repository, operation, operation.id, { plan, nowEpoch }),
      {
        code: "PLAN_PRECONDITION_FAILED",
      },
    );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM operations").get().n,
    0,
  );
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM oidc_jti").get().n, 0);
});
