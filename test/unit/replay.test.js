import assert from "node:assert/strict";
import test from "node:test";
import { DnsRepository } from "../../src/db/repository.js";
import { cleanupExpiredJtis } from "../../scripts/cleanup-jti.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";

function fixture(t) {
  const location = sqliteD1();
  t.after(location.close);
  const { sqlite, db } = location;
  sqlite
    .prepare(
      "INSERT INTO repositories(github_repository_id, github_owner_id, display_name, expected_workflow_ref, created_at, updated_at) VALUES (?,?,?,?,?,?)",
    )
    .run(
      "100",
      "200",
      "repo",
      "owner/repo/.github/workflows/deploy.yml@refs/heads/main",
      "now",
      "now",
    );
  return { sqlite, db, repository: new DnsRepository(db) };
}
const op = (id, hash = "hash") => ({
  id,
  repositoryId: 1,
  githubRunId: "run",
  githubRunAttempt: "1",
  operationType: "apply",
  manifestSha256: hash,
});
const reserve = (repository, id, jti, hash = "hash", claims = []) =>
  repository.reserveOperation({
    operation: op(id, hash),
    jti,
    jtiExpiresAt: 200,
    claims,
    now: "2026-09-11T00:00:00Z",
  });

test("OIDC-REPLAY-001/004 same JTI rejected and raw JWT never stored", async (t) => {
  const { sqlite, repository } = fixture(t);
  await reserve(repository, "first", "jti-1");
  await assert.rejects(reserve(repository, "second", "jti-1"), {
    code: "OIDC_TOKEN_REPLAYED",
  });
  const row = sqlite.prepare("SELECT * FROM oidc_jti").get();
  assert.deepEqual(Object.keys(row).sort(), [
    "expires_at",
    "jti",
    "repository_id",
    "used_at",
  ]);
  assert.equal(row.jti, "jti-1");
});

test("CONC-JTI-001/002 simultaneous reuse and failed claim reservation are atomic", async (t) => {
  const { sqlite, repository } = fixture(t);
  const settled = await Promise.allSettled([
    reserve(repository, "first", "one", "a"),
    reserve(repository, "second", "one", "b"),
  ]);
  assert.equal(
    settled.filter((entry) => entry.status === "fulfilled").length,
    1,
  );
  assert.equal(
    settled.filter(
      (entry) =>
        entry.status === "rejected" &&
        entry.reason.code === "OIDC_TOKEN_REPLAYED",
    ).length,
    1,
  );
  await assert.rejects(
    reserve(repository, "third", "fresh", "c", [
      { zoneId: 999, name: "bad.example.com", type: "A" },
    ]),
  );
  assert.equal(repository.getJti("fresh") instanceof Promise, true);
  assert.equal(await repository.getJti("fresh"), null);
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM operations").get().n,
    1,
  );
});

test("CONC-JTI-003 fresh JWT resumes operation and consumes the new JTI once", async (t) => {
  const { sqlite, repository } = fixture(t);
  await reserve(repository, "first", "jti-1");
  const resumed = await reserve(repository, "second", "jti-2");
  assert.equal(resumed.reused, true);
  assert.equal(resumed.operation.id, "first");
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM oidc_jti").get().n, 2);
  await assert.rejects(reserve(repository, "third", "jti-2"), {
    code: "OIDC_TOKEN_REPLAYED",
  });
});

test("OIDC-REPLAY-003 cleanup removes expired only, never boundary or unexpired", async (t) => {
  const { sqlite, db } = fixture(t);
  for (const [jti, expires] of [
    ["old", 99],
    ["boundary", 100],
    ["future", 101],
  ])
    sqlite
      .prepare(
        "INSERT INTO oidc_jti(jti, repository_id, expires_at, used_at) VALUES (?,?,?,?)",
      )
      .run(jti, 1, expires, "now");
  await cleanupExpiredJtis(db, 100);
  assert.deepEqual(
    sqlite
      .prepare("SELECT jti FROM oidc_jti ORDER BY jti")
      .all()
      .map((row) => row.jti),
    ["boundary", "future"],
  );
});
