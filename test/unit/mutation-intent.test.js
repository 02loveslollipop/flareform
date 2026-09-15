import assert from "node:assert/strict";
import test from "node:test";
import { DnsRepository } from "../../src/db/repository.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";

const now = "2026-09-12T00:00:00Z";
function fixture(t) {
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
    .run(
      "100",
      "200",
      "repo",
      "owner/repo/.github/workflows/deploy.yml@refs/heads/main",
      now,
      now,
    );
  const repository = new DnsRepository(db);
  return { sqlite, repository };
}
const lock = { zoneId: 1, name: "verify.example-app.example.com", type: "TXT" };
const mutation = {
  operationId: "ffop_test",
  repositoryId: 1,
  zoneId: 1,
  zoneName: "example.com",
  clientKey: "verify",
  recordName: lock.name,
  recordType: "TXT",
  action: "create",
  oldRecord: null,
  newRecord: {
    type: "TXT",
    name: lock.name,
    content: "secret-canary",
    comment: "private-canary",
  },
  githubRunId: "500",
  githubActorId: "700",
  now,
};
async function reserve(repository) {
  await repository.reserveOperation({
    operation: {
      id: mutation.operationId,
      repositoryId: 1,
      githubRunId: "500",
      githubRunAttempt: "1",
      operationType: "keep",
      manifestSha256: "digest",
    },
    jti: "one",
    jtiExpiresAt: 2000000000,
    locks: [lock],
    claims: [lock],
    zoneIds: [1],
    now,
  });
}

test("AUD-001/FAULT-001 intent and redacted audit are atomic before provider send", async (t) => {
  const { sqlite, repository } = fixture(t);
  await reserve(repository);
  await repository.beginMutationIntent(mutation);
  assert.equal(
    (await repository.getMutationIntent("ffop_test", "verify")).status,
    "prepared",
  );
  const audit = sqlite.prepare("SELECT * FROM audit_log").get();
  assert.equal(audit.action, "intent:create");
  assert.match(audit.new_value, /REDACTED/);
  assert.doesNotMatch(JSON.stringify(audit), /secret-canary|private-canary/);
  assert.equal(
    (await repository.markMutationSent("ffop_test", "verify", now)).status,
    "sent",
  );
  await assert.rejects(
    repository.markMutationSent("ffop_test", "verify", now),
    {
      code: "STATE_INDETERMINATE",
    },
  );
});

test("FAULT-002 missing lock or failed audit cannot leave a sendable intent", async (t) => {
  const { sqlite, repository } = fixture(t);
  await reserve(repository);
  await assert.rejects(
    repository.beginMutationIntent({
      ...mutation,
      recordName: "wrong.example.com",
    }),
    {
      code: "DATABASE_ERROR",
    },
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM mutation_intents").get().n,
    0,
  );
  sqlite.exec(
    "CREATE TRIGGER fail_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;",
  );
  await assert.rejects(repository.beginMutationIntent(mutation), {
    code: "DATABASE_ERROR",
  });
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM mutation_intents").get().n,
    0,
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM audit_log").get().n,
    0,
  );
});

test("APPLY-001 confirmed create stores ownership and releases lock only after outcome audit", async (t) => {
  const { sqlite, repository } = fixture(t);
  await reserve(repository);
  await repository.beginMutationIntent(mutation);
  await repository.markMutationSent("ffop_test", "verify", now);
  const claim = await repository.getClaim(1, lock.name, lock.type);
  const id = "c".repeat(32);
  const result = await repository.confirmMutation({
    ...mutation,
    claimId: claim.id,
    cloudflareRecordId: id,
    content: "secret-canary",
  });
  assert.equal(result.status, "confirmed");
  assert.equal(
    (await repository.getManagedRecord(1, "verify")).cloudflare_record_id,
    id,
  );
  assert.equal(
    (await repository.getClaim(1, lock.name, lock.type)).state,
    "active",
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM audit_log").get().n,
    2,
  );
  await repository.finishZone({
    operationId: "ffop_test",
    repositoryId: 1,
    zoneId: 1,
    zoneName: "example.com",
    now,
  });
  assert.equal(
    (await repository.listOperationLocks("ffop_test")).results.length,
    0,
  );
  assert.equal(
    (await repository.getCheckpoint("ffop_test", 1)).status,
    "success",
  );
});

test("FAULT-003 Cloudflare success plus D1 confirmation failure leaves sent intent and locked set", async (t) => {
  const { sqlite, repository } = fixture(t);
  await reserve(repository);
  await repository.beginMutationIntent(mutation);
  await repository.markMutationSent("ffop_test", "verify", now);
  const claim = await repository.getClaim(1, lock.name, lock.type);
  sqlite.exec(
    "CREATE TRIGGER fail_outcome BEFORE INSERT ON audit_log WHEN NEW.action LIKE 'outcome:%' BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END;",
  );
  await assert.rejects(
    repository.confirmMutation({
      ...mutation,
      claimId: claim.id,
      cloudflareRecordId: "c".repeat(32),
      content: "secret-canary",
    }),
    { code: "STATE_INDETERMINATE" },
  );
  assert.equal(await repository.getManagedRecord(1, "verify"), null);
  assert.equal(
    (await repository.getMutationIntent("ffop_test", "verify")).status,
    "sent",
  );
  assert.equal(
    (await repository.listOperationLocks("ffop_test")).results.length,
    1,
  );
  await assert.rejects(
    repository.finishZone({
      operationId: "ffop_test",
      repositoryId: 1,
      zoneId: 1,
      zoneName: "example.com",
      now,
    }),
    {
      code: "STATE_INDETERMINATE",
    },
  );
  assert.equal(
    (await repository.getCheckpoint("ffop_test", 1)).status,
    "pending",
  );
  await assert.rejects(
    repository.markMutationIndeterminate({
      ...mutation,
      errorCode: "DATABASE_ERROR",
    }),
    { code: "STATE_INDETERMINATE" },
  );
  assert.equal(
    (await repository.getMutationIntent("ffop_test", "verify")).status,
    "sent",
  );
});

test("OWN-STALE-001 deletion cannot confirm when expected D1 record ID differs", async (t) => {
  const { sqlite, repository } = fixture(t);
  const id = "c".repeat(32);
  const claimId = sqlite
    .prepare(
      "INSERT INTO record_claims(repository_id,zone_id,name,type,state,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
    )
    .run(1, 1, lock.name, lock.type, "active", now, now).lastInsertRowid;
  sqlite
    .prepare(
      "INSERT INTO managed_records(repository_id,record_claim_id,zone_id,client_key,cloudflare_record_id,content,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
    )
    .run(1, claimId, 1, "verify", id, "secret-canary", now, now);
  await repository.reserveOperation({
    operation: {
      id: "ffop_delete",
      repositoryId: 1,
      githubRunId: "500",
      githubRunAttempt: "1",
      operationType: "prune",
      manifestSha256: "digest",
    },
    jti: "delete-jti",
    jtiExpiresAt: 2000000000,
    locks: [lock],
    zoneIds: [1],
    now,
  });
  const deletion = {
    ...mutation,
    operationId: "ffop_delete",
    action: "delete",
    cloudflareRecordId: id,
    oldRecord: mutation.newRecord,
    newRecord: null,
  };
  await repository.beginMutationIntent(deletion);
  await repository.markMutationSent("ffop_delete", "verify", now);
  await assert.rejects(
    repository.confirmMutation({
      ...deletion,
      claimId,
      cloudflareRecordId: "d".repeat(32),
      content: null,
    }),
    { code: "STATE_INDETERMINATE" },
  );
  assert.equal(
    (await repository.getMutationIntent("ffop_delete", "verify")).status,
    "sent",
  );
  assert.equal(
    (await repository.getManagedRecord(1, "verify")).cloudflare_record_id,
    id,
  );
});
