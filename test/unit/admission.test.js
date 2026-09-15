import assert from "node:assert/strict";
import test from "node:test";
import { reserveApplyAdmission } from "../../src/dns/admission.js";
import { DnsRepository } from "../../src/db/repository.js";
import { collectDnsState } from "../../src/dns/state.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";

const now = Date.parse("2026-09-12T00:00:00Z");
const zones = [
  { name: "example.com", enabled: true, cloudflare_zone_id: "a".repeat(32) },
  {
    name: "example.net",
    enabled: true,
    cloudflare_zone_id: "b".repeat(32),
  },
];
function fixture(t) {
  const location = sqliteD1();
  t.after(location.close);
  const { sqlite, db } = location;
  for (const zone of zones)
    sqlite
      .prepare(
        "INSERT INTO zones(name,cloudflare_zone_id,created_at) VALUES (?,?,?)",
      )
      .run(zone.name, zone.cloudflare_zone_id, "now");
  sqlite
    .prepare(
      "INSERT INTO repositories(github_repository_id,github_owner_id,display_name,expected_workflow_ref,created_at,updated_at) VALUES (?,?,?,?,?,?)",
    )
    .run(
      "100",
      "200",
      "repo",
      "owner/repo/.github/workflows/deploy.yml@refs/heads/main",
      "now",
      "now",
    );
  const repository = sqlite.prepare("SELECT * FROM repositories").get();
  const dnsRepository = new DnsRepository(db);
  return { sqlite, db, repository, dnsRepository };
}
const claims = {
  repository_id: "100",
  run_id: "500",
  run_attempt: "1",
  actor_id: "700",
  jti: "first-jti",
  exp: Math.floor(now / 1000) + 300,
};
const record = (key, zone = "example.com", content = "192.0.2.1") => ({
  key,
  zone,
  name: `example-app.${zone}`,
  type: "A",
  content,
  ttl: 60,
  proxied: false,
});
function prepared(records, deletionCount = 0) {
  return {
    manifest: {
      reconciliation: deletionCount ? "prune" : "keep",
      records,
      ...(deletionCount ? { prune_zones: ["example.com"] } : {}),
    },
    policy: { zones },
    version: "policy-v1",
    state: {
      desired: records.map((item) => ({ record: item, claim: null })),
      prune: [],
    },
    planned: {
      manifestDigest: "digest",
      dnsStateDigest: "state-v1",
      deletionCount,
    },
  };
}

test("OP-IDEM-001/002 derive immutable run identity and reserve multi-value sets once", async (t) => {
  const { sqlite, db, repository } = fixture(t);
  const input = prepared([
    record("a-one"),
    record("a-two", "example.com", "192.0.2.2"),
    record("uk", "example.net"),
  ]);
  const first = await reserveApplyAdmission({
    db,
    repository,
    claims,
    prepared: input,
    now,
  });
  assert.match(first.operation.id, /^ffop_[0-9a-f]{32}$/);
  assert.equal(first.reused, false);
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM record_claims").get().n,
    2,
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM operation_locks").get().n,
    2,
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM operation_zones").get().n,
    2,
  );
  await assert.rejects(
    collectDnsState({
      manifest: input.manifest,
      policy: input.policy,
      repository,
      db,
      cloudflare: { listRecords: async () => [] },
    }),
    { code: "OPERATION_IN_PROGRESS" },
  );
  const resumable = await collectDnsState({
    manifest: input.manifest,
    policy: input.policy,
    repository,
    db,
    cloudflare: { listRecords: async () => [] },
    allowedOperationId: first.operation.id,
  });
  assert.equal(resumable.desired.length, 3);
  const retry = await reserveApplyAdmission({
    db,
    repository,
    claims: { ...claims, jti: "fresh-jti" },
    prepared: input,
    now,
  });
  assert.equal(retry.reused, true);
  assert.equal(retry.operation.id, first.operation.id);
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM oidc_jti").get().n, 2);
});

test("PRUNE-PRE-001/SEC-PLAN-001 deletion requires matching short-lived plan before any reservation", async (t) => {
  const { sqlite, db, repository, dnsRepository } = fixture(t);
  const input = prepared([record("a-one")], 1);
  await assert.rejects(
    reserveApplyAdmission({ db, repository, claims, prepared: input, now }),
    { code: "PLAN_PRECONDITION_FAILED" },
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM operations").get().n,
    0,
  );
  await dnsRepository.createPlan({
    id: "plan-id",
    repositoryId: repository.id,
    manifestSha256: "digest",
    policyVersion: "policy-v1",
    dnsStateSha256: "state-v1",
    createdAt: new Date(now).toISOString(),
    expiresAt: Math.floor(now / 1000) + 300,
  });
  await assert.rejects(
    reserveApplyAdmission({
      db,
      repository,
      claims,
      prepared: { ...input, version: "changed" },
      planId: "plan-id",
      now,
    }),
    { code: "PLAN_PRECONDITION_FAILED" },
  );
  assert.equal((await dnsRepository.getPlan("plan-id")).consumed_at, null);
  const applied = await reserveApplyAdmission({
    db,
    repository,
    claims,
    prepared: input,
    planId: "plan-id",
    now,
  });
  assert.equal(applied.reused, false);
  assert.notEqual((await dnsRepository.getPlan("plan-id")).consumed_at, null);
});

test("OP-IDEM-003 malformed run identity and expired token cannot reach operation storage", async (t) => {
  const { sqlite, db, repository } = fixture(t);
  const input = prepared([record("a-one")]);
  for (const bad of [
    { run_id: undefined },
    { run_id: "0" },
    { run_id: 500 },
    { run_attempt: "1 OR 1=1" },
    { actor_id: "-1" },
    { repository_id: "200" },
    { exp: Math.floor(now / 1000) },
  ])
    await assert.rejects(
      reserveApplyAdmission({
        db,
        repository,
        claims: { ...claims, ...bad },
        prepared: input,
        now,
      }),
    );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM operations").get().n,
    0,
  );
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM oidc_jti").get().n, 0);
});
