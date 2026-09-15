import assert from "node:assert/strict";
import test from "node:test";
import { DnsRepository } from "../../src/db/repository.js";
import { reserveApplyAdmission } from "../../src/dns/admission.js";
import { executeZone } from "../../src/dns/execute.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";
import { managedMetadata } from "../../src/dns/state.js";

const timestamp = Date.parse("2026-09-12T00:00:00Z");
const zone = {
  name: "example.com",
  cloudflare_zone_id: "a".repeat(32),
  enabled: true,
};
const record = {
  key: "main",
  zone: zone.name,
  name: "example-app.example.com",
  type: "A",
  content: "192.0.2.1",
  ttl: 60,
  proxied: false,
};
const claims = {
  repository_id: "100",
  run_id: "500",
  run_attempt: "1",
  actor_id: "700",
  jti: "fresh-jti",
  exp: Math.floor(timestamp / 1000) + 300,
};
function fixture(t, cloudflare) {
  const location = sqliteD1();
  t.after(location.close);
  const { sqlite, db } = location;
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
  const prepared = {
    manifest: { reconciliation: "keep", records: [record] },
    policy: { zones: [zone] },
    version: "v1",
    cloudflare,
    state: { desired: [{ record, claim: null, current: null }], prune: [] },
    planned: {
      manifestDigest: "digest",
      dnsStateDigest: "empty",
      deletionCount: 0,
      changes: {
        [zone.name]: [
          {
            action: "create",
            key: record.key,
            name: record.name,
            type: record.type,
          },
        ],
      },
    },
  };
  return { sqlite, db, repository, dnsRepository, prepared };
}
async function admit(location) {
  return reserveApplyAdmission({ ...location, claims, now: timestamp });
}

test("APPLY-001 single-zone create confirms D1 and audit after provider response", async (t) => {
  let creates = 0;
  const cloudflare = {
    listRecords: async () => [],
    create: async () => {
      creates++;
      return { id: "c".repeat(32) };
    },
  };
  const location = fixture(t, cloudflare);
  const admitted = await admit(location);
  const result = await executeZone({
    ...location,
    admitted,
    claims,
    zoneName: zone.name,
    now: () => timestamp,
  });
  assert.deepEqual(result, { zone: zone.name, status: "success" });
  assert.equal(creates, 1);
  assert.equal(
    (
      await location.dnsRepository.getManagedRecord(
        location.repository.id,
        "main",
      )
    ).content,
    record.content,
  );
  assert.equal(
    (await location.dnsRepository.getCheckpoint(admitted.operation.id, 1))
      .status,
    "success",
  );
  assert.equal(
    location.sqlite.prepare("SELECT count(*) AS n FROM operation_locks").get()
      .n,
    0,
  );
  assert.equal(
    location.sqlite.prepare("SELECT count(*) AS n FROM audit_log").get().n,
    3,
  );
  await executeZone({
    ...location,
    admitted,
    claims,
    zoneName: zone.name,
    now: () => timestamp,
  });
  assert.equal(creates, 1);
});

test("FAULT-004 uncertain provider response freezes set and cannot be retried", async (t) => {
  let creates = 0;
  const cloudflare = {
    listRecords: async () => [],
    create: async () => {
      creates++;
      throw Error("network timeout after possible create");
    },
  };
  const location = fixture(t, cloudflare);
  const admitted = await admit(location);
  await assert.rejects(
    executeZone({
      ...location,
      admitted,
      claims,
      zoneName: zone.name,
      now: () => timestamp,
    }),
    {
      code: "STATE_INDETERMINATE",
    },
  );
  assert.equal(
    (
      await location.dnsRepository.getMutationIntent(
        admitted.operation.id,
        "main",
      )
    ).status,
    "indeterminate",
  );
  assert.equal(
    (await location.dnsRepository.getCheckpoint(admitted.operation.id, 1))
      .status,
    "indeterminate",
  );
  assert.equal(
    location.sqlite.prepare("SELECT count(*) AS n FROM operation_locks").get()
      .n,
    1,
  );
  await assert.rejects(
    executeZone({
      ...location,
      admitted,
      claims,
      zoneName: zone.name,
      now: () => timestamp,
    }),
    {
      code: "STATE_INDETERMINATE",
    },
  );
  assert.equal(creates, 1);
});

test("APPLY-002 update rechecks old ID and metadata before patching", async (t) => {
  const id = "c".repeat(32);
  const old = {
    id,
    name: record.name,
    type: "A",
    content: "192.0.2.2",
    ttl: 60,
    proxied: false,
    ...managedMetadata("100", "main"),
  };
  let patches = 0;
  const cloudflare = {
    listRecords: async () => [old],
    patch: async (_zone, receivedId, payload) => {
      patches++;
      assert.equal(receivedId, id);
      assert.equal(payload.content, record.content);
      return { id };
    },
  };
  const location = fixture(t, cloudflare);
  const claimId = location.sqlite
    .prepare(
      "INSERT INTO record_claims(repository_id,zone_id,name,type,state,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
    )
    .run(
      location.repository.id,
      1,
      record.name,
      "A",
      "active",
      "now",
      "now",
    ).lastInsertRowid;
  location.sqlite
    .prepare(
      "INSERT INTO managed_records(repository_id,record_claim_id,zone_id,client_key,cloudflare_record_id,content,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
    )
    .run(
      location.repository.id,
      claimId,
      1,
      "main",
      id,
      old.content,
      "now",
      "now",
    );
  location.prepared.state.desired[0].claim =
    await location.dnsRepository.getClaim(1, record.name, "A");
  location.prepared.state.desired[0].current = old;
  location.prepared.planned.changes[zone.name][0].action = "update";
  const admitted = await admit(location);
  await executeZone({
    ...location,
    admitted,
    claims,
    zoneName: zone.name,
    now: () => timestamp,
  });
  assert.equal(patches, 1);
  assert.equal(
    (
      await location.dnsRepository.getManagedRecord(
        location.repository.id,
        "main",
      )
    ).content,
    record.content,
  );
});

test("APPLY-003 authorized prune deletes only the owned omitted record", async (t) => {
  const oldId = "c".repeat(32);
  const newId = "d".repeat(32);
  const old = {
    id: oldId,
    name: "old.example-app.example.com",
    type: "A",
    content: "192.0.2.2",
    ttl: 60,
    proxied: false,
    ...managedMetadata("100", "old"),
  };
  const providerRecords = [old];
  let deletes = 0;
  const cloudflare = {
    listRecords: async () => providerRecords,
    create: async (_zone, payload) => {
      providerRecords.push({ ...payload, id: newId });
      return { id: newId };
    },
    delete: async (_zone, receivedId) => {
      deletes++;
      assert.equal(receivedId, oldId);
      providerRecords.splice(
        providerRecords.findIndex((item) => item.id === oldId),
        1,
      );
      return { id: oldId };
    },
  };
  const location = fixture(t, cloudflare);
  const claimId = location.sqlite
    .prepare(
      "INSERT INTO record_claims(repository_id,zone_id,name,type,state,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
    )
    .run(
      location.repository.id,
      1,
      old.name,
      "A",
      "active",
      "now",
      "now",
    ).lastInsertRowid;
  location.sqlite
    .prepare(
      "INSERT INTO managed_records(repository_id,record_claim_id,zone_id,client_key,cloudflare_record_id,content,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
    )
    .run(
      location.repository.id,
      claimId,
      1,
      "old",
      oldId,
      old.content,
      "now",
      "now",
    );
  const row = (
    await location.dnsRepository.listOwnedRecords(location.repository.id)
  ).results[0];
  location.prepared.manifest.reconciliation = "prune";
  location.prepared.manifest.prune_zones = [zone.name];
  location.prepared.state.prune = [{ row, current: old, zone }];
  location.prepared.planned.deletionCount = 1;
  location.prepared.planned.changes[zone.name].push({
    action: "delete",
    key: "old",
    name: old.name,
    type: "A",
  });
  await location.dnsRepository.createPlan({
    id: "plan-id",
    repositoryId: location.repository.id,
    manifestSha256: "digest",
    policyVersion: "v1",
    dnsStateSha256: "empty",
    createdAt: new Date(timestamp).toISOString(),
    expiresAt: Math.floor(timestamp / 1000) + 300,
  });
  const admitted = await reserveApplyAdmission({
    ...location,
    claims,
    planId: "plan-id",
    now: timestamp,
  });
  await executeZone({
    ...location,
    admitted,
    claims,
    zoneName: zone.name,
    now: () => timestamp,
  });
  assert.equal(deletes, 1);
  assert.equal(
    await location.dnsRepository.getManagedRecord(
      location.repository.id,
      "old",
    ),
    null,
  );
  assert.equal(await location.dnsRepository.getClaim(1, old.name, "A"), null);
  assert.equal(
    (
      await location.dnsRepository.getManagedRecord(
        location.repository.id,
        "main",
      )
    ).cloudflare_record_id,
    newId,
  );
});

test("OWN-STALE-004 drift is denied before intent or provider mutation", async (t) => {
  let mutations = 0;
  const cloudflare = {
    listRecords: async () => [
      {
        id: "c".repeat(32),
        name: record.name,
        type: "A",
        content: "192.0.2.99",
        ttl: 60,
        proxied: false,
        tags: [],
      },
    ],
    create: async () => {
      mutations++;
      return { id: "d".repeat(32) };
    },
  };
  const location = fixture(t, cloudflare);
  const admitted = await admit(location);
  await assert.rejects(
    executeZone({
      ...location,
      admitted,
      claims,
      zoneName: zone.name,
      now: () => timestamp,
    }),
    {
      code: "STATE_INDETERMINATE",
    },
  );
  assert.equal(mutations, 0);
  assert.equal(
    location.sqlite.prepare("SELECT count(*) AS n FROM mutation_intents").get()
      .n,
    0,
  );
});

test("OWN-006 two desired A values confirm under one claim without a zone batch", async (t) => {
  const providerRecords = [];
  let creates = 0;
  const cloudflare = {
    listRecords: async () => providerRecords,
    create: async (_zone, payload) => {
      const entry = {
        ...payload,
        id: creates ? "d".repeat(32) : "c".repeat(32),
      };
      creates++;
      providerRecords.push(entry);
      return entry;
    },
  };
  const location = fixture(t, cloudflare);
  const second = { ...record, key: "second", content: "192.0.2.2" };
  location.prepared.manifest.records.push(second);
  location.prepared.state.desired.push({
    record: second,
    claim: null,
    current: null,
  });
  location.prepared.planned.changes[zone.name].push({
    action: "create",
    key: second.key,
    name: second.name,
    type: second.type,
  });
  const admitted = await admit(location);
  await executeZone({
    ...location,
    admitted,
    claims,
    zoneName: zone.name,
    now: () => timestamp,
  });
  assert.equal(creates, 2);
  assert.equal(
    location.sqlite.prepare("SELECT count(*) AS n FROM record_claims").get().n,
    1,
  );
  assert.equal(
    location.sqlite.prepare("SELECT count(*) AS n FROM managed_records").get()
      .n,
    2,
  );
});

test("APPLY-004 no-op writes no mutation intent and releases its operation lock", async (t) => {
  const external = {
    id: "c".repeat(32),
    name: record.name,
    type: "A",
    content: record.content,
    ttl: 60,
    proxied: false,
    ...managedMetadata("100", "main"),
  };
  const location = fixture(t, { listRecords: async () => [external] });
  const claimId = location.sqlite
    .prepare(
      "INSERT INTO record_claims(repository_id,zone_id,name,type,state,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
    )
    .run(1, 1, record.name, "A", "active", "now", "now").lastInsertRowid;
  location.sqlite
    .prepare(
      "INSERT INTO managed_records(repository_id,record_claim_id,zone_id,client_key,cloudflare_record_id,content,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
    )
    .run(1, claimId, 1, "main", external.id, record.content, "now", "now");
  location.prepared.state.desired[0] = {
    record,
    claim: await location.dnsRepository.getClaim(1, record.name, "A"),
    current: external,
  };
  location.prepared.planned.changes[zone.name][0].action = "noop";
  const admitted = await admit(location);
  await executeZone({ ...location, admitted, claims, zoneName: zone.name });
  assert.equal(
    location.sqlite.prepare("SELECT count(*) AS n FROM mutation_intents").get()
      .n,
    0,
  );
  assert.equal(
    (await location.dnsRepository.listOperationLocks(admitted.operation.id))
      .results.length,
    0,
  );
});
