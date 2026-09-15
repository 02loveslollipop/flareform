import assert from "node:assert/strict";
import test from "node:test";
import {
  buildPlan,
  digestManifest,
  MAX_PRUNE_DELETIONS,
} from "../../src/dns/plan.js";

const digestKey = "local-test-hmac-key-never-production-123456789";
const record = (key = "main", zone = "example.com") => ({
  key,
  zone,
  name: `example-app.${zone}`,
  type: "A",
  content: "192.0.2.1",
  ttl: 60,
  proxied: false,
});
const manifest = (records = [record()], reconciliation = "keep") => ({
  version: 1,
  reconciliation,
  records,
  ...(reconciliation === "prune" ? { prune_zones: ["example.com"] } : {}),
});
const policyRepository = { operations: { allow_prune: false } };
const input = (m, state, policy = policyRepository) => ({
  manifest: m,
  state,
  policyRepository: policy,
  repositoryId: "123",
  digestKey,
});
const state = (entries) => ({ desired: entries, prune: [], relevant: [] });

test("PLAN-UNIT-001/002/003 create, update and no-op are deterministic", async () => {
  const desired = record();
  const created = await buildPlan(
    input(manifest(), state([{ record: desired, current: null }])),
  );
  assert.equal(created.changes["example.com"][0].action, "create");
  const current = { type: "A", content: "192.0.2.2", ttl: 60, proxied: false };
  const updated = await buildPlan(
    input(manifest(), state([{ record: desired, current }])),
  );
  assert.equal(updated.changes["example.com"][0].action, "update");
  const noOp = await buildPlan(
    input(
      manifest(),
      state([
        { record: desired, current: { ...current, content: desired.content } },
      ]),
    ),
  );
  assert.equal(noOp.changes["example.com"][0].action, "noop");
});

test("MZ-001 manifest identity is independent of zone state; zone fingerprints are isolated", async () => {
  const a = record("a", "example.com");
  const b = record("b", "example.net");
  const m = manifest([a, b]);
  const base = await buildPlan(
    input(m, {
      desired: [
        { record: a, current: null },
        { record: b, current: null },
      ],
      prune: [],
      relevant: [],
    }),
  );
  assert.equal(base.manifestDigest, await digestManifest(m, "123", digestKey));
  const changed = await buildPlan(
    input(m, {
      desired: [
        { record: a, current: null },
        { record: b, current: null },
      ],
      prune: [],
      relevant: [
        {
          zone: "example.com",
          id: "a".repeat(32),
          name: a.name,
          type: "A",
          content: "192.0.2.1",
          ttl: 60,
          proxied: false,
          tags: [],
          comment: "",
        },
      ],
    }),
  );
  assert.equal(changed.manifestDigest, base.manifestDigest);
  assert.notEqual(
    changed.zoneDigests["example.com"],
    base.zoneDigests["example.com"],
  );
  assert.equal(
    changed.zoneDigests["example.net"],
    base.zoneDigests["example.net"],
  );
});

test("PLAN-UNIT-004/005/006 and PROP-PLAN-002 keep never deletes; order does not change digests", async () => {
  const a = record("a", "example.com");
  const b = record("b", "example.net");
  const first = await buildPlan(
    input(
      manifest([a, b]),
      state([
        { record: a, current: null },
        { record: b, current: null },
      ]),
    ),
  );
  const second = await buildPlan(
    input(
      manifest([b, a]),
      state([
        { record: b, current: null },
        { record: a, current: null },
      ]),
    ),
  );
  assert.deepEqual(first, second);
  const hiddenPrune = await buildPlan(
    input(manifest([a]), {
      desired: [{ record: a, current: null }],
      prune: [
        {
          row: {
            client_key: "old",
            zone_name: "example.com",
            name: "old.example.com",
            type: "A",
          },
          current: { content: "192.0.2.2" },
        },
      ],
      relevant: [],
    }),
  );
  assert.equal(hiddenPrune.deletionCount, 0);
  assert.ok(
    Object.values(hiddenPrune.changes)
      .flat()
      .every((change) => change.action !== "delete"),
  );
});

test("PRUNE-001/002/004/005 server-side opt-in and deletion limit", async () => {
  const candidate = {
    row: {
      client_key: "old",
      zone_name: "example.com",
      name: "old.example.com",
      type: "A",
    },
    current: { content: "192.0.2.2" },
  };
  const pruneState = {
    desired: [{ record: record(), current: null }],
    prune: [candidate],
    relevant: [],
  };
  await assert.rejects(
    buildPlan(input(manifest([record()], "prune"), pruneState)),
    { code: "PRUNE_NOT_AUTHORIZED" },
  );
  const enabled = { operations: { allow_prune: true } };
  const plan = await buildPlan(
    input(manifest([record()], "prune"), pruneState, enabled),
  );
  assert.equal(plan.deletionCount, 1);
  assert.equal(
    plan.changes["example.com"].find((change) => change.action === "delete")
      .key,
    "old",
  );
  await assert.rejects(
    buildPlan(
      input(
        manifest([record()], "prune"),
        {
          ...pruneState,
          prune: Array.from(
            { length: MAX_PRUNE_DELETIONS + 1 },
            () => candidate,
          ),
        },
        enabled,
      ),
    ),
    { code: "PRUNE_LIMIT_EXCEEDED" },
  );
});

test("MAN-TXT-002 and SEC-PLAN-002 TXT is redacted and digest is keyed", async () => {
  const txt = {
    ...record(),
    type: "TXT",
    content: "low-entropy-secret",
    proxied: false,
  };
  const p = await buildPlan(
    input(manifest([txt]), state([{ record: txt, current: null }])),
  );
  assert.equal(p.changes["example.com"][0].to, "[REDACTED]");
  assert.doesNotMatch(JSON.stringify(p), /low-entropy-secret/);
  assert.match(p.manifestDigest, /^[0-9a-f]{64}$/);
  assert.notEqual(
    p.manifestDigest,
    (
      await buildPlan({
        ...input(manifest([txt]), state([{ record: txt, current: null }])),
        digestKey: "another-local-test-key-1234567890123456789",
      })
    ).manifestDigest,
  );
});

test("DNS-STATE-004 fingerprint ignores API ordering but binds relevant record changes", async () => {
  const relevant = [
    {
      zone: "example.com",
      id: "a".repeat(32),
      name: "example-app.example.com",
      type: "A",
      content: "192.0.2.1",
      ttl: 60,
      proxied: false,
      tags: ["x:1"],
      comment: "one",
    },
    {
      zone: "example.com",
      id: "b".repeat(32),
      name: "example-app.example.com",
      type: "A",
      content: "192.0.2.2",
      ttl: 60,
      proxied: false,
      tags: ["x:2"],
      comment: "two",
    },
  ];
  const desired = [{ record: record(), current: null }];
  const first = await buildPlan(
    input(manifest(), { desired, prune: [], relevant }),
  );
  const second = await buildPlan(
    input(manifest(), {
      desired,
      prune: [],
      relevant: [...relevant].reverse(),
    }),
  );
  assert.equal(first.dnsStateDigest, second.dnsStateDigest);
  const changed = await buildPlan(
    input(manifest(), {
      desired,
      prune: [],
      relevant: [{ ...relevant[0], content: "192.0.2.3" }, relevant[1]],
    }),
  );
  assert.notEqual(first.dnsStateDigest, changed.dnsStateDigest);
});
