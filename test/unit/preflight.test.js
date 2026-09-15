import assert from "node:assert/strict";
import test from "node:test";
import { assertCurrentRecordSet } from "../../src/dns/preflight.js";
import { managedMetadata } from "../../src/dns/state.js";

const id = "a".repeat(32);
const zone = {
  name: "example.com",
  cloudflare_zone_id: "b".repeat(32),
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
const external = {
  id,
  name: record.name,
  type: "A",
  content: record.content,
  ttl: 60,
  proxied: false,
  ...managedMetadata("100", "main"),
};
const row = {
  repository_id: 1,
  claim_repository_id: 1,
  claim_state: "active",
  client_key: "main",
  zone_name: zone.name,
  name: record.name,
  type: "A",
  content: record.content,
  cloudflare_record_id: id,
};
const check = (items, options = {}) =>
  assertCurrentRecordSet({
    cloudflare: { listRecords: async () => items },
    zone,
    record,
    ownedRows: options.ownedRows ?? [row],
    repositoryId: "100",
    expectedCurrent: Object.hasOwn(options, "expectedCurrent")
      ? options.expectedCurrent
      : external,
  });

test("OWN-STALE-001/002 exact tracked set and snapshot pass just before update", async () => {
  assert.equal((await check([external])).id, id);
  assert.equal(await check([], { ownedRows: [], expectedCurrent: null }), null);
});

test("OWN-STALE-003 provider drift, unmanaged extra value and conflicts deny", async () => {
  for (const items of [
    [{ ...external, content: "192.0.2.2" }],
    [{ ...external, ttl: 120 }],
    [{ ...external, comment: "altered" }],
    [external, { ...external, id: "c".repeat(32), content: "192.0.2.2" }],
    [external, { ...external, id: "d".repeat(32), type: "CNAME" }],
    [external, { ...external, id: "e".repeat(32), type: "NS" }],
  ])
    await assert.rejects(check(items));
  await assert.rejects(check([], { ownedRows: [], expectedCurrent: external }));
});
