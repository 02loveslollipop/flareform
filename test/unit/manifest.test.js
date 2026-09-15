import assert from "node:assert/strict";
import test from "node:test";
import { parseManifest, parseManifestObject } from "../../src/dns/manifest.js";

const zones = [
  { name: "example.com", enabled: true },
  { name: "example.net", enabled: true },
];
const cname = (zone = "example.com") => ({
  key: `main-${zone.replaceAll(".", "-")}`,
  zone,
  name: `example-app.${zone}`,
  type: "CNAME",
  content: "target.example.com.",
  proxied: true,
  ttl: 1,
});
const manifest = (records = [cname()]) => ({
  version: 1,
  reconciliation: "keep",
  records,
});
const fails = (value, options) =>
  assert.throws(() => parseManifestObject(value, zones, options), {
    code: "INVALID_RECORD",
  });

test("MAN-001 mirrored keep manifest canonicalizes only after parsing", () => {
  const parsed = parseManifestObject(
    manifest([cname(), cname("example.net")]),
    zones,
  );
  assert.equal(parsed.records.length, 2);
  assert.equal(parsed.records[0].content, "target.example.com");
});

test("MAN-002/003/004/005/006/007 closed fields, identities, zone and prune", () => {
  fails({ ...manifest(), version: 2 });
  fails({ ...manifest(), records: [] });
  fails({ ...manifest(), extra: true });
  fails(manifest([{ ...cname(), id: "cf-id" }]));
  fails(manifest([cname(), { ...cname(), key: "MAIN-EXAMPLE-COM" }]));
  fails(manifest([cname(), { ...cname(), key: "other" }]));
  fails(manifest([{ ...cname(), zone: "example.net" }]));
  fails({ ...manifest(), prune_zones: ["example.com"] });
  fails({ ...manifest(), reconciliation: "prune" });
  assert.deepEqual(
    parseManifestObject(
      { ...manifest(), reconciliation: "prune", prune_zones: ["example.com"] },
      zones,
    ).prune_zones,
    ["example.com"],
  );
});

test("MAN-A-001/AAAA-001 strict address forms", () => {
  for (const content of ["0.0.0.0", "255.255.255.255"])
    assert.equal(
      parseManifestObject(
        manifest([{ ...cname(), type: "A", content, proxied: false, ttl: 60 }]),
        zones,
      ).records[0].content,
      content,
    );
  for (const content of [
    "1.2.3",
    "01.2.3.4",
    "+1.2.3.4",
    "0x7f.0.0.1",
    "256.1.1.1",
    "1.2.3.4 ",
  ])
    fails(manifest([{ ...cname(), type: "A", content }]));
  assert.equal(
    parseManifestObject(
      manifest([{ ...cname(), type: "AAAA", content: "2001:db8::1" }]),
      zones,
    ).records[0].content,
    "2001:db8::1",
  );
  for (const content of ["2001:::1", "fe80::1%eth0", "::gg", "2001:db8::1junk"])
    fails(manifest([{ ...cname(), type: "AAAA", content }]));
});

test("OWN-006 multi-value A, AAAA, and SRV sets require distinct values and keys", () => {
  const a = {
    ...cname(),
    key: "a-one",
    type: "A",
    content: "192.0.2.1",
    proxied: false,
    ttl: 60,
  };
  const a2 = { ...a, key: "a-two", content: "192.0.2.2" };
  assert.equal(parseManifestObject(manifest([a, a2]), zones).records.length, 2);
  fails(manifest([a, { ...a2, content: a.content }]));
  fails(manifest([a, { ...a2, key: a.key }]));
  const aaaa = { ...a, type: "AAAA", content: "2001:db8::1" };
  assert.equal(
    parseManifestObject(manifest([a, { ...aaaa, key: "ip6-one" }, a2]), zones)
      .records.length,
    3,
  );
  const srv = {
    key: "srv-one",
    zone: "example.com",
    name: "_grpc._tcp.example-app.example.com",
    type: "SRV",
    priority: 10,
    weight: 0,
    port: 443,
    target: "api.example-app.example.com",
    ttl: 60,
  };
  assert.equal(
    parseManifestObject(
      manifest([srv, { ...srv, key: "srv-two", port: 8443 }]),
      zones,
    ).records.length,
    2,
  );
  fails(manifest([srv, { ...srv, key: "srv-two" }]));
  fails(manifest([a, { ...cname(), key: "alias" }]));
});

test("MAN-CNAME-001/002/003 canonical target and self-reference", () => {
  fails(manifest([{ ...cname(), content: "EXAMPLE-APP.EXAMPLE.COM." }]));
  fails(manifest([{ ...cname(), content: "192.0.2.1" }]));
  fails(manifest([{ ...cname(), content: "bad_target.example.com" }]));
});

test("MAN-SRV-001/002/003 structural SRV only", () => {
  const srv = {
    key: "grpc",
    zone: "example.com",
    name: "_grpc._tcp.example-app.example.com",
    type: "SRV",
    priority: 10,
    weight: 100,
    port: 443,
    target: "api.example-app.example.com",
    ttl: 60,
  };
  assert.equal(
    parseManifestObject(manifest([srv]), zones).records[0].target,
    srv.target,
  );
  fails(manifest([{ ...srv, port: 65536 }]));
  fails(manifest([{ ...srv, content: "10 100 443 target" }]));
  fails(manifest([{ ...srv, name: "grpc.example-app.example.com" }]));
});

test("MAN-TXT-001/002, MAN-TYPE-001, MAN-PROXY-001 gated TXT and type/proxy combinations", () => {
  const txt = {
    ...cname(),
    type: "TXT",
    content: "verification=secret",
    proxied: false,
    ttl: 60,
  };
  fails(manifest([txt]));
  assert.equal(
    parseManifestObject(manifest([txt]), zones, { allowTxt: true }).records[0]
      .content,
    txt.content,
  );
  fails(manifest([{ ...txt, proxied: true }]), { allowTxt: true });
  for (const type of ["NS", "MX", "CAA", "DS", "PTR"])
    fails(manifest([{ ...cname(), type }]));
  fails(manifest([{ ...cname(), ttl: 60 }]));
  fails(manifest([{ ...cname(), proxied: false, ttl: 30 }]));
});

test("MAN-008/FUZZ-MAN-001 YAML extensions, duplicate keys, oversized data and prototype names reject", () => {
  const valid =
    "version: 1\nreconciliation: keep\nrecords:\n  - key: main\n    zone: example.com\n    name: example-app.example.com\n    type: CNAME\n    content: target.example.com\n    proxied: true\n    ttl: 1\n";
  assert.equal(parseManifest(valid, zones).records.length, 1);
  for (const source of [
    valid + "version: 1\n",
    valid.replace("key: main", "key: &id main"),
    valid.replace("key: main", "key: !custom main"),
    "x".repeat(65537),
    '{"version":1,"version":2}',
  ])
    assert.throws(() => parseManifest(source, zones));
  fails(manifest([{ ...cname(), __proto__: null, key: "__proto__" }]));
});
