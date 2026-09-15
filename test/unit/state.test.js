import assert from "node:assert/strict";
import test from "node:test";
import { collectDnsState, managedMetadata } from "../../src/dns/state.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";
import { DnsRepository } from "../../src/db/repository.js";

const zoneName = "example.com";
const zone = {
  name: zoneName,
  cloudflare_zone_id: "a".repeat(32),
  enabled: true,
};
const otherZone = {
  name: "example.net",
  cloudflare_zone_id: "b".repeat(32),
  enabled: true,
};
const record = {
  key: "main",
  zone: zoneName,
  name: `example-app.${zoneName}`,
  type: "A",
  content: "192.0.2.1",
  proxied: false,
  ttl: 60,
};
const manifest = (records = [record], reconciliation = "keep") => ({
  version: 1,
  reconciliation,
  records,
  ...(reconciliation === "prune" ? { prune_zones: [zoneName] } : {}),
});
const cfRecord = (id = "c".repeat(32), overrides = {}) => ({
  id,
  name: record.name,
  type: "A",
  content: record.content,
  proxied: false,
  ttl: 60,
  ...managedMetadata("123", "main"),
  ...overrides,
});

function fixture(t) {
  const location = sqliteD1();
  t.after(location.close);
  const { sqlite, db } = location;
  for (const entry of [zone, otherZone])
    sqlite
      .prepare(
        "INSERT INTO zones(name,cloudflare_zone_id,created_at) VALUES (?,?,?)",
      )
      .run(entry.name, entry.cloudflare_zone_id, "now");
  for (const [id, owner] of [
    ["123", "456"],
    ["999", "888"],
  ])
    sqlite
      .prepare(
        "INSERT INTO repositories(github_repository_id,github_owner_id,display_name,expected_workflow_ref,created_at,updated_at) VALUES (?,?,?,?,?,?)",
      )
      .run(
        id,
        owner,
        "repo",
        "owner/repo/.github/workflows/deploy.yml@refs/heads/main",
        "now",
        "now",
      );
  const repository = { id: 1, github_repository_id: "123" };
  const policy = { zones: [zone, otherZone] };
  const cloudflare = { listRecords: async () => [] };
  const collect = (input = manifest()) =>
    collectDnsState({ manifest: input, policy, repository, db, cloudflare });
  const claim = (repositoryId = 1, name = record.name, type = "A") =>
    sqlite
      .prepare(
        "INSERT INTO record_claims(repository_id,zone_id,name,type,state,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
      )
      .run(repositoryId, 1, name, type, "active", "now", "now").lastInsertRowid;
  const managed = (
    claimId,
    clientKey = "main",
    id = "c".repeat(32),
    content = record.content,
  ) =>
    sqlite
      .prepare(
        "INSERT INTO managed_records(repository_id,record_claim_id,zone_id,client_key,cloudflare_record_id,content,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
      )
      .run(1, claimId, 1, clientKey, id, content, "now", "now");
  return {
    sqlite,
    db,
    repository,
    policy,
    cloudflare,
    collect,
    claim,
    managed,
  };
}

test("DNS-STATE-001/OWN-001 absent authorized name has no implicit owner", async (t) => {
  const f = fixture(t);
  const state = await f.collect();
  assert.equal(state.desired[0].claim, null);
  assert.equal(state.desired[0].current, null);
});

test("OWN-003/004/005 and SEC-TAKEOVER-002 no D1 claim means no adoption", async (t) => {
  const f = fixture(t);
  f.cloudflare.listRecords = async () => [cfRecord()];
  await assert.rejects(f.collect(), { code: "RECORD_NOT_OWNED" });
  f.claim(2);
  await assert.rejects(f.collect(), {
    code: "RECORD_OWNED_BY_OTHER_REPOSITORY",
  });
});

test("DNS-STATE-002 incompatible CNAME/NS coexistence fails", async (t) => {
  const f = fixture(t);
  for (const type of ["CNAME", "NS"]) {
    f.cloudflare.listRecords = async () => [cfRecord("c".repeat(32), { type })];
    await assert.rejects(f.collect(), { code: "DNS_CONFLICT" });
  }
});

test("OWN-002/006/007/008/009 and SEC-TAKEOVER-003 D1 and Cloudflare metadata must agree", async (t) => {
  const f = fixture(t);
  f.managed(f.claim());
  f.cloudflare.listRecords = async () => [cfRecord()];
  assert.equal((await f.collect()).desired[0].current.id, "c".repeat(32));
  for (const mutation of [
    { tags: ["managed-by:flareform"] },
    { comment: "forged" },
    { content: "192.0.2.2" },
    { id: "d".repeat(32) },
  ]) {
    f.cloudflare.listRecords = async () => [cfRecord("c".repeat(32), mutation)];
    await assert.rejects(f.collect(), { code: "STATE_INDETERMINATE" });
  }
});

test("DNS-STATE-003 extra owned A value shares claim; untracked value freezes", async (t) => {
  const f = fixture(t);
  const claimId = f.claim();
  f.managed(claimId);
  f.managed(claimId, "secondary", "d".repeat(32), "192.0.2.2");
  f.cloudflare.listRecords = async () => [
    cfRecord(),
    cfRecord("d".repeat(32), {
      content: "192.0.2.2",
      ...managedMetadata("123", "secondary"),
    }),
  ];
  assert.equal((await f.collect()).desired[0].current.id, "c".repeat(32));
  f.cloudflare.listRecords = async () => [
    cfRecord(),
    cfRecord("d".repeat(32), {
      content: "192.0.2.2",
      ...managedMetadata("123", "secondary"),
    }),
    cfRecord("e".repeat(32)),
  ];
  await assert.rejects(f.collect(), { code: "STATE_INDETERMINATE" });
});

test("OWN-006 multiple AAAA and SRV values share one owned claim", async (t) => {
  for (const [type, name, values] of [
    ["AAAA", record.name, ["2001:db8::1", "2001:db8::2"]],
    [
      "SRV",
      `_grpc._tcp.${record.name}`,
      [
        {
          priority: 10,
          weight: 1,
          port: 443,
          target: "api.example-app.example.com",
        },
        {
          priority: 20,
          weight: 2,
          port: 8443,
          target: "api.example-app.example.com",
        },
      ],
    ],
  ]) {
    const f = fixture(t);
    const claimId = f.claim(1, name, type);
    f.managed(
      claimId,
      "main",
      "c".repeat(32),
      typeof values[0] === "string" ? values[0] : JSON.stringify(values[0]),
    );
    f.managed(
      claimId,
      "secondary",
      "d".repeat(32),
      typeof values[1] === "string" ? values[1] : JSON.stringify(values[1]),
    );
    f.cloudflare.listRecords = async () =>
      values.map((value, index) => ({
        ...cfRecord(index ? "d".repeat(32) : "c".repeat(32), {
          name,
          type,
          ...(typeof value === "string"
            ? { content: value }
            : { data: Object.fromEntries(Object.entries(value).reverse()) }),
        }),
        ...managedMetadata("123", index ? "secondary" : "main"),
      }));
    const desired = {
      ...record,
      name,
      type,
      ...(type === "AAAA"
        ? { content: values[0] }
        : {
            priority: 10,
            weight: 1,
            port: 443,
            target: "api.example-app.example.com",
          }),
    };
    assert.equal(
      (await f.collect(manifest([desired]))).desired[0].current.id,
      "c".repeat(32),
    );
  }
});

test("CONC-CLAIM-001 two repositories racing for one canonical set reserve at most one claim", async (t) => {
  const f = fixture(t);
  const repo = new DnsRepository(f.db);
  const operation = (id, repositoryId) => ({
    id,
    repositoryId,
    githubRunId: `run-${id}`,
    githubRunAttempt: "1",
    operationType: "apply",
    manifestSha256: `digest-${id}`,
  });
  const attempts = await Promise.allSettled(
    [1, 2].map((repositoryId) =>
      repo.reserveOperation({
        operation: operation(`op-${repositoryId}`, repositoryId),
        jti: `jti-${repositoryId}`,
        jtiExpiresAt: 100,
        claims: [{ zoneId: 1, name: record.name, type: "A" }],
        now: "now",
      }),
    ),
  );
  assert.equal(
    attempts.filter((entry) => entry.status === "fulfilled").length,
    1,
  );
  assert.equal(
    f.sqlite.prepare("SELECT count(*) AS n FROM record_claims").get().n,
    1,
  );
  assert.equal(
    f.sqlite.prepare("SELECT count(*) AS n FROM operations").get().n,
    1,
  );
});

test("PRUNE-002/003 owned omitted key is a candidate only in explicit scope", async (t) => {
  const f = fixture(t);
  const oldName = `old.${zoneName}`;
  const claimId = f.claim(1, oldName);
  f.managed(claimId, "old", "d".repeat(32), "192.0.2.2");
  f.cloudflare.listRecords = async () => [
    {
      ...cfRecord("d".repeat(32), { name: oldName, content: "192.0.2.2" }),
      ...managedMetadata("123", "old"),
    },
  ];
  assert.equal((await f.collect(manifest())).prune.length, 0);
  assert.equal((await f.collect(manifest([record], "prune"))).prune.length, 1);
});

test("DNS-STATE-002 CNAME claim cannot acquire a second logical key", async (t) => {
  const f = fixture(t);
  const claimId = f.claim(1, record.name, "CNAME");
  f.managed(claimId, "old", "c".repeat(32), "target.example.net");
  f.cloudflare.listRecords = async () => [
    {
      ...cfRecord("c".repeat(32), {
        type: "CNAME",
        content: "target.example.net",
      }),
      ...managedMetadata("123", "old"),
    },
  ];
  await assert.rejects(
    f.collect(
      manifest([
        { ...record, key: "new", type: "CNAME", content: "target.example.net" },
      ]),
    ),
    { code: "DNS_CONFLICT" },
  );
});
