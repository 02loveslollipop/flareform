import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  auditOwnership,
  generateInventory,
} from "../../src/admin/inventory.js";
import { managedMetadata } from "../../src/dns/state.js";
import { parsePolicyYaml, validatePolicy } from "../../src/policy/config.js";
import { syncPolicy } from "../../src/policy/sync.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";

const zones = parsePolicyYaml(
  await readFile(
    new URL("../../config/examples/zones.yaml", import.meta.url),
    "utf8",
  ),
);
const repositoryPolicy = parsePolicyYaml(
  await readFile(
    new URL(
      "../../config/examples/repositories/example-app.yaml",
      import.meta.url,
    ),
    "utf8",
  ),
);
const policy = validatePolicy(zones, [repositoryPolicy]);

test("ADM-INV-001/002 inventory reads every zone, captures classification, and redacts credential-shaped data", async (t) => {
  const { db, close } = sqliteD1();
  t.after(close);
  await syncPolicy(db, policy);
  const reads = [];
  const inventory = await generateInventory({
    db,
    token: "dns-admin-token-canary",
    now: Date.parse("2026-09-14T00:00:00Z"),
    cloudflareFactory: ({ token }) => {
      assert.equal(token, "dns-admin-token-canary");
      return {
        listRecords: async (zone) => {
          reads.push(zone.name);
          return zone.name === "example.com"
            ? [
                {
                  id: "a".repeat(32),
                  name: "example-app.example.com",
                  type: "A",
                  content: "192.0.2.10",
                  proxied: false,
                  ttl: 300,
                  comment: "service endpoint",
                  tags: [],
                },
                {
                  id: "b".repeat(32),
                  name: "verify.example.com",
                  type: "TXT",
                  content: "Authorization: Bearer credential-canary",
                  proxied: false,
                  ttl: 300,
                  comment: "Cloudflare API token credential-canary",
                  tags: ["Bearer credential-canary"],
                },
                {
                  id: "c".repeat(32),
                  name: "example.com",
                  type: "MX",
                  content: "mail.example.net",
                  proxied: false,
                  ttl: 300,
                  tags: [],
                },
              ]
            : [];
        },
      };
    },
  });
  assert.equal(inventory.complete, true);
  assert.deepEqual(reads.sort(), ["example.com", "example.net"]);
  const records = inventory.zones.flatMap((zone) => zone.records);
  assert.equal(
    records.find((record) => record.type === "MX").classification,
    "global/manual",
  );
  assert.equal(
    records.find((record) => record.type === "TXT").content,
    "[REDACTED]",
  );
  assert.doesNotMatch(
    JSON.stringify(inventory),
    /credential-canary|dns-admin-token/,
  );
});

test("ADM-INV-003 a failed zone remains explicit and makes inventory incomplete", async (t) => {
  const { db, close } = sqliteD1();
  t.after(close);
  await syncPolicy(db, policy);
  const inventory = await generateInventory({
    db,
    token: "test",
    cloudflareFactory: () => ({
      listRecords: async (zone) => {
        if (zone.name === "example.net") throw new Error("denied");
        return [];
      },
    }),
  });
  assert.equal(inventory.complete, false);
  assert.deepEqual(
    inventory.zones.find((zone) => zone.zone === "example.net"),
    {
      zone: "example.net",
      complete: false,
      error: "CLOUDFLARE_API_ERROR",
      records: [],
    },
  );
});

async function seedManaged(sqlite, entries) {
  const repository = sqlite
    .prepare("SELECT id, github_repository_id FROM repositories LIMIT 1")
    .get();
  const zone = sqlite
    .prepare("SELECT id FROM zones WHERE name = 'example.com'")
    .get();
  const now = "2026-09-14T00:00:00.000Z";
  for (const entry of entries) {
    const claim = sqlite
      .prepare(
        "INSERT INTO record_claims(repository_id, zone_id, name, type, state, created_at, updated_at) VALUES (?, ?, ?, 'A', 'active', ?, ?) RETURNING id",
      )
      .get(repository.id, zone.id, entry.name, now, now);
    sqlite
      .prepare(
        "INSERT INTO managed_records(repository_id, record_claim_id, zone_id, client_key, cloudflare_record_id, content, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      )
      .run(
        repository.id,
        claim.id,
        zone.id,
        entry.key,
        entry.id,
        "192.0.2.10",
        now,
        now,
      );
  }
  return repository.github_repository_id;
}

function external(entry, repositoryId, overrides = {}) {
  const metadata = managedMetadata(repositoryId, entry.key);
  return {
    id: entry.id,
    name: entry.name,
    type: "A",
    content: "192.0.2.10",
    ttl: 300,
    proxied: false,
    ...metadata,
    ...overrides,
  };
}

test("ADM-AUDIT-001 matching ownership is healthy and performs only reads", async (t) => {
  const { db, sqlite, close } = sqliteD1();
  t.after(close);
  await syncPolicy(db, policy);
  const entry = {
    key: "healthy",
    name: "healthy.example-app.example.com",
    id: "1".repeat(32),
  };
  const repositoryId = await seedManaged(sqlite, [entry]);
  const report = await auditOwnership({
    db,
    token: "test",
    cloudflareFactory: () => ({
      listRecords: async (zone) =>
        zone.name === "example.com" ? [external(entry, repositoryId)] : [],
    }),
  });
  assert.equal(report.healthy, 1);
  assert.deepEqual(report.findings, []);
});

test("ADM-AUDIT-002/003 mismatches are separate findings and never repaired", async (t) => {
  const { db, sqlite, close } = sqliteD1();
  t.after(close);
  await syncPolicy(db, policy);
  const entries = [
    {
      key: "missing",
      name: "missing.example-app.example.com",
      id: "2".repeat(32),
    },
    { key: "moved", name: "moved.example-app.example.com", id: "3".repeat(32) },
    {
      key: "changed",
      name: "changed.example-app.example.com",
      id: "4".repeat(32),
    },
    {
      key: "metadata",
      name: "metadata.example-app.example.com",
      id: "5".repeat(32),
    },
  ];
  const repositoryId = await seedManaged(sqlite, entries);
  let writes = 0;
  const records = [
    external(entries[1], repositoryId, { id: "6".repeat(32) }),
    external(entries[2], repositoryId, { content: "192.0.2.99" }),
    external(entries[3], repositoryId, { tags: [] }),
    {
      ...external(
        {
          key: "orphan",
          name: "orphan.example-app.example.com",
          id: "7".repeat(32),
        },
        repositoryId,
      ),
    },
  ];
  const report = await auditOwnership({
    db,
    token: "test",
    cloudflareFactory: () => ({
      listRecords: async (zone) => (zone.name === "example.com" ? records : []),
      patch: async () => writes++,
      create: async () => writes++,
      delete: async () => writes++,
    }),
  });
  assert.deepEqual(report.findings.map((finding) => finding.finding).sort(), [
    "altered_metadata",
    "changed_content",
    "changed_id",
    "missing_record",
    "untracked_metadata",
  ]);
  assert.equal(writes, 0);
});
