import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { adoptRecord } from "../../src/admin/adopt.js";
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
const id = "a".repeat(32);

function provider(initial = {}) {
  let record = {
    id,
    name: "example-app.example.com",
    type: "A",
    content: "192.0.2.10",
    ttl: 300,
    proxied: false,
    tags: [],
    ...initial,
  };
  let patches = 0;
  return {
    factory: () => ({
      listRecords: async () => [structuredClone(record)],
      patch: async (_zone, recordId, payload) => {
        patches++;
        assert.equal(recordId, id);
        record = { ...record, ...structuredClone(payload) };
        return structuredClone(record);
      },
    }),
    get record() {
      return record;
    },
    get patches() {
      return patches;
    },
  };
}

function options(db, cloudflareFactory) {
  return {
    db,
    repositoryId: repositoryPolicy.github.repository_id,
    clientKey: "existing-ipv4",
    zoneName: "example.com",
    cloudflareRecordId: id,
    token: "admin-test-token",
    cloudflareFactory,
    now: Date.parse("2026-09-14T00:00:00Z"),
  };
}

test("ADM-ADOPT-001 dry-run shows exact target without provider or D1 mutation", async (t) => {
  const { db, sqlite, close } = sqliteD1();
  t.after(close);
  await syncPolicy(db, policy);
  const cloudflare = provider();
  const preview = await adoptRecord(options(db, cloudflare.factory));
  assert.deepEqual(preview, {
    repository_id: repositoryPolicy.github.repository_id,
    client_key: "existing-ipv4",
    zone: "example.com",
    cloudflare_record_id: id,
    name: "example-app.example.com",
    type: "A",
    current: {
      type: "A",
      name: "example-app.example.com",
      content: "192.0.2.10",
      comment: null,
    },
    metadata_change: true,
    database_change: true,
  });
  assert.equal(cloudflare.patches, 0);
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM record_claims").get().n,
    0,
  );
  assert.equal(
    sqlite
      .prepare(
        "SELECT count(*) AS n FROM audit_log WHERE action LIKE 'adoption_%' OR action = 'record_adopted'",
      )
      .get().n,
    0,
  );
});

test("ADM-ADOPT-003 valid apply adds exact metadata and ownership atomically", async (t) => {
  const { db, sqlite, close } = sqliteD1();
  t.after(close);
  await syncPolicy(db, policy);
  const cloudflare = provider();
  const result = await adoptRecord({
    ...options(db, cloudflare.factory),
    apply: true,
  });
  assert.equal(result.adopted, true);
  assert.equal(result.idempotent, false);
  assert.equal(cloudflare.patches, 1);
  assert.deepEqual(
    cloudflare.record.tags,
    managedMetadata(repositoryPolicy.github.repository_id, "existing-ipv4")
      .tags,
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM record_claims").get().n,
    1,
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM managed_records").get().n,
    1,
  );
  assert.equal(
    sqlite.prepare("SELECT action FROM audit_log ORDER BY id DESC").get()
      .action,
    "record_adopted",
  );
  const repeated = await adoptRecord({
    ...options(db, cloudflare.factory),
    apply: true,
  });
  assert.equal(repeated.idempotent, true);
  assert.equal(cloudflare.patches, 1);
});

test("ADM-ADOPT-004 denied grant and foreign metadata fail before mutation", async (t) => {
  const { db, close } = sqliteD1();
  t.after(close);
  await syncPolicy(db, policy);
  const outside = provider({ name: "other.example.com" });
  await assert.rejects(
    adoptRecord(options(db, outside.factory)),
    (error) => error.code === "HOSTNAME_NOT_AUTHORIZED",
  );
  assert.equal(outside.patches, 0);
  const foreign = provider({
    ...managedMetadata("999", "foreign"),
  });
  await assert.rejects(
    adoptRecord(options(db, foreign.factory)),
    (error) => error.code === "RECORD_OWNED_BY_OTHER_REPOSITORY",
  );
  assert.equal(foreign.patches, 0);
});

test("ADM-ADOPT-005 metadata success plus D1 failure is audited and resumable", async (t) => {
  const { db, sqlite, close } = sqliteD1();
  t.after(close);
  await syncPolicy(db, policy);
  const cloudflare = provider();
  let failBatch = true;
  const interrupted = {
    prepare: db.prepare,
    batch: async (statements) => {
      if (failBatch) {
        failBatch = false;
        throw new Error("injected database failure");
      }
      return db.batch(statements);
    },
  };
  await assert.rejects(
    adoptRecord({
      ...options(interrupted, cloudflare.factory),
      apply: true,
    }),
    (error) => error.code === "STATE_INDETERMINATE",
  );
  assert.equal(cloudflare.patches, 1);
  assert.equal(
    sqlite.prepare("SELECT action FROM audit_log ORDER BY id DESC").get()
      .action,
    "adoption_database_failed",
  );
  const resumed = await adoptRecord({
    ...options(db, cloudflare.factory),
    apply: true,
  });
  assert.equal(resumed.adopted, true);
  assert.equal(cloudflare.patches, 1);
});
