import assert from "node:assert/strict";
import test from "node:test";
import { exportAuditEvents } from "../../src/audit/export.js";
import { DnsRepository } from "../../src/db/repository.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";

function archive() {
  const objects = new Map();
  return {
    objects,
    async put(key, value, options) {
      assert.deepEqual(options.onlyIf, { etagDoesNotMatch: "*" });
      if (objects.has(key)) return null;
      objects.set(key, value);
      return { key };
    },
    async get(key) {
      return objects.has(key) ? { text: async () => objects.get(key) } : null;
    },
  };
}

test("AUD-EXPORT-001 scheduled export writes immutable, redacted, idempotent objects", async (t) => {
  const location = sqliteD1();
  t.after(location.close);
  const repo = new DnsRepository(location.db);
  await repo.appendAudit({
    action: "test",
    zone: "example.com",
    recordName: "example-app.example.com",
    recordType: "TXT",
    success: true,
    now: "2026-09-14T00:00:00Z",
  });
  const bucket = archive();
  assert.equal(await exportAuditEvents({ db: location.db, bucket, now: 1 }), 1);
  assert.equal(bucket.objects.size, 1);
  const [key, body] = [...bucket.objects][0];
  assert.equal(key, "audit/v1/00000000000000000001.json");
  assert.doesNotMatch(body, /token|authorization/i);
  assert.equal(await exportAuditEvents({ db: location.db, bucket, now: 2 }), 0);
});

test("AUD-EXPORT-002 R2 success plus D1 marker failure safely verifies on retry", async (t) => {
  const location = sqliteD1();
  t.after(location.close);
  const repo = new DnsRepository(location.db);
  await repo.appendAudit({ action: "test", success: false, now: "now" });
  const bucket = archive();
  location.sqlite.exec(
    "CREATE TRIGGER fail_export BEFORE INSERT ON audit_exports BEGIN SELECT RAISE(ABORT, 'fail'); END;",
  );
  await assert.rejects(exportAuditEvents({ db: location.db, bucket }), {
    code: "DATABASE_ERROR",
  });
  assert.equal(bucket.objects.size, 1);
  location.sqlite.exec("DROP TRIGGER fail_export");
  assert.equal(await exportAuditEvents({ db: location.db, bucket }), 1);
  assert.equal(bucket.objects.size, 1);
  location.sqlite.prepare("DELETE FROM audit_exports").run();
  bucket.objects.set([...bucket.objects.keys()][0], '{"tampered":true}');
  await assert.rejects(exportAuditEvents({ db: location.db, bucket }), {
    code: "DATABASE_ERROR",
  });
});
