import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { DnsRepository } from "../../src/db/repository.js";

test("SEC-INJ-001 request-controlled values are bound and cannot alter SQL", async (t) => {
  const sqlite = new DatabaseSync(":memory:");
  t.after(() => sqlite.close());
  sqlite.exec("CREATE TABLE zones(name TEXT)");
  sqlite.prepare("INSERT INTO zones(name) VALUES (?)").run("safe.example");
  const repository = new DnsRepository({
    prepare: (sql) => ({
      bind: (...values) => ({
        first: async () => sqlite.prepare(sql).get(...values) ?? null,
      }),
    }),
    batch: async () => [],
  });
  assert.equal(await repository.getZone("safe.example' OR 1=1 --"), null);
  assert.equal((await repository.getZone("safe.example")).name, "safe.example");
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM zones").get().n, 1);
});
