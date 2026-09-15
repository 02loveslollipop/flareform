import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const migrate = fileURLToPath(
  new URL("../../scripts/migrate.js", import.meta.url),
);
const wrangler = fileURLToPath(
  new URL("../../node_modules/wrangler/bin/wrangler.js", import.meta.url),
);
const sql = fileURLToPath(
  new URL("../../migrations/0001_initial.sql", import.meta.url),
);
const policySql = fileURLToPath(
  new URL("../../migrations/0002_policy_versions.sql", import.meta.url),
);
const admissionSql = fileURLToPath(
  new URL("../../migrations/0003_apply_admission.sql", import.meta.url),
);
const maintenanceSql = fileURLToPath(
  new URL("../../migrations/0004_d1_maintenance_storage.sql", import.meta.url),
);

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "flareform-migration-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "migrations"));
  await copyFile(sql, join(root, "migrations", "0001_initial.sql"));
  await copyFile(
    policySql,
    join(root, "migrations", "0002_policy_versions.sql"),
  );
  await copyFile(
    admissionSql,
    join(root, "migrations", "0003_apply_admission.sql"),
  );
  await copyFile(
    maintenanceSql,
    join(root, "migrations", "0004_d1_maintenance_storage.sql"),
  );
  const config = join(root, "wrangler.jsonc");
  const state = join(root, "state");
  await writeFile(
    config,
    JSON.stringify({
      name: "flareform-migration-test",
      compatibility_date: "2026-09-11",
      d1_databases: [
        {
          binding: "DB",
          database_name: "flareform-test",
          database_id: randomUUID(),
          migrations_dir: "migrations",
        },
      ],
    }),
  );
  return { root, config, state };
}

function apply({ config, state }) {
  return execFileSync(
    process.execPath,
    [migrate, "--local", "--config", config, "--persist-to", state],
    {
      encoding: "utf8",
      env: { ...process.env, CI: "true" },
    },
  );
}

function query({ config, state }, sqlCommand) {
  const output = execFileSync(
    process.execPath,
    [
      wrangler,
      "d1",
      "execute",
      "DB",
      "--local",
      "--config",
      config,
      "--persist-to",
      state,
      "--command",
      sqlCommand,
      "--json",
    ],
    {
      encoding: "utf8",
      env: { ...process.env, CI: "true" },
    },
  );
  return JSON.parse(output)[0].results;
}

test("DB-MIG-001/002 Wrangler applies ordered migration once and records its version", async (t) => {
  const location = await fixture(t);
  assert.match(apply(location), /0001_initial.sql/);
  assert.equal(query(location, "SELECT name FROM d1_migrations").length, 4);
  assert.equal(
    query(location, "SELECT name FROM d1_migrations ORDER BY name")[0].name,
    "0001_initial.sql",
  );
  apply(location);
  assert.equal(
    query(location, "SELECT count(*) AS n FROM d1_migrations")[0].n,
    4,
  );
  assert.equal(query(location, "PRAGMA foreign_keys")[0].foreign_keys, 1);
});

test("DB-MIG-003 failed migration rolls back and preserves earlier schema", async (t) => {
  const location = await fixture(t);
  apply(location);
  await writeFile(
    join(location.root, "migrations", "0005_broken.sql"),
    "CREATE TABLE rollback_probe(id INTEGER PRIMARY KEY);\nINSERT INTO does_not_exist VALUES (1);\n",
  );
  const result = spawnSync(
    process.execPath,
    [
      migrate,
      "--local",
      "--config",
      location.config,
      "--persist-to",
      location.state,
    ],
    {
      encoding: "utf8",
      env: { ...process.env, CI: "true" },
    },
  );
  assert.notEqual(result.status, 0);
  assert.equal(
    query(location, "SELECT count(*) AS n FROM d1_migrations")[0].n,
    4,
  );
  assert.equal(
    query(
      location,
      "SELECT name FROM sqlite_master WHERE name = 'rollback_probe'",
    ).length,
    0,
  );
  assert.equal(
    query(location, "SELECT name FROM sqlite_master WHERE name = 'zones'")
      .length,
    1,
  );
});

test("DB-MIG-004 no prior schema is supported before 0001", async (t) => {
  const location = await fixture(t);
  apply(location);
  assert.deepEqual(
    query(location, "SELECT name FROM d1_migrations ORDER BY name").map(
      (row) => row.name,
    ),
    [
      "0001_initial.sql",
      "0002_policy_versions.sql",
      "0003_apply_admission.sql",
      "0004_d1_maintenance_storage.sql",
    ],
  );
});

test("DB-MIG-005 remote migration requires explicit confirmation and operator config", async (t) => {
  const location = await fixture(t);
  const result = spawnSync(
    process.execPath,
    [migrate, "--remote", "--config", location.config],
    {
      encoding: "utf8",
      env: { ...process.env, CI: "true" },
    },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Usage:/);
});

test("DB-MIG-006 trigger CASE expressions are compatible with remote D1 parsing", async () => {
  const source = await readFile(admissionSql, "utf8");
  assert.doesNotMatch(source, /SELECT CASE/);
  assert.equal(source.match(/SELECT \(CASE/g)?.length, 7);
});

test("DB-MIG-007 D1 replaces object-storage export state", async () => {
  const source = await readFile(maintenanceSql, "utf8");
  assert.match(source, /DROP TABLE audit_exports/);
  for (const table of [
    "maintenance_runs",
    "inventory_zone_snapshots",
    "inventory_record_snapshots",
    "ownership_findings",
  ])
    assert.match(source, new RegExp(`CREATE TABLE ${table}`));
  assert.doesNotMatch(source, /R2|object_key/i);
});
