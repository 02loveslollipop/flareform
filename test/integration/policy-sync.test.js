import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { authorizeRecords } from "../../src/policy/authorize.js";
import { parsePolicyYaml, validatePolicy } from "../../src/policy/config.js";
import { policyVersion, syncPolicy } from "../../src/policy/sync.js";
import { readActivePolicy } from "../../src/policy/storage.js";
import { loadPolicy, remoteD1 } from "../../scripts/sync-config.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";

const zones = parsePolicyYaml(
  await readFile(
    new URL("../../config/examples/zones.yaml", import.meta.url),
    "utf8",
  ),
);
const repo = parsePolicyYaml(
  await readFile(
    new URL(
      "../../config/examples/repositories/example-app.yaml",
      import.meta.url,
    ),
    "utf8",
  ),
);
const canonical = () => validatePolicy(zones, [repo]);

test("POL-SYNC-001/E2E-ADM-001 valid two-zone policy sync records version and audit", async (t) => {
  const { db, sqlite, close } = sqliteD1();
  t.after(close);
  const policy = await loadPolicy(
    new URL("../../config/examples", import.meta.url).pathname,
  );
  const result = await syncPolicy(db, policy);
  assert.equal(result.version, policyVersion(policy));
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM zones WHERE enabled = 1").get().n,
    2,
  );
  assert.equal(
    sqlite
      .prepare("SELECT count(*) AS n FROM repositories WHERE enabled = 1")
      .get().n,
    1,
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM repository_grants").get().n,
    4,
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM policy_versions").get().n,
    1,
  );
  assert.equal(
    sqlite.prepare("SELECT action,new_value FROM audit_log").get().new_value,
    result.version,
  );
  const active = await readActivePolicy(db);
  assert.equal(active.version, result.version);
  const authorized = authorizeRecords(
    active.policy,
    repo.github.repository_id,
    [
      { name: "example-app.example.com", type: "A" },
      { name: "_grpc._tcp.api.example-app.example.net", type: "SRV" },
    ],
  );
  assert.deepEqual(
    authorized.map((item) => item.zone),
    ["example.com", "example.net"],
  );
  assert.equal((await syncPolicy(db, policy)).changed, false);
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM audit_log").get().n,
    1,
  );
});

test("POL-SYNC-002/003 invalid candidate and failures preserve last-known-good", async (t) => {
  const { db, sqlite, close } = sqliteD1();
  t.after(close);
  const policy = canonical();
  await syncPolicy(db, policy);
  const original = sqlite
    .prepare("SELECT current_version FROM policy_state")
    .get().current_version;
  const bad = structuredClone(repo);
  bad.grants[0].zone = "example.net";
  assert.throws(() => validatePolicy(zones, [bad]));
  assert.equal((await readActivePolicy(db)).version, original);
  assert.equal(
    sqlite.prepare("SELECT current_version FROM policy_state").get()
      .current_version,
    original,
  );
  const differentOwner = structuredClone(policy);
  differentOwner.repositories[0].github.owner_id = "222";
  await assert.rejects(syncPolicy(db, differentOwner));
  assert.equal(
    sqlite.prepare("SELECT current_version FROM policy_state").get()
      .current_version,
    original,
  );
  assert.equal(
    sqlite.prepare("SELECT github_owner_id FROM repositories").get()
      .github_owner_id,
    "987654321",
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM policy_versions").get().n,
    1,
  );
  const invalidZoneId = structuredClone(policy);
  invalidZoneId.zones[0].cloudflare_zone_id =
    "ffffffffffffffffffffffffffffffff";
  await assert.rejects(syncPolicy(db, invalidZoneId));
  assert.equal(
    sqlite.prepare("SELECT current_version FROM policy_state").get()
      .current_version,
    original,
  );
});

test("POL-SYNC-003 every batch position rolls back the complete candidate", async (t) => {
  const { db, sqlite, close } = sqliteD1();
  t.after(close);
  await syncPolicy(db, canonical());
  const original = sqlite
    .prepare("SELECT current_version FROM policy_state")
    .get().current_version;
  const candidate = canonical();
  candidate.repositories[0].enabled = false;
  const realBatch = db.batch;
  for (let position = 0; position <= 13; position++) {
    db.batch = (statements) => {
      const injected = [...statements];
      injected.splice(
        position,
        0,
        db.prepare("INSERT INTO missing_failure_probe VALUES (1)"),
      );
      return realBatch(injected);
    };
    await assert.rejects(syncPolicy(db, candidate));
    assert.equal(
      sqlite.prepare("SELECT current_version FROM policy_state").get()
        .current_version,
      original,
    );
    assert.equal(
      sqlite.prepare("SELECT enabled FROM repositories").get().enabled,
      1,
    );
    assert.equal(
      sqlite.prepare("SELECT count(*) AS n FROM policy_versions").get().n,
      1,
    );
  }
  db.batch = realBatch;
});

test("POL-SYNC-004 canonical version ignores source and repository ordering", () => {
  const second = structuredClone(repo);
  second.github.repository_id = "222222222";
  second.grants = [
    {
      zone: "example.com",
      exact: ["other.example.com"],
      descendants: ["other.example.com"],
      record_types: ["SRV", "A"],
    },
  ];
  const a = validatePolicy(zones, [repo, second]);
  const reversedZones = { zones: [...zones.zones].reverse() };
  const b = validatePolicy(reversedZones, [second, repo]);
  assert.equal(policyVersion(a), policyVersion(b));
});

test("POL-SYNC-005 removed repository, zone, and grant are disabled atomically", async (t) => {
  const { db, sqlite, close } = sqliteD1();
  t.after(close);
  const first = canonical();
  await syncPolicy(db, first);
  const second = structuredClone(first);
  second.zones[1].enabled = false;
  second.repositories[0].grants = second.repositories[0].grants.filter(
    (grant) => grant.zone === "example.com",
  );
  await syncPolicy(db, second);
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM repository_grants").get().n,
    2,
  );
  assert.equal(
    sqlite.prepare("SELECT enabled FROM zones WHERE name = 'example.net'").get()
      .enabled,
    0,
  );
  const active = await readActivePolicy(db);
  assert.throws(() =>
    authorizeRecords(active.policy, repo.github.repository_id, [
      { name: "example-app.example.net", type: "A" },
    ]),
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM policy_versions").get().n,
    2,
  );
  const empty = { ...second, repositories: [] };
  await syncPolicy(db, empty);
  assert.equal(
    sqlite.prepare("SELECT enabled FROM repositories").get().enabled,
    0,
  );
});

test("SEC-POL-002 remote adapter sends bound atomic batch and never accepts failed result", async () => {
  let observed;
  let succeed = true;
  const fakeFetch = async (_url, init) => {
    observed = init;
    return {
      ok: true,
      json: async () => ({
        success: succeed,
        result: [{ success: succeed, results: [] }],
      }),
    };
  };
  const db = remoteD1({
    accountId: "a".repeat(32),
    databaseId: "11111111-1111-1111-1111-111111111111",
    token: "x".repeat(20),
    fetchImpl: fakeFetch,
  });
  await db.batch([db.prepare("SELECT ?").bind("x'; DROP TABLE zones; --")]);
  const sent = JSON.parse(observed.body).batch;
  assert.equal(sent[0].sql, "BEGIN TRANSACTION");
  assert.equal(sent.at(-1).sql, "COMMIT");
  assert.equal(sent[1].params[0], "x'; DROP TABLE zones; --");
  assert.equal(sent[1].sql, "SELECT ?");
  assert.equal(observed.redirect, "error");
  succeed = false;
  await assert.rejects(
    db.batch([db.prepare("SELECT 1")]),
    /Administrative D1 query failed/,
  );
});

test("E2E-ADM-001 operator CLI validates and dry-runs without a D1 credential", () => {
  const script = new URL("../../scripts/sync-config.js", import.meta.url)
    .pathname;
  const dir = new URL("../../config/examples", import.meta.url).pathname;
  for (const mode of ["--validate", "--dry-run"]) {
    const run = spawnSync(
      process.execPath,
      [script, mode, "--config-dir", dir],
      {
        encoding: "utf8",
        env: { ...process.env, FLAREFORM_D1_ADMIN_TOKEN: "" },
      },
    );
    assert.equal(run.status, 0, run.stderr);
    assert.equal(JSON.parse(run.stdout).zones, 2);
  }
  const unsafe = spawnSync(
    process.execPath,
    [script, "--apply", "--config-dir", dir],
    { encoding: "utf8" },
  );
  assert.notEqual(unsafe.status, 0);
});
