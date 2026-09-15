import assert from "node:assert/strict";
import test from "node:test";
import { cleanupEphemeralState } from "../../src/operations/maintenance.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";

test("OIDC-REPLAY-003/OPS maintenance deletes only expired unreferenced ephemeral state", async (t) => {
  const location = sqliteD1();
  t.after(location.close);
  const sql = location.sqlite;
  sql
    .prepare(
      "INSERT INTO zones(name,cloudflare_zone_id,created_at) VALUES(?,?,?)",
    )
    .run("example.com", "zone", "now");
  sql
    .prepare(
      `INSERT INTO repositories(github_repository_id,github_owner_id,display_name,expected_workflow_ref,created_at,updated_at) VALUES(?,?,?,?,?,?)`,
    )
    .run(
      "1",
      "2",
      "repo",
      "owner/repo/.github/workflows/dns.yml@refs/heads/main",
      "now",
      "now",
    );
  sql.prepare("INSERT INTO oidc_jti VALUES(?,?,?,?)").run("old", 1, 99, "now");
  sql
    .prepare("INSERT INTO oidc_jti VALUES(?,?,?,?)")
    .run("boundary", 1, 100, "now");
  sql
    .prepare(
      "INSERT INTO plans(id,repository_id,manifest_sha256,policy_version,dns_state_sha256,created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
    )
    .run("old", 1, "m", "p", "d", "now", 99);
  sql
    .prepare(
      "INSERT INTO plans(id,repository_id,manifest_sha256,policy_version,dns_state_sha256,created_at,expires_at) VALUES(?,?,?,?,?,?,?)",
    )
    .run("boundary", 1, "m", "p", "d", "now", 100);
  await cleanupEphemeralState(location.db, 100);
  assert.deepEqual(
    sql
      .prepare("SELECT jti FROM oidc_jti ORDER BY jti")
      .all()
      .map((row) => row.jti),
    ["boundary"],
  );
  assert.deepEqual(
    sql
      .prepare("SELECT id FROM plans ORDER BY id")
      .all()
      .map((row) => row.id),
    ["boundary"],
  );
});

test("maintenance cleanup rejects an invalid clock without touching state", async (t) => {
  const location = sqliteD1();
  t.after(location.close);
  await assert.rejects(cleanupEphemeralState(location.db, -1), TypeError);
});
