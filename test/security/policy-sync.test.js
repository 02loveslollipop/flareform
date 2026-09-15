import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("SEC-POL-001 public Worker has no administration route", async () => {
  const worker = await readFile(
    new URL("../../src/index.js", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(worker, /syncPolicy|policy\/sync|admin\/policy/);
});

test("SEC-POL-002 application identity alone cannot invoke remote policy sync", () => {
  const script = new URL("../../scripts/sync-config.js", import.meta.url)
    .pathname;
  const configDir = new URL("../../config/examples", import.meta.url).pathname;
  const result = spawnSync(
    process.execPath,
    [
      script,
      "--apply",
      "--config-dir",
      configDir,
      "--account-id",
      "a".repeat(32),
      "--database-id",
      "11111111-1111-1111-1111-111111111111",
      "--confirm-remote",
    ],
    { encoding: "utf8", env: { ...process.env, FLAREFORM_D1_ADMIN_TOKEN: "" } },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /Policy validation or synchronization failed/);
  assert.doesNotMatch(result.stderr, /Authorization|Bearer|\.yaml/);
});

test("SEC-POL-002 admin workflow is manual, main-only, and environment-gated", async () => {
  const workflow = await readFile(
    new URL("../../examples/github-workflows/sync-policy.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /environment: dns-policy/);
  assert.match(
    workflow,
    /FLAREFORM_D1_ADMIN_TOKEN: \$\{\{ secrets\.FLAREFORM_D1_ADMIN_TOKEN \}\}/,
  );
  assert.doesNotMatch(workflow, /pull_request:/);
});
