import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("DEP-001/002 trusted-main deployment orders checks, migration, policy, deploy, and smoke", async () => {
  const workflow = await readFile(
    new URL("../../examples/github-workflows/deploy.yml", import.meta.url),
    "utf8",
  );
  const ordered = [
    "npm run check",
    "migrate:remote",
    "sync-config.js --apply",
    "wrangler deploy",
    "Smoke-test fixed health endpoint",
    "Smoke-test authenticated read-only plan",
  ].map((text) => workflow.indexOf(text));
  assert.ok(ordered.every((position) => position >= 0));
  assert.deepEqual(
    ordered,
    [...ordered].sort((a, b) => a - b),
  );
  assert.match(workflow, /needs: verify/);
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /FLAREFORM_DEPLOY_ENABLED == 'true'/);
  assert.match(workflow, /environment: production/);
});

test("SEC-CI-002/003 deployment has minimal permissions, separate credential, and no PR trigger", async () => {
  const workflow = await readFile(
    new URL("../../examples/github-workflows/deploy.yml", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(workflow, /pull_request(?:_target)?:/);
  assert.match(
    workflow,
    /CLOUDFLARE_API_TOKEN: \$\{\{ secrets\.CLOUDFLARE_DEPLOY_TOKEN \}\}/,
  );
  assert.doesNotMatch(workflow, /CLOUDFLARE_DNS_TOKEN/);
  assert.match(workflow, /contents: read/);
  assert.match(workflow, /id-token: write/);
  assert.match(workflow, /wrangler rollback/);
  const jobEnvironment = workflow.slice(
    workflow.indexOf("  deploy:"),
    workflow.indexOf("    steps:", workflow.indexOf("  deploy:")),
  );
  assert.doesNotMatch(jobEnvironment, /secrets\./);
  const smokeAction = workflow.slice(
    workflow.indexOf("uses: .\/github-action"),
    workflow.indexOf("- name: Roll back"),
  );
  assert.doesNotMatch(smokeAction, /CLOUDFLARE|FLAREFORM_D1_ADMIN_TOKEN/);
  for (const match of workflow.matchAll(/uses: (?!\.\/)[^@\n]+@([^\s#]+)/g))
    assert.match(match[1], /^[0-9a-f]{40}$/);
});

test("DEP-003 smoke manifest is keep-only and covers both configured zones", async () => {
  const manifest = await readFile(
    new URL("../../config/examples/smoke-manifest.yaml", import.meta.url),
    "utf8",
  );
  assert.match(manifest, /reconciliation: keep/);
  assert.match(manifest, /zone: example\.com/);
  assert.match(manifest, /zone: example\.net/);
  assert.doesNotMatch(manifest, /prune|\$\{/);
});

test("OPS/SEC-MON scheduled controls are configured and alert guidance excludes secrets", async () => {
  const [worker, config, operations] = await Promise.all([
    readFile(new URL("../../src/index.js", import.meta.url), "utf8"),
    readFile(new URL("../../wrangler.jsonc", import.meta.url), "utf8"),
    readFile(new URL("../../docs/operations.md", import.meta.url), "utf8"),
  ]);
  assert.match(worker, /runScheduledMaintenance/);
  assert.match(config, /"crons"/);
  for (const phrase of [
    "authorization denials",
    "replay",
    "prune attempts",
    "partial or indeterminate",
    "maintenance persistence failure",
    "Leaked runtime token",
    "Compromised application repository",
    "Compromised control plane",
    "Ownership mismatch",
    "Zone\/provider outage",
  ])
    assert.match(operations, new RegExp(phrase, "i"));
  assert.match(operations, /never forward headers, JWTs, tokens/);
});
