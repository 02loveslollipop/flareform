import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { scanText } from "../../scripts/scan-secrets.js";

test("SEC-SUP-002 secret scanner detects credential patterns without returning values", () => {
  const secret = `ghp_${"a".repeat(36)}`;
  const findings = scanText(`safe\n${secret}\n`);
  assert.deepEqual(findings, [{ rule: "github-token", line: 2 }]);
  assert.doesNotMatch(JSON.stringify(findings), new RegExp(secret));
});

test("SEC-CI-001 PR CI audits dependencies, scans secrets, verifies builds, and only uploads redacted evidence", async () => {
  const workflow = await readFile(
    new URL("../../.github/workflows/test.yml", import.meta.url),
    "utf8",
  );
  for (const required of [
    "npm ci",
    "npm audit --audit-level=high",
    "npm audit --prefix github-action",
    "node scripts/scan-secrets.js",
    "npm run check",
    "node scripts/review-dependencies.js",
    "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
  ])
    assert.match(
      workflow,
      new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")),
    );
  assert.doesNotMatch(
    workflow,
    /wrangler deploy|d1 migrations apply|secret put/,
  );
  assert.doesNotMatch(workflow, /pull-requests: write/);
});

test("SEC-WF-004 CODEOWNERS covers all security-sensitive paths", async () => {
  const owners = await readFile(
    new URL("../../.github/CODEOWNERS", import.meta.url),
    "utf8",
  );
  for (const path of [
    "/.github/",
    "/config/",
    "/migrations/",
    "/src/admin/",
    "/src/auth/",
    "/src/db/",
    "/src/dns/",
    "/src/http/",
    "/github-action/",
    "/wrangler.jsonc",
  ])
    assert.match(owners, new RegExp(`^${path.replaceAll("/", "\\/")} `, "m"));
});
