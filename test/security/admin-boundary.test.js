import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { isApprovedAdministrativeCi } from "../../scripts/adopt-record.js";

test("SEC-ADM-001 public Worker contains no adoption or ownership repair route", async () => {
  const router = await readFile(
    new URL("../../src/http/router.js", import.meta.url),
    "utf8",
  );
  assert.doesNotMatch(
    router,
    /adopt|inventory|audit-ownership|reconcile-admin/,
  );
  assert.match(router, /"\/v1\/plan"/);
  assert.match(router, /"\/v1\/apply"/);
});

test("ADM-ADOPT-002/003 and SEC-ADM-002 only trusted main control-plane CI bypasses manual confirmation", () => {
  const approved = {
    GITHUB_ACTIONS: "true",
    GITHUB_REPOSITORY: "example-org/flareform",
    FLAREFORM_CONTROL_REPOSITORY: "example-org/flareform",
    GITHUB_REF: "refs/heads/main",
    FLAREFORM_ADMIN_ENVIRONMENT: "dns-administration",
  };
  assert.equal(isApprovedAdministrativeCi(approved), true);
  for (const [key, value] of Object.entries({
    GITHUB_ACTIONS: "false",
    GITHUB_REPOSITORY: "example-org/example-app",
    GITHUB_REF: "refs/heads/feature",
    FLAREFORM_ADMIN_ENVIRONMENT: "production",
  }))
    assert.equal(
      isApprovedAdministrativeCi({ ...approved, [key]: value }),
      false,
    );
});

test("SEC-ADM-002 adoption workflow is manual, main-only, environment-gated, and pinned", async () => {
  const workflow = await readFile(
    new URL(
      "../../examples/github-workflows/adopt-record.yml",
      import.meta.url,
    ),
    "utf8",
  );
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /environment: dns-administration/);
  assert.doesNotMatch(workflow, /pull_request:|push:/);
  for (const match of workflow.matchAll(/uses: [^@\n]+@([^\s#]+)/g))
    assert.match(match[1], /^[0-9a-f]{40}$/);
});

test("SEC-ADM-003 reconciliation workflow is manual, main-only, environment-gated, and pinned", async () => {
  const workflow = await readFile(
    new URL(
      "../../examples/github-workflows/reconcile-record.yml",
      import.meta.url,
    ),
    "utf8",
  );
  assert.match(workflow, /workflow_dispatch:/);
  assert.match(workflow, /github\.ref == 'refs\/heads\/main'/);
  assert.match(workflow, /environment: dns-administration/);
  assert.match(workflow, /reconcile-record\.js --resolve/);
  assert.doesNotMatch(workflow, /pull_request:|push:/);
  for (const match of workflow.matchAll(/uses: [^@\n]+@([^\s#]+)/g))
    assert.match(match[1], /^[0-9a-f]{40}$/);
});
