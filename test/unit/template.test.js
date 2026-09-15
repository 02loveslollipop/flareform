import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parse } from "yaml";

const root = new URL("../../templates/flareform-template/", import.meta.url);

test("TPL-001 manifest mirrors one service across both primary zones", async () => {
  const manifest = parse(
    await readFile(new URL("flareform.yaml", root), "utf8"),
  );
  assert.equal(manifest.reconciliation, "keep");
  assert.deepEqual(manifest.records.map((record) => record.zone).sort(), [
    "example.com",
    "example.net",
  ]);
  assert.ok(
    manifest.records.every((record) => record.content === "${DEPLOYMENT_IPV4}"),
  );
});

test("TPL-002/003 and SEC-WF-002 production workflow is minimal, protected, and main-only", async () => {
  const source = await readFile(
    new URL(".github/workflows/deploy-and-dns.yml", root),
    "utf8",
  );
  const workflow = parse(source);
  assert.deepEqual(workflow.on, { push: { branches: ["main"] } });
  assert.deepEqual(workflow.permissions, { contents: "read" });
  assert.deepEqual(workflow.jobs.dns.permissions, {
    contents: "read",
    "id-token": "write",
  });
  assert.equal(workflow.jobs.dns.environment, "production");
  assert.equal(workflow.concurrency["cancel-in-progress"], false);
  assert.doesNotMatch(
    source,
    /pull_request(?:_target)?|workflow_dispatch|tags:|branches-ignore/,
  );
});

test("TPL-004/SEC-WF-001 template has no Cloudflare secret and pins every Action", async () => {
  const files = await Promise.all(
    ["flareform.yaml", "README.md", ".github/workflows/deploy-and-dns.yml"].map(
      (name) => readFile(new URL(name, root), "utf8"),
    ),
  );
  const source = files.join("\n");
  assert.doesNotMatch(
    source,
    /CLOUDFLARE_(?:API_)?TOKEN|CLOUDFLARE_DNS_TOKEN|\$\{\{\s*secrets\./i,
  );
  for (const match of files[2].matchAll(/uses:\s*[^@\s]+@([^\s#]+)/g))
    assert.match(match[1], /^[0-9a-f]{40}$/);
  assert.equal((files[2].match(/uses:/g) ?? []).length, 4);
});
