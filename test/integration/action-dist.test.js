import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../..", import.meta.url));
const preload = fileURLToPath(
  new URL("../fixtures/action-fetch.cjs", import.meta.url),
);

function run(environment) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["github-action/dist/index.js"], {
      cwd: root,
      env: environment,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk));
    child.stderr.on("data", (chunk) => (stderr += chunk));
    child.on("error", reject);
    child.on("close", (code) => resolve({ code, stdout, stderr }));
  });
}

test("ACT-INT-001/E2E-ACT-001 packaged Action plans and applies mirrored records with OIDC", async () => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), "flareform-dist-"));
  await writeFile(
    path.join(workspace, "flareform.yaml"),
    `version: 1
reconciliation: keep
records:
  - key: main-me
    zone: example.com
    name: example-app.example.com
    type: A
    content: \${DEPLOYMENT_IPV4}
    proxied: false
    ttl: 60
  - key: main-uk
    zone: example.net
    name: example-app.example.net
    type: A
    content: \${DEPLOYMENT_IPV4}
    proxied: false
    ttl: 60
`,
  );
  const result = await run({
    ...process.env,
    NODE_OPTIONS:
      `${process.env.NODE_OPTIONS ?? ""} --require=${preload}`.trim(),
    GITHUB_WORKSPACE: workspace,
    INPUT_OPERATION: "apply",
    INPUT_MANIFEST: "flareform.yaml",
    DEPLOYMENT_IPV4: "192.0.2.10",
    ACTIONS_ID_TOKEN_REQUEST_URL:
      "https://pipelines.actions.githubusercontent.com/token",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "request-token-canary",
    SECRET_CANARY: "environment-secret-canary",
  });
  assert.equal(result.code, 0, result.stderr);
  assert.match(result.stdout, /\[example\.com\] success/);
  assert.match(result.stdout, /\[example\.net\] success/);
  assert.doesNotMatch(
    `${result.stdout}\n${result.stderr}`,
    /request-token-canary|environment-secret-canary|192\.0\.2\.10|fixture-[12]/,
  );
});
