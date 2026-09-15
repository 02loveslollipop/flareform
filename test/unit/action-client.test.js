import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  ActionError,
  callFlareForm,
  prepareManifest,
  PRODUCTION_AUDIENCE,
  requestOidcToken,
  runAction,
} from "../../github-action/src/client.js";
import { parse } from "yaml";

const jwt = (value) => `eyJhbGciOiJub25lIn0.${value}.signature`;
const manifest = `
version: 1
reconciliation: keep
records:
  - key: main-me
    zone: example.com
    name: example-app.example.com
    type: A
    content: \${DEPLOYMENT_IPV4}
    proxied: false
    ttl: 60
`;

test("ACT-UNIT-001 Action metadata exposes only safe manifest and operation inputs", async () => {
  const metadata = parse(
    await readFile(
      new URL("../../github-action/action.yml", import.meta.url),
      "utf8",
    ),
  );
  assert.equal(metadata.runs.using, "node24");
  assert.equal(metadata.runs.main, "dist/index.js");
  assert.deepEqual(Object.keys(metadata.inputs).sort(), [
    "manifest",
    "operation",
  ]);
  assert.equal(metadata.inputs.manifest.default, "flareform.yaml");
  assert.equal(metadata.inputs.operation.default, "apply");
});

test("ACT-UNIT-002/003 explicit variables resolve structurally and local mistakes fail closed", () => {
  const result = prepareManifest(manifest, {
    DEPLOYMENT_IPV4: "192.0.2.10",
    SECRET_CANARY: "must-not-be-read",
  });
  assert.match(result, /192\.0\.2\.10/);
  assert.doesNotMatch(result, /must-not-be-read|DEPLOYMENT_IPV4/);
  assert.throws(
    () => prepareManifest(manifest, {}),
    (error) =>
      error instanceof ActionError && error.code === "MISSING_VARIABLE",
  );
  assert.throws(
    () => prepareManifest("version: 1\nrecords: []\n", {}),
    (error) => error.code === "INVALID_MANIFEST",
  );
  assert.throws(
    () => prepareManifest(manifest.replace("${DEPLOYMENT_IPV4}", "${bad}"), {}),
    (error) => error.code === "INVALID_VARIABLE_REFERENCE",
  );
});

test("ACT-UNIT-004 OIDC audience is fixed and the runner endpoint cannot redirect", async () => {
  const calls = [];
  const environment = {
    ACTIONS_ID_TOKEN_REQUEST_URL:
      "https://pipelines.actions.githubusercontent.com/token?job=1",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "oidc-request-secret",
  };
  const token = await requestOidcToken({
    environment,
    fetchImpl: async (url, init) => {
      calls.push({ url: String(url), init });
      return Response.json({ value: jwt("one") });
    },
  });
  assert.equal(token, jwt("one"));
  assert.equal(
    new URL(calls[0].url).searchParams.get("audience"),
    PRODUCTION_AUDIENCE,
  );
  assert.equal(calls[0].init.redirect, "manual");
  await assert.rejects(
    requestOidcToken({
      environment,
      fetchImpl: async () =>
        new Response(null, {
          status: 302,
          headers: { location: "https://attacker.invalid" },
        }),
    }),
    (error) => error.code === "REDIRECT_REJECTED",
  );
});

test("SEC-ACT-001/002 API endpoint is immutable and redirects never receive a follow-up JWT", async () => {
  const calls = [];
  await assert.rejects(
    callFlareForm({
      operation: "apply",
      manifest: "safe",
      token: "jwt-canary",
      fetchImpl: async (url, init) => {
        calls.push({ url, init });
        return new Response(null, {
          status: 307,
          headers: { location: "https://attacker.invalid/steal" },
        });
      },
    }),
    (error) => error.code === "REDIRECT_REJECTED",
  );
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://dns.02labs.me/v1/apply");
  assert.equal(calls[0].init.redirect, "manual");
});

test("ACT-UNIT-005/006/007 apply renders zones and retries once with a fresh JWT", async () => {
  const workspace = await mkdtemp(path.join(os.tmpdir(), "flareform-action-"));
  await writeFile(path.join(workspace, "flareform.yaml"), manifest);
  const environment = {
    GITHUB_WORKSPACE: workspace,
    INPUT_OPERATION: "apply",
    INPUT_MANIFEST: "flareform.yaml",
    DEPLOYMENT_IPV4: "192.0.2.10",
    FLAREFORM_ENDPOINT: "https://attacker.invalid",
    ACTIONS_ID_TOKEN_REQUEST_URL:
      "https://pipelines.actions.githubusercontent.com/token",
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: "oidc-request-canary",
    SECRET_CANARY: "environment-secret-canary",
  };
  const calls = [];
  let oidc = 0;
  let apply = 0;
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), authorization: init.headers.authorization });
    if (
      String(url).startsWith("https://pipelines.actions.githubusercontent.com")
    )
      return Response.json({ value: jwt(`token-${++oidc}`) });
    if (String(url).endsWith("/v1/plan"))
      return Response.json({
        plan_id: "11111111-1111-4111-8111-111111111111",
        changes: {
          "example.com": [
            {
              action: "create",
              type: "A",
              name: "example-app.example.com",
              key: "main-me",
            },
          ],
        },
      });
    apply++;
    if (apply === 1)
      return Response.json(
        {
          operation_id: "ffop_123",
          status: "partial_failure",
          zones: {
            "example.com": { status: "failed", error: "DNS_READ_FAILED" },
          },
          error: { code: "PARTIAL_ZONE_FAILURE" },
        },
        { status: 502 },
      );
    return Response.json({
      operation_id: "ffop_123",
      status: "complete",
      zones: { "example.com": { status: "success" } },
    });
  };
  const logs = [];
  const result = await runAction({
    environment,
    fetchImpl,
    logger: { log: (line) => logs.push(line) },
  });
  assert.equal(result.status, "complete");
  assert.equal(oidc, 3);
  assert.equal(apply, 2);
  assert.deepEqual(
    calls
      .filter((call) => call.url.startsWith("https://dns.02labs.me/"))
      .map((call) => call.url),
    [
      "https://dns.02labs.me/v1/plan",
      "https://dns.02labs.me/v1/apply",
      "https://dns.02labs.me/v1/apply",
    ],
  );
  const output = logs.join("\n");
  assert.match(output, /\[example\.com\] create A example-app\.example\.com/);
  assert.match(output, /\[example\.com\] success/);
  assert.doesNotMatch(
    output,
    /environment-secret-canary|oidc-request-canary|token-[123]|192\.0\.2\.10/,
  );
});

test("SEC-ACT-003 hostile non-JSON response and secret values never enter errors", async () => {
  const canary = "raw-response-secret-canary";
  let thrown;
  try {
    await callFlareForm({
      operation: "plan",
      manifest: "safe",
      token: "jwt-secret-canary",
      fetchImpl: async () =>
        new Response(`<html>${canary}</html>`, {
          status: 500,
          headers: { "content-type": "text/html" },
        }),
    });
  } catch (error) {
    thrown = error;
  }
  assert.equal(thrown.code, "INVALID_RESPONSE");
  assert.doesNotMatch(String(thrown), /raw-response|jwt-secret/);
});
