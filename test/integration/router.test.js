import assert from "node:assert/strict";
import test from "node:test";
import { createWorker, MAX_BODY_BYTES } from "../../src/http/router.js";

const claims = {
  repository_id: "123",
  repository_owner_id: "456",
  sub: "repo:owner/repo:environment:production",
  event_name: "push",
  ref: "refs/heads/main",
  environment: "production",
  workflow_ref: "owner/repo/.github/workflows/deploy.yml@refs/heads/main",
  runner_environment: "github-hosted",
};
const repository = {
  github_repository_id: "123",
  github_owner_id: "456",
  enabled: 1,
  expected_workflow_ref: claims.workflow_ref,
  expected_job_workflow_ref: null,
  allowed_ref: claims.ref,
  allowed_environment: claims.environment,
  allowed_event: claims.event_name,
  allowed_runner_environment: "github-hosted",
};
function setup() {
  let reached = 0;
  const actual = createWorker({
    verify: async (token) => {
      if (token !== "valid") throw Error("invalid token secret");
      return claims;
    },
    lookupRepository: async () => repository,
    business: async () => {
      reached++;
      return Response.json({ accepted: true });
    },
  });
  const worker = {
    fetch: (request, env = {}) =>
      actual.fetch(request, {
        RATE_LIMITER: { limit: async () => ({ success: true }) },
        ...env,
      }),
  };
  const request = (path = "/v1/plan", options = {}) =>
    new Request(`https://dns.02labs.me${path}`, {
      method: "POST",
      headers: {
        authorization: "Bearer valid",
        "content-type": "application/json",
        ...options.headers,
      },
      body: options.body ?? JSON.stringify({ manifest: "version: 1" }),
    });
  return { worker, request, reached: () => reached };
}

test("API-BOUND-001/002/003/007/009 fixed routes, methods, content type and minimal health", async () => {
  const f = setup();
  const health = await f.worker.fetch(
    new Request("https://dns.02labs.me/healthz"),
    {},
  );
  assert.deepEqual(await health.json(), { status: "ok" });
  assert.equal(health.headers.get("access-control-allow-origin"), null);
  assert.equal((await f.worker.fetch(f.request("/admin"), {})).status, 400);
  assert.equal(
    (await f.worker.fetch(new Request("https://dns.02labs.me/v1/plan"), {}))
      .status,
    405,
  );
  assert.equal(
    (
      await f.worker.fetch(
        f.request("/v1/apply", { headers: { "content-type": "text/plain" } }),
        {},
      )
    ).status,
    400,
  );
  assert.equal(f.reached(), 0);
  assert.equal((await f.worker.fetch(f.request(), {})).status, 200);
  assert.equal(f.reached(), 1);
});

test("API-BOUND-004/005 and SEC-HTTP-002 bounded JSON, duplicate keys and prohibited IDs", async () => {
  const f = setup();
  const badBodies = [
    "{",
    '{"manifest":"a","manifest":"b"}',
    ...["zone_id", "record_id", "endpoint", "api_url", "redirect"].map(
      (field) => JSON.stringify({ manifest: "x", [field]: "arbitrary" }),
    ),
    JSON.stringify({ manifest: "x".repeat(MAX_BODY_BYTES) }),
    JSON.stringify({ manifest: Array.from({ length: 2000 }, () => "x") }),
  ];
  for (const body of badBodies) {
    const response = await f.worker.fetch(f.request("/v1/plan", { body }), {});
    assert.notEqual(response.status, 200);
  }
  assert.equal(f.reached(), 0);
});

test("SEC-HTTP-001 alternate host, method override, forwarded host and encoded paths fail", async () => {
  const f = setup();
  for (const path of [
    "/v1/%70lan",
    "/v1/apply%2f",
    "/v1/../v1/apply?x=1",
    "/v1/apply?x=1",
  ])
    assert.notEqual((await f.worker.fetch(f.request(path), {})).status, 200);
  for (const header of [
    "host",
    "x-forwarded-host",
    "x-http-method-override",
    "x-original-url",
  ])
    assert.notEqual(
      (
        await f.worker.fetch(
          f.request("/v1/apply", { headers: { [header]: "evil.test" } }),
          {},
        )
      ).status,
      200,
    );
  const other = new Request("https://evil.test/v1/apply", {
    method: "POST",
    headers: {
      authorization: "Bearer valid",
      "content-type": "application/json",
    },
    body: '{"manifest":"x"}',
  });
  assert.notEqual((await f.worker.fetch(other, {})).status, 200);
  assert.equal(f.reached(), 0);
});

test("API-BOUND-008 rate limiting follows authentication and never authorizes", async () => {
  const f = setup();
  const limited = { RATE_LIMITER: { limit: async () => ({ success: false }) } };
  const response = await f.worker.fetch(f.request(), limited);
  assert.equal((await response.json()).error.code, "RATE_LIMITED");
  assert.equal(f.reached(), 0);
  const bad = await f.worker.fetch(
    f.request("/v1/plan", { headers: { authorization: "Bearer invalid" } }),
    limited,
  );
  assert.equal((await bad.json()).error.code, "INTERNAL_ERROR");
  assert.equal(f.reached(), 0);
});

test("API-BOUND-006 bounded authentication and body timeouts never reach business", async () => {
  let reached = false;
  const worker = createWorker({
    verify: () => new Promise(() => {}),
    business: async () => {
      reached = true;
      return Response.json({ ok: true });
    },
    requestTimeoutMs: 20,
  });
  const response = await worker.fetch(
    new Request("https://dns.02labs.me/v1/plan", {
      method: "POST",
      headers: {
        authorization: "Bearer valid",
        "content-type": "application/json",
      },
      body: '{"manifest":"x"}',
    }),
    {},
  );
  assert.equal((await response.json()).error.code, "REQUEST_TIMEOUT");
  assert.equal(reached, false);
});

test("FUZZ-API-001 malformed structures never reach the business handler", async () => {
  const f = setup();
  for (let i = 0; i < 100; i++) {
    const body =
      i % 2
        ? `{${'"x":'.repeat(i + 1)}`
        : JSON.stringify({ manifest: "x", [`unknown_${i}`]: i });
    const response = await f.worker.fetch(f.request("/v1/plan", { body }), {});
    assert.notEqual(response.status, 200);
  }
  assert.equal(f.reached(), 0);
});
