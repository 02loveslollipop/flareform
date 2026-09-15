import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { createPlanHandler } from "../../src/api/plan.js";
import { createWorker } from "../../src/http/router.js";
import { parsePolicyYaml, validatePolicy } from "../../src/policy/config.js";
import { syncPolicy } from "../../src/policy/sync.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";

const zones = parsePolicyYaml(
  await readFile(
    new URL("../../config/examples/zones.yaml", import.meta.url),
    "utf8",
  ),
);
const repositoryPolicy = parsePolicyYaml(
  await readFile(
    new URL(
      "../../config/examples/repositories/example-app.yaml",
      import.meta.url,
    ),
    "utf8",
  ),
);
const policy = validatePolicy(zones, [repositoryPolicy]);
const names = ["example.com", "example.net"];
const manifest = JSON.stringify({
  version: 1,
  reconciliation: "keep",
  records: names.map((zone) => ({
    key: `main-${zone.replaceAll(".", "-")}`,
    zone,
    name: `example-app.${zone}`,
    type: "CNAME",
    content: "deployment.example.net",
    proxied: true,
    ttl: 1,
  })),
});
const identity = (jti = "first-jti") => ({
  repository_id: repositoryPolicy.github.repository_id,
  repository_owner_id: repositoryPolicy.github.owner_id,
  sub: "repo:example-org/example-app:environment:production",
  event_name: "push",
  ref: "refs/heads/main",
  environment: "production",
  workflow_ref: repositoryPolicy.oidc.workflow_ref,
  runner_environment: "github-hosted",
  run_id: "500",
  run_attempt: "1",
  actor_id: "700",
  jti,
  exp: Math.floor(Date.now() / 1000) + 300,
});
const request = () =>
  new Request("https://dns.02labs.me/v1/apply", {
    method: "POST",
    headers: {
      authorization: "Bearer local",
      "content-type": "application/json",
    },
    body: JSON.stringify({ manifest }),
  });
async function fixture(t, behavior = {}) {
  const location = sqliteD1();
  t.after(location.close);
  await syncPolicy(location.db, policy);
  const records = new Map(names.map((name) => [name, []]));
  const counts = {
    reads: Object.fromEntries(names.map((name) => [name, 0])),
    creates: Object.fromEntries(names.map((name) => [name, 0])),
  };
  const cloudflare = {
    async listRecords(zone) {
      counts.reads[zone.name]++;
      if (behavior.failRead?.(zone.name, counts.reads[zone.name]))
        throw Error("provider read failed");
      return records.get(zone.name);
    },
    async create(zone, payload) {
      counts.creates[zone.name]++;
      const id = (
        counts.creates[zone.name] + (zone.name === names[0] ? 10 : 20)
      )
        .toString(16)
        .padStart(32, "0");
      if (behavior.failCreate?.(zone.name, counts.creates[zone.name]))
        throw Error("ambiguous provider response");
      const entry = { ...payload, id };
      records.get(zone.name).push(entry);
      return entry;
    },
  };
  let claims = identity();
  const worker = createWorker({
    verify: async () => claims,
    business: createPlanHandler({ cloudflareFactory: () => cloudflare }),
  });
  const env = {
    DB: location.db,
    RATE_LIMITER: { limit: async () => ({ success: true }) },
    CLOUDFLARE_DNS_TOKEN: "local-test-token",
    PLAN_HMAC_KEY: "local-test-hmac-key-never-production-123456789",
  };
  return {
    ...location,
    worker,
    env,
    records,
    counts,
    setClaims: (value) => {
      claims = value;
    },
  };
}

test("E2E-MIRROR-001 mirrored apply confirms both zones and fresh-JTI retry is idempotent", async (t) => {
  const f = await fixture(t);
  const firstResponse = await f.worker.fetch(request(), f.env);
  assert.equal(firstResponse.status, 200);
  const first = await firstResponse.json();
  assert.equal(first.status, "complete");
  assert.match(first.operation_id, /^ffop_[0-9a-f]{32}$/);
  assert.equal(first.zones[names[0]].status, "success");
  assert.equal(first.zones[names[1]].status, "success");
  assert.deepEqual(Object.values(f.counts.creates), [1, 1]);
  assert.equal(
    f.sqlite.prepare("SELECT count(*) AS n FROM managed_records").get().n,
    2,
  );
  assert.deepEqual(
    {
      ...f.sqlite
        .prepare(
          "SELECT github_run_id, github_run_attempt, github_actor_id, workflow_ref FROM audit_log WHERE action = 'intent:create' ORDER BY id LIMIT 1",
        )
        .get(),
    },
    {
      github_run_id: "500",
      github_run_attempt: "1",
      github_actor_id: "700",
      workflow_ref: repositoryPolicy.oidc.workflow_ref,
    },
  );
  f.setClaims(identity("retry-jti"));
  const retry = await f.worker.fetch(request(), f.env);
  assert.equal(retry.status, 200);
  assert.equal((await retry.json()).operation_id, first.operation_id);
  assert.deepEqual(Object.values(f.counts.creates), [1, 1]);
  const replay = await f.worker.fetch(request(), f.env);
  assert.equal((await replay.json()).error.code, "OIDC_TOKEN_REPLAYED");
});

test("MZ-001/FAULT-MZ-001 failed pre-send UK read retries without repeating confirmed .me mutation", async (t) => {
  const f = await fixture(t, {
    failRead: (name, count) => name === names[1] && count === 2,
  });
  const first = await f.worker.fetch(request(), f.env);
  assert.equal(first.status, 502);
  const partial = await first.json();
  assert.equal(partial.error.code, "PARTIAL_ZONE_FAILURE");
  assert.equal(partial.zones[names[0]].status, "success");
  assert.equal(partial.zones[names[1]].status, "failed");
  assert.deepEqual(Object.values(f.counts.creates), [1, 0]);
  f.setClaims(identity("retry-jti"));
  const retry = await f.worker.fetch(request(), f.env);
  assert.equal(retry.status, 200);
  const completed = await retry.json();
  assert.equal(completed.operation_id, partial.operation_id);
  assert.deepEqual(Object.values(f.counts.creates), [1, 1]);
  assert.equal(completed.zones[names[1]].status, "success");
});

test("FAULT-MZ-002 uncertain UK create freezes its zone and never resends", async (t) => {
  const f = await fixture(t, { failCreate: (name) => name === names[1] });
  const first = await f.worker.fetch(request(), f.env);
  assert.equal(first.status, 502);
  const partial = await first.json();
  assert.equal(partial.zones[names[0]].status, "success");
  assert.equal(partial.zones[names[1]].status, "indeterminate");
  f.setClaims(identity("retry-jti"));
  const retry = await f.worker.fetch(request(), f.env);
  assert.equal(retry.status, 502);
  assert.equal((await retry.json()).operation_id, partial.operation_id);
  assert.deepEqual(Object.values(f.counts.creates), [1, 1]);
});
