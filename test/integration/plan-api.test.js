import assert from "node:assert/strict";
import test from "node:test";
import { createPlanHandler } from "../../src/api/plan.js";
import { createWorker } from "../../src/http/router.js";
import { DnsRepository } from "../../src/db/repository.js";
import { managedMetadata } from "../../src/dns/state.js";
import { parsePolicyYaml, validatePolicy } from "../../src/policy/config.js";
import { syncPolicy } from "../../src/policy/sync.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";
import { readFile } from "node:fs/promises";

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
const claims = {
  repository_id: repositoryPolicy.github.repository_id,
  repository_owner_id: repositoryPolicy.github.owner_id,
  sub: "repo:example-org/example-app:environment:production",
  event_name: "push",
  ref: "refs/heads/main",
  environment: "production",
  workflow_ref: repositoryPolicy.oidc.workflow_ref,
  runner_environment: "github-hosted",
};
const record = (zone) => ({
  key: `main-${zone.replaceAll(".", "-")}`,
  zone,
  name: `example-app.${zone}`,
  type: "CNAME",
  content: "deployment.example.net",
  proxied: true,
  ttl: 1,
});
const manifest = (records) =>
  JSON.stringify({ version: 1, reconciliation: "keep", records });

test("API-PLAN-001/003/004 and E2E-PLAN-001 mirrored plan persists only opaque artifact", async (t) => {
  const { db, sqlite, close } = sqliteD1();
  t.after(close);
  await syncPolicy(db, policy);
  let reads = 0;
  let mutations = 0;
  const cloudflareFactory = () => ({
    listRecords: async () => {
      reads++;
      return [];
    },
    create: () => {
      mutations++;
    },
    patch: () => {
      mutations++;
    },
    delete: () => {
      mutations++;
    },
  });
  const worker = createWorker({
    verify: async () => claims,
    business: createPlanHandler({ cloudflareFactory }),
  });
  const env = {
    DB: db,
    RATE_LIMITER: { limit: async () => ({ success: true }) },
    CLOUDFLARE_DNS_TOKEN: "local-test-token",
    PLAN_HMAC_KEY: "local-test-hmac-key-never-production-123456789",
  };
  const request = (text) =>
    new Request("https://dns.02labs.me/v1/plan", {
      method: "POST",
      headers: {
        authorization: "Bearer local",
        "content-type": "application/json",
      },
      body: JSON.stringify({ manifest: text }),
    });
  const firstResponse = await worker.fetch(
    request(manifest([record("example.com"), record("example.net")])),
    env,
  );
  assert.equal(firstResponse.status, 200);
  const first = await firstResponse.json();
  assert.equal(first.operation, "plan");
  assert.equal(first.repository_id, claims.repository_id);
  assert.equal(first.changes["example.com"][0].action, "create");
  assert.equal(first.changes["example.net"][0].action, "create");
  assert.match(first.plan_id, /^[0-9a-f-]{36}$/);
  assert.match(first.manifest_digest, /^[0-9a-f]{64}$/);
  assert.equal(reads, 2);
  assert.equal(mutations, 0);
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM plans").get().n, 1);
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM record_claims").get().n,
    0,
  );
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM managed_records").get().n,
    0,
  );
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM oidc_jti").get().n, 0);
  assert.equal(
    sqlite.prepare("SELECT count(*) AS n FROM policy_versions").get().n,
    1,
  );
  const artifacts = new DnsRepository(db);
  const stored = await artifacts.getPlan(first.plan_id);
  assert.equal(stored.manifest_sha256, first.manifest_digest);
  assert.equal(
    await artifacts.getActivePlan(
      first.plan_id,
      stored.repository_id + 1,
      Math.floor(Date.now() / 1000),
    ),
    null,
  );
  assert.equal(
    await artifacts.getActivePlan(
      first.plan_id,
      stored.repository_id,
      stored.expires_at,
    ),
    null,
  );
  const second = await (
    await worker.fetch(
      request(manifest([record("example.net"), record("example.com")])),
      env,
    )
  ).json();
  assert.equal(second.manifest_digest, first.manifest_digest);
  assert.equal(second.dns_state_fingerprint, first.dns_state_fingerprint);
  assert.notEqual(second.plan_id, first.plan_id);
  const applyPreflight = await worker.fetch(
    new Request("https://dns.02labs.me/v1/apply", {
      method: "POST",
      headers: {
        authorization: "Bearer local",
        "content-type": "application/json",
      },
      body: JSON.stringify({ manifest: manifest([record("example.com")]) }),
    }),
    env,
  );
  assert.equal((await applyPreflight.json()).error.code, "INVALID_TOKEN");
  assert.equal(mutations, 0);
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM plans").get().n, 2);
  const invalid = await worker.fetch(
    request(
      manifest([{ ...record("example.com"), name: "other.example.com" }]),
    ),
    env,
  );
  assert.notEqual(invalid.status, 200);
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM plans").get().n, 2);
});

test("OWN-006/E2E-PLAN-001 multiple desired A values share one name and plan separately", async (t) => {
  const { db, close } = sqliteD1();
  t.after(close);
  await syncPolicy(db, policy);
  const a = {
    key: "a-one",
    zone: "example.com",
    name: "example-app.example.com",
    type: "A",
    content: "192.0.2.1",
    proxied: false,
    ttl: 60,
  };
  const worker = createWorker({
    verify: async () => claims,
    business: createPlanHandler({
      cloudflareFactory: () => ({ listRecords: async () => [] }),
    }),
  });
  const response = await worker.fetch(
    new Request("https://dns.02labs.me/v1/plan", {
      method: "POST",
      headers: {
        authorization: "Bearer local",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        manifest: manifest([a, { ...a, key: "a-two", content: "192.0.2.2" }]),
      }),
    }),
    {
      DB: db,
      RATE_LIMITER: { limit: async () => ({ success: true }) },
      CLOUDFLARE_DNS_TOKEN: "local-test-token",
      PLAN_HMAC_KEY: "local-test-hmac-key-never-production-123456789",
    },
  );
  assert.equal(response.status, 200);
  const plan = await response.json();
  assert.deepEqual(
    plan.changes["example.com"].map((entry) => entry.key),
    ["a-one", "a-two"],
  );
  assert.ok(
    plan.changes["example.com"].every((entry) => entry.action === "create"),
  );
});

test("SEC-PLAN-001 unmanaged external record blocks artifact and DNS remains read-only", async (t) => {
  const { db, sqlite, close } = sqliteD1();
  t.after(close);
  await syncPolicy(db, policy);
  const worker = createWorker({
    verify: async () => claims,
    business: createPlanHandler({
      cloudflareFactory: () => ({
        listRecords: async () => [
          {
            id: "c".repeat(32),
            name: "example-app.example.com",
            type: "CNAME",
            content: "existing.example.net",
            ttl: 1,
            proxied: true,
            tags: [],
            comment: "",
          },
        ],
      }),
    }),
  });
  const env = {
    DB: db,
    RATE_LIMITER: { limit: async () => ({ success: true }) },
    CLOUDFLARE_DNS_TOKEN: "local-test-token",
    PLAN_HMAC_KEY: "local-test-hmac-key-never-production-123456789",
  };
  const request = new Request("https://dns.02labs.me/v1/plan", {
    method: "POST",
    headers: {
      authorization: "Bearer local",
      "content-type": "application/json",
    },
    body: JSON.stringify({ manifest: manifest([record("example.com")]) }),
  });
  const response = await worker.fetch(request, env);
  assert.equal((await response.json()).error.code, "RECORD_NOT_OWNED");
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM plans").get().n, 0);
});

test("PRUNE-002/004 and API-PLAN-004 prune lists only owned records; over-limit creates no artifact", async (t) => {
  const { db, sqlite, close } = sqliteD1();
  t.after(close);
  const prunePolicy = validatePolicy(zones, [
    { ...repositoryPolicy, operations: { allow_prune: true } },
  ]);
  await syncPolicy(db, prunePolicy);
  const repositoryId = sqlite.prepare("SELECT id FROM repositories").get().id;
  const zoneId = sqlite
    .prepare("SELECT id FROM zones WHERE name = ?")
    .get("example.com").id;
  const external = [];
  for (let i = 0; i < 11; i++) {
    const name = `old${i}.example-app.example.com`;
    const clientKey = `old-${i}`;
    const id = i.toString(16).padStart(32, "0");
    const claimId = sqlite
      .prepare(
        "INSERT INTO record_claims(repository_id,zone_id,name,type,state,created_at,updated_at) VALUES (?,?,?,?,?,?,?)",
      )
      .run(
        repositoryId,
        zoneId,
        name,
        "A",
        "active",
        "now",
        "now",
      ).lastInsertRowid;
    sqlite
      .prepare(
        "INSERT INTO managed_records(repository_id,record_claim_id,zone_id,client_key,cloudflare_record_id,content,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?)",
      )
      .run(
        repositoryId,
        claimId,
        zoneId,
        clientKey,
        id,
        "192.0.2.2",
        "now",
        "now",
      );
    external.push({
      id,
      name,
      type: "A",
      content: "192.0.2.2",
      ttl: 60,
      proxied: false,
      ...managedMetadata(claims.repository_id, clientKey),
    });
  }
  const worker = createWorker({
    verify: async () => claims,
    business: createPlanHandler({
      cloudflareFactory: () => ({ listRecords: async () => external }),
    }),
  });
  const env = {
    DB: db,
    RATE_LIMITER: { limit: async () => ({ success: true }) },
    CLOUDFLARE_DNS_TOKEN: "local-test-token",
    PLAN_HMAC_KEY: "local-test-hmac-key-never-production-123456789",
  };
  const payload = JSON.stringify({
    version: 1,
    reconciliation: "prune",
    prune_zones: ["example.com"],
    records: [record("example.com")],
  });
  const request = () =>
    new Request("https://dns.02labs.me/v1/plan", {
      method: "POST",
      headers: {
        authorization: "Bearer local",
        "content-type": "application/json",
      },
      body: JSON.stringify({ manifest: payload }),
    });
  const over = await worker.fetch(request(), env);
  assert.equal((await over.json()).error.code, "PRUNE_LIMIT_EXCEEDED");
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM plans").get().n, 0);
  external.pop();
  sqlite
    .prepare("DELETE FROM managed_records WHERE client_key = ?")
    .run("old-10");
  sqlite
    .prepare("DELETE FROM record_claims WHERE name = ?")
    .run("old10.example-app.example.com");
  const allowed = await (await worker.fetch(request(), env)).json();
  assert.equal(
    allowed.changes["example.com"].filter(
      (change) => change.action === "delete",
    ).length,
    10,
  );
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM plans").get().n, 1);
});

test("MAN-SRV-001/API-PLAN-001 structural SRV owner passes authorization and planning", async (t) => {
  const { db, close } = sqliteD1();
  t.after(close);
  await syncPolicy(db, policy);
  const worker = createWorker({
    verify: async () => claims,
    business: createPlanHandler({
      cloudflareFactory: () => ({ listRecords: async () => [] }),
    }),
  });
  const srv = {
    key: "grpc",
    zone: "example.com",
    name: "_grpc._tcp.example-app.example.com",
    type: "SRV",
    priority: 10,
    weight: 100,
    port: 443,
    target: "api.example-app.example.com",
    ttl: 60,
  };
  const env = {
    DB: db,
    RATE_LIMITER: { limit: async () => ({ success: true }) },
    CLOUDFLARE_DNS_TOKEN: "local-test-token",
    PLAN_HMAC_KEY: "local-test-hmac-key-never-production-123456789",
  };
  const response = await worker.fetch(
    new Request("https://dns.02labs.me/v1/plan", {
      method: "POST",
      headers: {
        authorization: "Bearer local",
        "content-type": "application/json",
      },
      body: JSON.stringify({ manifest: manifest([srv]) }),
    }),
    env,
  );
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.changes["example.com"][0].action, "create");
  assert.deepEqual(body.changes["example.com"][0].to, {
    priority: 10,
    weight: 100,
    port: 443,
    target: "api.example-app.example.com",
  });
});

test("M3 exit: A, AAAA, and policy-authorized TXT plan together with TXT redacted", async (t) => {
  const { db, close } = sqliteD1();
  t.after(close);
  const trusted = structuredClone(repositoryPolicy);
  trusted.grants[0].record_types.push("TXT");
  await syncPolicy(db, validatePolicy(zones, [trusted]));
  const worker = createWorker({
    verify: async () => claims,
    business: createPlanHandler({
      cloudflareFactory: () => ({ listRecords: async () => [] }),
    }),
  });
  const env = {
    DB: db,
    RATE_LIMITER: { limit: async () => ({ success: true }) },
    CLOUDFLARE_DNS_TOKEN: "local-test-token",
    PLAN_HMAC_KEY: "local-test-hmac-key-never-production-123456789",
  };
  const records = [
    {
      key: "address-v4",
      zone: "example.com",
      name: "example-app.example.com",
      type: "A",
      content: "192.0.2.1",
      ttl: 60,
      proxied: false,
    },
    {
      key: "address-v6",
      zone: "example.com",
      name: "example-app.example.com",
      type: "AAAA",
      content: "2001:db8::1",
      ttl: 60,
      proxied: false,
    },
    {
      key: "verification",
      zone: "example.com",
      name: "verification.example-app.example.com",
      type: "TXT",
      content: "secret-verification",
      ttl: 60,
    },
  ];
  const response = await worker.fetch(
    new Request("https://dns.02labs.me/v1/plan", {
      method: "POST",
      headers: {
        authorization: "Bearer local",
        "content-type": "application/json",
      },
      body: JSON.stringify({ manifest: manifest(records) }),
    }),
    env,
  );
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.deepEqual(
    result.changes["example.com"].map((change) => change.type).sort(),
    ["A", "AAAA", "TXT"],
  );
  assert.equal(
    result.changes["example.com"].find((change) => change.type === "TXT").to,
    "[REDACTED]",
  );
  assert.doesNotMatch(JSON.stringify(result), /secret-verification/);
});

test("M3 exit: external CNAME and NS conflicts deny A planning before artifact write", async (t) => {
  const { db, sqlite, close } = sqliteD1();
  t.after(close);
  await syncPolicy(db, policy);
  let externalType = "CNAME";
  const worker = createWorker({
    verify: async () => claims,
    business: createPlanHandler({
      cloudflareFactory: () => ({
        listRecords: async () => [
          {
            id: "c".repeat(32),
            name: "example-app.example.com",
            type: externalType,
            content: "external.example.net",
            ttl: 60,
            tags: [],
            comment: "",
          },
        ],
      }),
    }),
  });
  const env = {
    DB: db,
    RATE_LIMITER: { limit: async () => ({ success: true }) },
    CLOUDFLARE_DNS_TOKEN: "local-test-token",
    PLAN_HMAC_KEY: "local-test-hmac-key-never-production-123456789",
  };
  for (const type of ["CNAME", "NS"]) {
    externalType = type;
    const request = new Request("https://dns.02labs.me/v1/plan", {
      method: "POST",
      headers: {
        authorization: "Bearer local",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        manifest: manifest([
          {
            key: "address-v4",
            zone: "example.com",
            name: "example-app.example.com",
            type: "A",
            content: "192.0.2.1",
            ttl: 60,
          },
        ]),
      }),
    });
    const response = await worker.fetch(request, env);
    assert.equal((await response.json()).error.code, "DNS_CONFLICT");
  }
  assert.equal(sqlite.prepare("SELECT count(*) AS n FROM plans").get().n, 0);
});
