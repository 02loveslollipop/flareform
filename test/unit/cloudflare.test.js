import assert from "node:assert/strict";
import test from "node:test";
import { createCloudflareClient } from "../../src/dns/cloudflare.js";
import { managedMetadata } from "../../src/dns/state.js";

const zone = {
  name: "example.com",
  cloudflare_zone_id: "a".repeat(32),
  enabled: true,
};
const id1 = "b".repeat(32);
const id2 = "c".repeat(32);
const metadata = {
  tags: ["managed-by:flareform", "repository-id:123", "client-key:main"],
  comment: "Managed by FlareForm for GitHub repository 123",
};
const record = {
  id: id1,
  name: "example-app.example.com",
  type: "A",
  content: "192.0.2.1",
  ttl: 60,
  ...metadata,
};
const desired = {
  name: record.name,
  type: "A",
  content: record.content,
  ttl: 60,
  proxied: false,
  ...metadata,
};
const ok = (result, result_info) =>
  Response.json({
    success: true,
    result,
    ...(result_info ? { result_info } : {}),
  });

test("CF-UNIT-001 full pagination and duplicate API state fail closed", async () => {
  const calls = [];
  const client = createCloudflareClient({
    token: "test-secret",
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      const page = Number(new URL(url).searchParams.get("page"));
      return ok(page === 1 ? [record] : [{ ...record, id: id2 }], {
        page,
        total_pages: 2,
      });
    },
  });
  assert.equal((await client.listRecords(zone)).length, 2);
  assert.equal(calls.length, 2);
  assert.ok(
    calls.every((call) =>
      call.url.startsWith("https://api.cloudflare.com/client/v4/zones/"),
    ),
  );
  assert.ok(calls.every((call) => call.options.redirect === "manual"));
  const duplicate = createCloudflareClient({
    token: "token",
    fetchImpl: async (url) =>
      ok([record], {
        page: Number(new URL(url).searchParams.get("page")),
        total_pages: 2,
      }),
  });
  await assert.rejects(duplicate.listRecords(zone));
  const empty = createCloudflareClient({
    token: "token",
    fetchImpl: async () => ok([], { page: 1, total_pages: 0, total_count: 0 }),
  });
  assert.deepEqual(await empty.listRecords(zone), []);
  const shifted = createCloudflareClient({
    token: "token",
    fetchImpl: async (url) => {
      const page = Number(new URL(url).searchParams.get("page"));
      return ok([page === 1 ? record : { ...record, id: id2 }], {
        page,
        total_pages: 2,
        total_count: page === 1 ? 2 : 3,
      });
    },
  });
  await assert.rejects(shifted.listRecords(zone));
});

test("CF-UNIT-002/003/004 fixed paths and allowlisted mutation bodies", async () => {
  const calls = [];
  const client = createCloudflareClient({
    token: "test-secret",
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return ok(
        url.endsWith("/batch")
          ? { deletes: [{ id: id1 }], patches: [], posts: [record] }
          : options.method === "DELETE"
            ? { id: id1 }
            : record,
      );
    },
  });
  await client.create(zone, desired);
  await client.patch(zone, id1, desired);
  await client.delete(zone, id1);
  await client.batch(zone, { deletes: [id1], posts: [desired] });
  assert.deepEqual(
    calls.map((call) => call.options.method),
    ["POST", "PATCH", "DELETE", "POST"],
  );
  assert.ok(
    calls.every((call) =>
      call.url.startsWith(
        `https://api.cloudflare.com/client/v4/zones/${zone.cloudflare_zone_id}/dns_records`,
      ),
    ),
  );
  assert.deepEqual(Object.keys(JSON.parse(calls[0].options.body)).sort(), [
    "comment",
    "content",
    "name",
    "proxied",
    "tags",
    "ttl",
    "type",
  ]);
  assert.deepEqual(Object.keys(JSON.parse(calls[3].options.body)).sort(), [
    "deletes",
    "patches",
    "posts",
  ]);
});

test("CF-UNIT-005/006/007 429, malformed response and timeout fail safely", async () => {
  let attempts = 0;
  const retry = createCloudflareClient({
    token: "token",
    sleep: async () => {},
    fetchImpl: async (url) => {
      attempts++;
      return attempts < 3
        ? Response.json({ success: false, errors: [] }, { status: 429 })
        : ok([], {
            page: Number(new URL(url).searchParams.get("page")),
            total_pages: 1,
          });
    },
  });
  assert.deepEqual(await retry.listRecords(zone), []);
  assert.equal(attempts, 3);
  const malformed = createCloudflareClient({
    token: "token",
    fetchImpl: async () =>
      Response.json({ success: true, result: "not-a-list" }),
  });
  await assert.rejects(malformed.listRecords(zone), {
    code: "CLOUDFLARE_API_ERROR",
  });
  const timeout = createCloudflareClient({
    token: "token",
    timeoutMs: 10,
    fetchImpl: () => new Promise(() => {}),
  });
  await assert.rejects(timeout.listRecords(zone), {
    code: "CLOUDFLARE_API_ERROR",
  });
});

test("SEC-SSRF-001/002/003 malicious IDs, redirects and content cannot move bearer token", async () => {
  const destinations = [];
  const client = createCloudflareClient({
    token: "test-secret",
    fetchImpl: async (url) => {
      destinations.push(url);
      return Response.redirect("https://evil.test/steal");
    },
  });
  await assert.rejects(client.listRecords(zone));
  await assert.rejects(
    client.create({ ...zone, cloudflare_zone_id: "../evil" }, desired),
  );
  await assert.rejects(client.delete(zone, "../evil"));
  await assert.rejects(
    client.create(zone, { ...desired, content: "https://evil.test/steal" }),
  );
  assert.ok(
    destinations.every((url) =>
      url.startsWith("https://api.cloudflare.com/client/v4/"),
    ),
  );
});

test("CF-INT-001/002 partial batch and unsafe mutation retries fail closed", async () => {
  const partial = createCloudflareClient({
    token: "secret",
    fetchImpl: async () => ok({ deletes: [], patches: [], posts: [] }),
  });
  await assert.rejects(partial.batch(zone, { posts: [desired] }), {
    code: "CLOUDFLARE_API_ERROR",
  });
  let attempts = 0;
  const failing = createCloudflareClient({
    token: "secret",
    fetchImpl: async () => {
      attempts++;
      return Response.json(
        { success: false, errors: [{ message: "secret" }] },
        { status: 503 },
      );
    },
  });
  await assert.rejects(failing.create(zone, desired), {
    code: "CLOUDFLARE_API_ERROR",
  });
  assert.equal(attempts, 1);
});

test("OWN-006/007 mutation payload carries exact metadata and altered provider echo fails", async () => {
  const expected = managedMetadata("123", "main");
  let body;
  const client = createCloudflareClient({
    token: "secret",
    fetchImpl: async (_url, options) => {
      body = JSON.parse(options.body);
      return ok({
        ...record,
        tags: ["managed-by:flareform"],
        comment: expected.comment,
      });
    },
  });
  await assert.rejects(client.create(zone, { ...desired, ...expected }), {
    code: "CLOUDFLARE_API_ERROR",
  });
  assert.deepEqual(body.tags, expected.tags);
  assert.equal(body.comment, expected.comment);
});

test("CF-UNIT-008 SRV confirmation accepts provider data key reordering only", async () => {
  const srv = {
    name: "_grpc._tcp.example-app.example.com",
    type: "SRV",
    ttl: 60,
    data: {
      priority: 10,
      weight: 1,
      port: 443,
      target: "api.example-app.example.com",
    },
    ...managedMetadata("123", "grpc"),
  };
  const client = createCloudflareClient({
    token: "secret",
    fetchImpl: async () =>
      ok({
        ...srv,
        id: id1,
        data: Object.fromEntries(Object.entries(srv.data).reverse()),
      }),
  });
  assert.equal((await client.create(zone, srv)).id, id1);
});
