import assert from "node:assert/strict";
import test from "node:test";
import worker from "../../src/index.js";

test("foundation Worker exposes health and fails closed for unauthenticated mutation routes", async () => {
  const health = await worker.fetch(
    new Request("https://dns.02labs.me/healthz"),
    {},
  );
  assert.equal(health.status, 200);
  assert.deepEqual(await health.json(), { status: "ok" });
  for (const path of ["/v1/plan", "/v1/apply", "/admin", "/anything"]) {
    const response = await worker.fetch(
      new Request(`https://dns.02labs.me${path}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      }),
      {},
    );
    assert.ok([400, 401].includes(response.status));
  }
});
