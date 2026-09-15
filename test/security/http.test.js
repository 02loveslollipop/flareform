import assert from "node:assert/strict";
import test from "node:test";
import { createWorker } from "../../src/http/router.js";

test("SEC-INJ-002 M2 exit: hostile token, body and header values never reach logs or responses", async () => {
  const secret = "secret-CF-and-JWT-123\nforged-log-entry";
  const events = [];
  const original = console.error;
  console.error = (value) => events.push(value);
  try {
    const worker = createWorker({
      verify: async () => {
        throw new Error(secret);
      },
      business: async () => {
        throw new Error("must not reach business");
      },
    });
    const response = await worker.fetch(
      new Request("https://dns.02labs.me/v1/apply", {
        method: "POST",
        headers: {
          authorization: "Bearer secret-CF-and-JWT-123",
          "content-type": "application/json",
        },
        body: JSON.stringify({ manifest: secret }),
      }),
      {},
    );
    assert.equal(response.status, 500);
    assert.doesNotMatch(
      JSON.stringify(await response.json()),
      /secret-CF|forged-log-entry/,
    );
    assert.doesNotMatch(events.join("\n"), /secret-CF|forged-log-entry/);
    for (const event of events)
      assert.deepEqual(Object.keys(JSON.parse(event)).sort(), [
        "code",
        "correlation_id",
        "event",
        "timestamp",
      ]);
  } finally {
    console.error = original;
  }
});
