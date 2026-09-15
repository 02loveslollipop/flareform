import assert from "node:assert/strict";
import test from "node:test";
import {
  errorResponse,
  logError,
  redactRecordForAudit,
  unexpectedErrorResponse,
} from "../../src/errors.js";

test("SEC-LOG-001/002 authorization and Cloudflare token canaries never reach responses or logs", async () => {
  const canaries = ["Bearer jwt-secret-canary", "cloudflare-token-canary"];
  for (const canary of canaries) {
    const lines = [];
    logError(
      {
        code: "DATABASE_ERROR",
        correlationId: canary,
        authorization: canary,
        cloudflareToken: canary,
      },
      (line) => lines.push(line),
    );
    const body = await unexpectedErrorResponse(
      new Error(canary),
      canary,
    ).text();
    const direct = await errorResponse(canary, canary).text();
    for (const output of [...lines, body, direct])
      assert.ok(!output.includes(canary));
  }
});

test("SEC-LOG-003/005 raw JWT or hostile upstream body cannot enter the structured log", () => {
  const lines = [];
  logError(
    {
      code: "CLOUDFLARE_API_ERROR",
      correlationId: "eyJhbGciOiJSUzI1NiJ9.payload.signature",
      jwt: "eyJhbGciOiJSUzI1NiJ9.payload.signature",
      upstreamBody: "cloudflare-token-canary",
    },
    (line) => lines.push(line),
  );
  assert.doesNotMatch(lines[0], /eyJhbGci|cloudflare-token-canary/);
});

test("SEC-LOG-004 TXT values and all comments are removed from audit projections", () => {
  const txt = redactRecordForAudit({
    type: "TXT",
    name: "x.example",
    content: "secret-value",
    comment: "secret-comment",
  });
  const a = redactRecordForAudit({
    type: "A",
    name: "x.example",
    content: "192.0.2.1",
    comment: "secret-comment",
  });
  assert.equal(txt.content, "[REDACTED]");
  assert.equal(txt.comment, "[REDACTED]");
  assert.equal(a.comment, "[REDACTED]");
  assert.doesNotMatch(
    JSON.stringify({ txt, a }),
    /secret-value|secret-comment/,
  );
});

test("SEC-LOG-006 public errors omit stack traces, SQL, and internal URLs", async () => {
  const content =
    "SELECT * FROM secret; https://api.cloudflare.com/client/v4/zones/private";
  const body = await unexpectedErrorResponse(new Error(content)).text();
  assert.doesNotMatch(body, /SELECT|cloudflare\.com|stack|private/);
});
