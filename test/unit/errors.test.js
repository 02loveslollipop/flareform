import assert from "node:assert/strict";
import test from "node:test";
import {
  ERROR_DEFINITIONS,
  FlareFormError,
  errorResponse,
  logError,
  unexpectedErrorResponse,
} from "../../src/errors.js";

const documentedCodes = [
  "INVALID_TOKEN",
  "TOKEN_EXPIRED",
  "INVALID_ISSUER",
  "INVALID_AUDIENCE",
  "INVALID_SUBJECT",
  "INVALID_RUNNER_ENVIRONMENT",
  "OIDC_TOKEN_REPLAYED",
  "UNKNOWN_REPOSITORY",
  "REPOSITORY_DISABLED",
  "INVALID_OWNER",
  "INVALID_WORKFLOW",
  "INVALID_REF",
  "INVALID_EVENT",
  "INVALID_ENVIRONMENT",
  "UNKNOWN_ZONE",
  "ZONE_DISABLED",
  "HOSTNAME_NOT_AUTHORIZED",
  "RECORD_TYPE_NOT_AUTHORIZED",
  "INVALID_RECORD",
  "RECORD_NOT_OWNED",
  "RECORD_OWNED_BY_OTHER_REPOSITORY",
  "DNS_CONFLICT",
  "OPERATION_IN_PROGRESS",
  "STATE_INDETERMINATE",
  "PRUNE_NOT_AUTHORIZED",
  "PRUNE_LIMIT_EXCEEDED",
  "PLAN_PRECONDITION_FAILED",
  "CLOUDFLARE_API_ERROR",
  "PARTIAL_ZONE_FAILURE",
  "DATABASE_ERROR",
];

test("UNIT-ERR-001 documented codes use a stable JSON envelope and HTTP status", async () => {
  for (const code of documentedCodes) {
    const response = errorResponse(code);
    const body = await response.json();
    assert.equal(response.status, ERROR_DEFINITIONS[code][0]);
    assert.equal(body.error.code, code);
    assert.equal(body.error.message, ERROR_DEFINITIONS[code][1]);
    assert.match(body.error.correlation_id, /^[0-9a-f-]{36}$/);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.deepEqual(Object.keys(body), ["error"]);
  }
});

test("UNIT-ERR-002 unknown exceptions become generic errors", async () => {
  const secret = "secret-untrusted-exception-text";
  const response = unexpectedErrorResponse(new Error(secret), secret);
  const body = await response.text();
  assert.equal(response.status, 500);
  assert.match(body, /INTERNAL_ERROR/);
  assert.doesNotMatch(body, /secret-untrusted-exception-text/);
  assert.match(JSON.parse(body).error.correlation_id, /^[0-9a-f-]{36}$/);
});

test("UNIT-ERR-003 clients can branch on code without parsing messages", async () => {
  assert.equal(
    (await errorResponse("INVALID_RECORD").json()).error.code,
    "INVALID_RECORD",
  );
  assert.equal(
    (await errorResponse("INVALID_TOKEN").json()).error.code,
    "INVALID_TOKEN",
  );
  assert.equal(
    (await unexpectedErrorResponse(new FlareFormError("DNS_CONFLICT")).json())
      .error.code,
    "DNS_CONFLICT",
  );
  assert.throws(() => new FlareFormError("NOT_A_CODE"), TypeError);
});

test("UNIT-ERR-004 unknown caller codes cannot be reflected", async () => {
  const response = errorResponse("JWT.secret.payload");
  assert.equal((await response.json()).error.code, "INTERNAL_ERROR");
});

test("UNIT-ERR-005 log shape contains only allowlisted fields", () => {
  const entries = [];
  logError(
    {
      code: "INVALID_TOKEN",
      correlationId: "Bearer secret",
      token: "cf-secret",
      upstreamBody: "sensitive",
    },
    (entry) => entries.push(entry),
  );
  const parsed = JSON.parse(entries[0]);
  assert.deepEqual(Object.keys(parsed), [
    "event",
    "code",
    "correlation_id",
    "timestamp",
  ]);
  assert.equal(parsed.code, "INVALID_TOKEN");
  assert.doesNotMatch(entries[0], /secret|sensitive/);
});
