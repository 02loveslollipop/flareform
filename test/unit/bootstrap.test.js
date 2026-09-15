import assert from "node:assert/strict";
import test from "node:test";
import { validateBootstrap } from "../../scripts/validate-bootstrap.js";

const valid = {
  accountId: "0123456789abcdef0123456789abcdef",
  databaseId: "12345678-1234-4123-8123-123456789abc",
  zone02labsId: "1234567890abcdef1234567890abcdef",
  zoneUkId: "abcdef1234567890abcdef1234567890",
  repositoryId: "123456789",
  ownerId: "987654321",
  runtimeDnsToken: "runtime-dns-token-test-only",
  deploymentToken: "worker-deploy-token-test-only",
};

test("OPS-BOOT-001 bootstrap accepts distinct production-shaped inputs without returning secrets", () => {
  const result = validateBootstrap(valid);
  assert.deepEqual(result, {
    valid: true,
    zones: ["example.com", "example.net"],
    credentials_distinct: true,
  });
  assert.doesNotMatch(JSON.stringify(result), /runtime-dns|worker-deploy/);
});

test("OPS-BOOT-001 placeholders, missing IDs, repeated zones, and credential reuse fail", () => {
  for (const change of [
    { accountId: "a".repeat(32) },
    { databaseId: "example-database-id" },
    { repositoryId: "0" },
    { ownerId: "owner-placeholder" },
    { zoneUkId: valid.zone02labsId },
    { deploymentToken: valid.runtimeDnsToken },
  ])
    assert.throws(() => validateBootstrap({ ...valid, ...change }));
});
