import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";
import { inspectPublicFiles } from "../../scripts/check-public-release.js";

test("SEC-PUB-001 ordinary public files pass", () => {
  assert.deepEqual(
    inspectPublicFiles(["README.md"], () => Buffer.from("public")),
    [],
  );
});

test("SEC-PUB-001 private paths fail without reading their contents", () => {
  let reads = 0;
  const findings = inspectPublicFiles(
    ["config/zones.yaml", "README.md"],
    () => {
      reads += 1;
      return Buffer.from("public");
    },
  );
  assert.deepEqual(findings, [
    { file: "config/zones.yaml", reason: "private-path" },
  ]);
  assert.equal(reads, 1);
});
