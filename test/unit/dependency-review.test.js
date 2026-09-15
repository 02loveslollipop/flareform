import assert from "node:assert/strict";
import test from "node:test";
import {
  inspectLockfile,
  reviewDependencies,
} from "../../scripts/review-dependencies.js";

test("SEC-SUP-002 committed dependencies use trusted immutable npm artifacts", async () => {
  assert.deepEqual(await reviewDependencies(), []);
});

test("SEC-SUP-002 alternate origins, weak integrity, and forbidden licenses fail", () => {
  const findings = inspectLockfile(
    {
      lockfileVersion: 3,
      packages: {
        "": {},
        "node_modules/bad": {
          resolved: "https://example.invalid/bad.tgz?token=secret",
          integrity: "sha1-weak",
          license: "AGPL-3.0-only",
        },
      },
    },
    "fixture-lock.json",
  );
  assert.deepEqual(
    findings.map((finding) => finding.reason),
    ["untrusted-resolution", "missing-sha512-integrity", "forbidden-license"],
  );
  assert.doesNotMatch(JSON.stringify(findings), /token=secret/);
});
