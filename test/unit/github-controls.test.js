import assert from "node:assert/strict";
import test from "node:test";
import { evaluateControls } from "../../scripts/audit-github-controls.js";

const branch = {
  required_status_checks: {
    strict: true,
    contexts: ["check", "dependency-review"],
  },
  required_pull_request_reviews: { dismiss_stale_reviews: true },
  enforce_admins: { enabled: true },
  required_conversation_resolution: { enabled: true },
  allow_force_pushes: { enabled: false },
  allow_deletions: { enabled: false },
};
const environments = ["production", "dns-administration"].map((name) => ({
  name,
  deployment_branch_policy: { custom_branch_policies: true },
  branchPolicies: [{ name: "main", type: "branch" }],
}));

test("SEC-WF-005 desired main and environment controls pass audit", () => {
  assert.deepEqual(evaluateControls({ branch, environments }), {
    valid: true,
    findings: [],
  });
});

test("SEC-WF-005 weakened checks, force push, deletion, or environments are visible", () => {
  const weakened = structuredClone(branch);
  weakened.required_status_checks.contexts = ["check"];
  weakened.allow_force_pushes.enabled = true;
  weakened.allow_deletions.enabled = true;
  const result = evaluateControls({ branch: weakened, environments: [] });
  assert.equal(result.valid, false);
  assert.deepEqual(result.findings, [
    "missing-required-check:dependency-review",
    "force-push-enabled",
    "protected-branch-deletion-enabled",
    "missing-environment:production",
    "missing-environment:dns-administration",
  ]);
});
