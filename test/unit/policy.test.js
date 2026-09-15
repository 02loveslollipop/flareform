import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { parsePolicyYaml, validatePolicy } from "../../src/policy/config.js";

const zonesText = await readFile(
  new URL("../../config/examples/zones.yaml", import.meta.url),
  "utf8",
);
const repoText = await readFile(
  new URL(
    "../../config/examples/repositories/example-app.yaml",
    import.meta.url,
  ),
  "utf8",
);
const zones = parsePolicyYaml(zonesText);
const repo = parsePolicyYaml(repoText);
const clone = (value) => structuredClone(value);

test("POL-SCHEMA-001 mirrored sample grants exact and descendants in both zones", () => {
  const policy = validatePolicy(zones, [repo]);
  assert.equal(policy.zones.length, 2);
  assert.equal(policy.repositories[0].grants.length, 4);
  assert.equal(
    policy.repositories[0].grants.some((g) => g.record_types.includes("TXT")),
    false,
  );
});

test("POL-SCHEMA-002/003 unknown fields and unsafe OIDC conditions fail closed", () => {
  for (const mutate of [
    (p) => {
      p.surprise = true;
    },
    (p) => {
      delete p.github.repository_id;
    },
    (p) => {
      p.github.owner_id = 987654321;
    },
    (p) => {
      p.oidc.event = "pull_request_target";
    },
    (p) => {
      p.oidc.runner_environment = "self-hosted";
    },
    (p) => {
      p.oidc.workflow_ref = "*";
    },
    (p) => {
      p.grants[0].record_types.push("NS");
    },
    (p) => {
      p.grants[0].exact = ["evilexample-app.example.com.attacker.com"];
    },
    (p) => {
      p.grants[0].zone = "example.net";
    },
  ]) {
    const bad = clone(repo);
    mutate(bad);
    assert.throws(() => validatePolicy(zones, [bad]), TypeError);
  }
  const badZone = clone(zones);
  badZone.zones[0].unknown = true;
  assert.throws(() => validatePolicy(badZone, [repo]), TypeError);
});

test("POL-GRANT-001..005 overlaps are rejected in both repository orders", () => {
  const second = clone(repo);
  second.github.repository_id = "222222222";
  second.grants = [
    {
      zone: "example.com",
      exact: ["api.example-app.example.com"],
      descendants: ["api.example-app.example.com"],
      record_types: ["A"],
    },
  ];
  for (const ordered of [
    [repo, second],
    [second, repo],
  ])
    assert.throws(() => validatePolicy(zones, ordered), /overlap/);
  const nonOverlap = clone(second);
  nonOverlap.grants[0].exact = ["separate.example.com"];
  nonOverlap.grants[0].descendants = ["separate.example.com"];
  assert.equal(
    validatePolicy(zones, [repo, nonOverlap]).repositories.length,
    2,
  );
  const exactOnly = clone(repo);
  exactOnly.grants[0] = {
    zone: "example.com",
    exact: ["example-app.example.com"],
    record_types: ["A"],
  };
  assert.equal(
    validatePolicy(zones, [exactOnly]).repositories[0].grants.length,
    3,
  );
  const sameRoot = clone(second);
  sameRoot.grants = [
    {
      zone: "example.com",
      descendants: ["example-app.example.com"],
      record_types: ["A"],
    },
  ];
  assert.throws(() => validatePolicy(zones, [exactOnly, sameRoot]), /overlap/);
});

test("SEC-POL-002 YAML aliases, tags, merges, duplicates and oversized input fail", () => {
  for (const source of [
    "a: 1\na: 2\n",
    "a: &x foo\nb: *x\n",
    "a: !!str foo\n",
    "a: { <<: { x: y } }\n",
    "x".repeat(65537),
  ])
    assert.throws(() => parsePolicyYaml(source), TypeError);
});
