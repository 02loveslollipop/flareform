import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { authorizeRecords } from "../../src/policy/authorize.js";
import { parsePolicyYaml, validatePolicy } from "../../src/policy/config.js";

const policy = validatePolicy(
  parsePolicyYaml(
    await readFile(
      new URL("../../config/examples/zones.yaml", import.meta.url),
      "utf8",
    ),
  ),
  [
    parsePolicyYaml(
      await readFile(
        new URL(
          "../../config/examples/repositories/example-app.yaml",
          import.meta.url,
        ),
        "utf8",
      ),
    ),
  ],
);
const id = policy.repositories[0].github.repository_id;

test("SEC-AUTHZ-001/002 suffix, encoded separator and lookalike attempts deny", () => {
  for (const name of [
    "evilexample-app.example.com",
    "example-app.example.com.attacker.com",
    "api%2eexample-app.example.com",
    "api。example-app.example.com",
    "ｏｔｈｅｒ.example.com",
    "example-app.example.com..",
  ])
    assert.throws(() => authorizeRecords(policy, id, [{ name, type: "A" }]));
  assert.equal(
    authorizeRecords(policy, id, [
      { name: "API.EXAMPLE-APP.EXAMPLE.COM.", type: "A" },
    ])[0].name,
    "api.example-app.example.com",
  );
});
