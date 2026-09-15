import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { FlareFormError } from "../../src/errors.js";
import { authorizeRecords } from "../../src/policy/authorize.js";
import { parsePolicyYaml, validatePolicy } from "../../src/policy/config.js";

const zones = parsePolicyYaml(
  await readFile(
    new URL("../../config/examples/zones.yaml", import.meta.url),
    "utf8",
  ),
);
const repo = parsePolicyYaml(
  await readFile(
    new URL(
      "../../config/examples/repositories/example-app.yaml",
      import.meta.url,
    ),
    "utf8",
  ),
);
const policy = validatePolicy(zones, [repo]);
const id = repo.github.repository_id;
const record = (name, type = "A") => ({ name, type });
const allow = (name, type = "A", p = policy) =>
  authorizeRecords(p, id, [record(name, type)]);
const deny = (code, name, type = "A", p = policy) =>
  assert.throws(
    () => allow(name, type, p),
    (error) => error instanceof FlareFormError && error.code === code,
  );

test("UNIT-AUTHZ-001..008 exact and strict descendant grants are independent per zone", () => {
  for (const zone of ["example.com", "example.net"]) {
    assert.equal(allow(`example-app.${zone}`)[0].zone, zone);
    assert.equal(
      allow(`api.example-app.${zone}`)[0].name,
      `api.example-app.${zone}`,
    );
    assert.equal(allow(`v2.api.example-app.${zone}`)[0].zone, zone);
    deny("HOSTNAME_NOT_AUTHORIZED", `evilexample-app.${zone}`);
    deny("UNKNOWN_ZONE", `example-app.${zone}.attacker.com`);
  }
  const exactOnly = structuredClone(policy);
  exactOnly.repositories[0].grants = exactOnly.repositories[0].grants.filter(
    (g) => g.kind === "exact",
  );
  deny(
    "HOSTNAME_NOT_AUTHORIZED",
    "api.example-app.example.com",
    "A",
    exactOnly,
  );
  const descendantsOnly = structuredClone(policy);
  descendantsOnly.repositories[0].grants =
    descendantsOnly.repositories[0].grants.filter(
      (g) => g.kind === "descendants",
    );
  deny(
    "HOSTNAME_NOT_AUTHORIZED",
    "example-app.example.com",
    "A",
    descendantsOnly,
  );
  const oneZone = structuredClone(policy);
  oneZone.repositories[0].grants = oneZone.repositories[0].grants.filter(
    (g) => g.zone === "example.com",
  );
  deny("HOSTNAME_NOT_AUTHORIZED", "example-app.example.net", "A", oneZone);
});

test("UNIT-AUTHZ-009..012 status, type, identity and prune checks fail closed", () => {
  const disabledRepo = structuredClone(policy);
  disabledRepo.repositories[0].enabled = false;
  deny("REPOSITORY_DISABLED", "example-app.example.com", "A", disabledRepo);
  const disabledZone = structuredClone(policy);
  disabledZone.zones[0].enabled = false;
  deny("ZONE_DISABLED", "example-app.example.com", "A", disabledZone);
  for (const type of ["A", "AAAA", "CNAME"])
    assert.equal(allow("example-app.example.com", type)[0].type, type);
  assert.equal(
    allow("_grpc._tcp.example-app.example.com", "SRV")[0].type,
    "SRV",
  );
  deny("INVALID_RECORD", "example-app.example.com", "SRV");
  for (const type of ["TXT", "NS", "MX", "CAA", "DS"])
    deny("RECORD_TYPE_NOT_AUTHORIZED", "example-app.example.com", type);
  assert.throws(
    () =>
      authorizeRecords(policy, "999999999", [
        record("example-app.example.com"),
      ]),
    (error) => error.code === "UNKNOWN_REPOSITORY",
  );
  assert.throws(
    () =>
      authorizeRecords(policy, id, [record("example-app.example.com")], {
        prune: true,
      }),
    (error) => error.code === "PRUNE_NOT_AUTHORIZED",
  );
  const txt = structuredClone(policy);
  const exactGrant = txt.repositories[0].grants.find(
    (g) => g.zone === "example.com" && g.kind === "exact",
  );
  exactGrant.record_types.push("TXT");
  assert.equal(allow(exactGrant.root, "TXT", txt).length, 1);
  assert.throws(
    () =>
      authorizeRecords(policy, id, [record("example-app.example.com")], {
        operation: "delete_all",
      }),
    (error) => error.code === "INVALID_RECORD",
  );
});

test("E2E-AUTHZ-001 both zones preflight before any mutation callback", () => {
  let mutated = 0;
  function planAndMutate(records) {
    const authorized = authorizeRecords(policy, id, records);
    mutated += authorized.length;
  }
  assert.throws(
    () =>
      planAndMutate([
        record("example-app.example.com"),
        record("unowned.example.net"),
      ]),
    (error) => error.code === "HOSTNAME_NOT_AUTHORIZED",
  );
  assert.equal(mutated, 0);
});
