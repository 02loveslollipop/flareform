import assert from "node:assert/strict";
import test from "node:test";
import {
  isStrictDescendant,
  normalizeDnsName,
} from "../../src/dns/normalize.js";

function* inputs(seed, count) {
  const alphabet = "abcXYZ09.-_%/ @\u0000\u3002éоｏ";
  let state = seed;
  for (let i = 0; i < count; i++) {
    let value = "";
    const length = i % 48;
    for (let j = 0; j < length; j++) {
      state = (1664525 * state + 1013904223) >>> 0;
      value += alphabet[state % alphabet.length];
    }
    yield value;
  }
}

test("FUZZ-NAME-001 malformed random inputs either normalize or throw TypeError", () => {
  for (const input of inputs(42, 2000)) {
    try {
      assert.match(normalizeDnsName(input), /^[a-z0-9.-]+$/);
    } catch (error) {
      assert.ok(error instanceof TypeError, `${input}: ${error}`);
    }
  }
});

test("FUZZ-NAME-002 normalization is idempotent for valid names", () => {
  for (const label of ["api", "BÜCHER", "service-1", "192", "x".repeat(63)]) {
    const once = normalizeDnsName(`${label}.example-app.example.com`);
    assert.equal(normalizeDnsName(once), once);
  }
});

test("FUZZ-NAME-003 descendant helper requires an extra full label", () => {
  const root = "example-app.example.com";
  for (const name of ["api", "v2.api", "bücher"]) {
    const descendant = normalizeDnsName(`${name}.${root}`);
    assert.ok(isStrictDescendant(descendant, root));
    assert.ok(descendant.endsWith(`.${root}`));
    assert.notEqual(descendant, root);
  }
});

test("SEC-AUTHZ-002 encoded dots and alternate separators cannot escape namespace", () => {
  for (const value of [
    "api%2eexample-app.example.com",
    "api\u3002example-app.example.com",
    "api/example-app.example.com",
    "example-app.example.com.attacker.com",
  ]) {
    if (value.includes("attacker")) {
      assert.ok(
        !isStrictDescendant(normalizeDnsName(value), "example-app.example.com"),
      );
    } else {
      assert.throws(() => normalizeDnsName(value));
    }
  }
});
