import assert from "node:assert/strict";
import test from "node:test";
import {
  isStrictDescendant,
  normalizeDnsName,
  selectConfiguredZone,
} from "../../src/dns/normalize.js";

test("UNIT-NAME-001/002 lowercase is stable and uppercase canonicalizes", () => {
  assert.equal(
    normalizeDnsName("example-app.example.com"),
    "example-app.example.com",
  );
  assert.equal(
    normalizeDnsName("Example-App.Example.COM"),
    "example-app.example.com",
  );
});

test("UNIT-NAME-003 exactly one trailing dot may be removed", () => {
  assert.equal(
    normalizeDnsName("api.example-app.example.com."),
    "api.example-app.example.com",
  );
  assert.throws(() => normalizeDnsName("api.example-app.example.com.."));
});

test("UNIT-NAME-004 outer whitespace is trimmed; inner whitespace denied", () => {
  assert.equal(normalizeDnsName(" \tApi.Example.COM\n"), "api.example.com");
  assert.throws(() => normalizeDnsName("api .example.com"));
});

test("UNIT-NAME-005 equivalent Unicode and Punycode produce one name", () => {
  assert.equal(normalizeDnsName("bücher.example"), "xn--bcher-kva.example");
  assert.equal(
    normalizeDnsName("BÜCHER.example"),
    normalizeDnsName("xn--bcher-kva.example"),
  );
});

test("UNIT-NAME-006 lookalikes cannot canonicalize to authorized ASCII", () => {
  assert.notEqual(
    normalizeDnsName("оther.example.com"),
    "example-app.example.com",
  );
  assert.throws(() => normalizeDnsName("ｏｔｈｅｒ.example.com"));
  assert.throws(() => normalizeDnsName("Key.example.com"));
});

test("UNIT-NAME-007 invalid labels and separators fail", () => {
  for (const value of [
    "",
    ".example.com",
    "a..example.com",
    "-a.example.com",
    "a-.example.com",
    "a_b.example.com",
    "a/b.example.com",
    "a@b.example.com",
    "a%2eb.example.com",
    "a\u0000b.example.com",
    "a\u3002example.com",
    "xn--.example.com",
  ]) {
    assert.throws(() => normalizeDnsName(value), value);
  }
});

test("UNIT-NAME-008 63-octet label accepted; 64 denied", () => {
  assert.equal(normalizeDnsName(`${"a".repeat(63)}.example.com`).length, 75);
  assert.throws(() => normalizeDnsName(`${"a".repeat(64)}.example.com`));
});

test("UNIT-NAME-009 total length limit applies after IDNA", () => {
  const max = [
    "a".repeat(63),
    "b".repeat(63),
    "c".repeat(63),
    "d".repeat(61),
  ].join(".");
  assert.equal(max.length, 253);
  assert.equal(normalizeDnsName(max), max);
  assert.throws(() => normalizeDnsName(`${max}a`));
});

test("UNIT-NAME-010 longest configured zone wins at a label boundary", () => {
  const zones = [
    { name: "example.com", enabled: true },
    { name: "example-app.example.com", enabled: false },
  ];
  assert.deepEqual(selectConfiguredZone("api.example-app.example.com", zones), {
    name: "example-app.example.com",
    enabled: false,
  });
  assert.equal(
    selectConfiguredZone("other.example.com", zones).name,
    "example.com",
  );
});

test("UNIT-NAME-011 suffix confusion never selects a zone", () => {
  const zones = [{ name: "example-app.example.com" }];
  assert.equal(
    selectConfiguredZone("evilexample-app.example.com", zones),
    null,
  );
  assert.equal(
    selectConfiguredZone("example-app.example.com.attacker.com", zones),
    null,
  );
  assert.equal(
    isStrictDescendant(
      "evilexample-app.example.com",
      "example-app.example.com",
    ),
    false,
  );
  assert.equal(
    isStrictDescendant("example-app.example.com", "example-app.example.com"),
    false,
  );
});
