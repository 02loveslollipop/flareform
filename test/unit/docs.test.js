import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("DOC-001 README describes scope, types, and credential boundary", async () => {
  const readme = await readFile("README.md", "utf8");
  for (const text of [
    "A, AAAA, CNAME, and SRV",
    "TXT is opt-in",
    "without giving those repositories Cloudflare credentials",
  ]) {
    assert.ok(readme.includes(text));
  }
});

test("DOC-002 SECURITY describes maintainer and account compromise boundaries", async () => {
  const security = await readFile("SECURITY.md", "utf8");
  assert.match(security, /maintainer who can change \*\*and approve\*\*/);
  assert.match(security, /cannot protect records if the Cloudflare account/);
  assert.match(security, /private GitHub security advisory/);
  assert.match(security, /Incident response/);
});

test("DOC-003 documentation does not claim cross-zone atomicity", async () => {
  const docs = `${await readFile("README.md", "utf8")}\n${await readFile("SECURITY.md", "utf8")}`;
  assert.match(docs, /not atomic across zones/);
  assert.match(docs, /not atomic/);
});
