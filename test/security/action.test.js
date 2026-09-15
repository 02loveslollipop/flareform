import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import {
  callFlareForm,
  PRODUCTION_AUDIENCE,
} from "../../github-action/src/client.js";

test("SEC-ACT-001/004 production metadata and bundle have no endpoint or audience override", async () => {
  const [metadata, source, bundle] = await Promise.all([
    readFile(
      new URL("../../github-action/action.yml", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../../github-action/src/client.js", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../../github-action/dist/index.js", import.meta.url),
      "utf8",
    ),
  ]);
  assert.equal(PRODUCTION_AUDIENCE, "https://dns.02labs.me");
  assert.doesNotMatch(metadata, /endpoint|audience|token/i);
  assert.doesNotMatch(source, /FLAREFORM_(?:ENDPOINT|AUDIENCE)/);
  assert.doesNotMatch(
    bundle,
    /localhost|127\.0\.0\.1|FLAREFORM_(?:ENDPOINT|AUDIENCE)/,
  );
});

test("SEC-ACT-002/003 redirect and hostile body cannot move or disclose a JWT", async () => {
  const calls = [];
  let error;
  try {
    await callFlareForm({
      operation: "plan",
      manifest: "safe",
      token: "jwt-security-canary",
      fetchImpl: async (url, init) => {
        calls.push({ url, authorization: init.headers.authorization });
        return new Response("redirect-secret-canary", {
          status: 302,
          headers: { location: "https://attacker.invalid/capture" },
        });
      },
    });
  } catch (caught) {
    error = caught;
  }
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, "https://dns.02labs.me/v1/plan");
  assert.equal(error.code, "REDIRECT_REJECTED");
  assert.doesNotMatch(String(error), /jwt-security|redirect-secret|attacker/);
});
