import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const readJson = async (path) => JSON.parse(await readFile(path, "utf8"));

test("BLD-001 lockfiles match package manifests", async () => {
  for (const prefix of [".", "github-action"]) {
    const manifest = await readJson(`${prefix}/package.json`);
    const lock = await readJson(`${prefix}/package-lock.json`);
    assert.equal(lock.packages[""].name, manifest.name);
    assert.deepEqual(
      lock.packages[""].devDependencies ?? {},
      manifest.devDependencies ?? {},
    );
  }
});

test("BLD-002 all required commands are executable npm scripts", async () => {
  const { scripts } = await readJson("package.json");
  for (const name of [
    "format:check",
    "lint",
    "test:unit",
    "test:integration",
    "test:security",
    "build",
    "verify:action-dist",
  ]) {
    assert.match(scripts[name], /\S/);
  }
});

test("BLD-003 runtime and Action both declare Node 24", async () => {
  const root = await readJson("package.json");
  const action = await readJson("github-action/package.json");
  const metadata = await readFile("github-action/action.yml", "utf8");
  assert.equal(root.type, "module");
  assert.equal(action.type, "module");
  assert.equal(root.engines.node, ">=24 <25");
  assert.equal(action.engines.node, ">=24 <25");
  assert.match(metadata, /using: node24/);
});

test("SEC-SUP-001 CI installs only from lockfiles and pins external actions", async () => {
  const workflow = await readFile(".github/workflows/test.yml", "utf8");
  assert.equal((workflow.match(/run: npm ci/g) ?? []).length, 2);
  assert.doesNotMatch(workflow, /run: npm install/);
  for (const match of workflow.matchAll(/uses: [^@\n]+@([^\s#]+)/g)) {
    assert.match(match[1], /^[0-9a-f]{40}$/);
  }
});

test("BLD-ACT-001 committed Action output matches source", async () => {
  const { build } = await import("esbuild");
  const result = await build({
    entryPoints: ["github-action/src/index.js"],
    bundle: true,
    format: "cjs",
    platform: "node",
    target: "node24",
    write: false,
    logLevel: "silent",
  });
  assert.equal(
    await readFile("github-action/dist/index.js", "utf8"),
    result.outputFiles[0].text,
  );
});

test("BLD-ACT-002 stale generated output is detected by the comparison", async () => {
  const { assertBundleCurrent } = await import("../../scripts/bundle-check.js");
  const committed = await readFile("github-action/dist/index.js", "utf8");
  assert.doesNotThrow(() => assertBundleCurrent(committed, committed));
  assert.throws(
    () => assertBundleCurrent(`${committed}\n// changed source`, committed),
    /stale/,
  );
});
