import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import test from "node:test";

const wrangler = new URL(
  "../../node_modules/wrangler/bin/wrangler.js",
  import.meta.url,
).pathname;
const config = new URL("../fixtures/wrangler-d1.jsonc", import.meta.url)
  .pathname;

async function freePort() {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  await new Promise((resolve) => server.close(resolve));
  return port;
}

test("DB-REPO-004 native local D1 batch rolls back an earlier successful insert", async (t) => {
  const state = await mkdtemp(join(tmpdir(), "flareform-d1-batch-"));
  const port = await freePort();
  const child = spawn(
    process.execPath,
    [
      wrangler,
      "dev",
      "--local",
      "--config",
      config,
      "--persist-to",
      state,
      "--port",
      String(port),
      "--ip",
      "127.0.0.1",
      "--log-level",
      "error",
      "--show-interactive-dev-session",
      "false",
    ],
    {
      env: { ...process.env, CI: "true", WRANGLER_SEND_METRICS: "false" },
      stdio: "ignore",
    },
  );
  t.after(async () => {
    child.kill("SIGTERM");
    await delay(300);
    await rm(state, { recursive: true, force: true });
  });
  const base = `http://127.0.0.1:${port}`;
  let ready = false;
  for (let attempt = 0; attempt < 150; attempt++) {
    if (child.exitCode !== null) break;
    try {
      const response = await fetch(`${base}/setup`);
      if (response.ok) {
        ready = true;
        break;
      }
    } catch {
      /* Workerd is still starting. */
    }
    await delay(200);
  }
  assert.equal(ready, true, "local D1 Worker did not start");
  assert.equal(await (await fetch(`${base}/conflict`)).text(), "rolled back");
  assert.equal(await (await fetch(`${base}/count`)).text(), "0");
});
