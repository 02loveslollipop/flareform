import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

function usage() {
  throw new Error(
    "Usage: migrate.js (--local|--remote) --config <operator-config.jsonc> [--persist-to <directory>] [--confirm-remote]",
  );
}

const args = process.argv.slice(2);
const mode = args.shift();
if (mode !== "--local" && mode !== "--remote") usage();

let config;
let persistTo;
let confirmRemote = false;
while (args.length > 0) {
  const option = args.shift();
  if (option === "--config" && !config) config = args.shift();
  else if (option === "--persist-to" && !persistTo) persistTo = args.shift();
  else if (option === "--confirm-remote" && !confirmRemote)
    confirmRemote = true;
  else usage();
}

if (!config || !existsSync(config)) usage();
if (mode === "--remote" && (!confirmRemote || persistTo)) usage();
if (mode === "--local" && confirmRemote) usage();

// A real D1 binding and database ID must come from an operator-supplied,
// uncommitted config. Wrangler records versions in d1_migrations and rolls
// back each failed migration. Never use the runtime DNS token to run this.
const wrangler = fileURLToPath(
  new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url),
);
const command = ["d1", "migrations", "apply", "DB", "--config", config, mode];
if (persistTo) command.push("--persist-to", persistTo);

const result = spawnSync(process.execPath, [wrangler, ...command], {
  stdio: "inherit",
  env: { ...process.env, WRANGLER_SEND_METRICS: "false" },
});
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
