import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Strict inequality protects JTIs that are still valid at the cleanup instant.
export async function cleanupExpiredJtis(
  db,
  nowEpoch = Math.floor(Date.now() / 1000),
) {
  if (!Number.isSafeInteger(nowEpoch) || nowEpoch < 0)
    throw new TypeError("Invalid cleanup time");
  return db
    .prepare("DELETE FROM oidc_jti WHERE expires_at < ?")
    .bind(nowEpoch)
    .run();
}

if (
  process.argv[1] &&
  fileURLToPath(import.meta.url) === resolve(process.argv[1])
) {
  const args = process.argv.slice(2);
  const mode = args.shift();
  const configFlag = args.shift();
  const config = args.shift();
  const confirm = args.shift();
  if (
    !["--local", "--remote"].includes(mode) ||
    configFlag !== "--config" ||
    !config ||
    !existsSync(config) ||
    args.length ||
    (mode === "--remote" && confirm !== "--confirm-remote") ||
    (mode === "--local" && confirm !== undefined)
  )
    throw new Error(
      "Usage: cleanup-jti.js (--local|--remote) --config <operator-config.jsonc> [--confirm-remote]",
    );
  const wrangler = fileURLToPath(
    new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url),
  );
  const nowEpoch = Math.floor(Date.now() / 1000);
  const result = spawnSync(
    process.execPath,
    [
      wrangler,
      "d1",
      "execute",
      "DB",
      "--config",
      config,
      mode,
      "--command",
      `DELETE FROM oidc_jti WHERE expires_at < ${nowEpoch}`,
    ],
    {
      stdio: "inherit",
      env: { ...process.env, WRANGLER_SEND_METRICS: "false" },
    },
  );
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
}
