import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { adoptRecord } from "../src/admin/adopt.js";
import { remoteD1 } from "./sync-config.js";

export function isApprovedAdministrativeCi(environment = process.env) {
  return (
    environment.GITHUB_ACTIONS === "true" &&
    typeof environment.FLAREFORM_CONTROL_REPOSITORY === "string" &&
    environment.FLAREFORM_CONTROL_REPOSITORY.length > 0 &&
    environment.GITHUB_REPOSITORY ===
      environment.FLAREFORM_CONTROL_REPOSITORY &&
    environment.GITHUB_REF === "refs/heads/main" &&
    environment.FLAREFORM_ADMIN_ENVIRONMENT === "dns-administration"
  );
}

function usage() {
  throw new Error(
    "Usage: adopt-record.js (--dry-run|--apply) --account-id <id> --database-id <id> --repository-id <id> --client-key <key> --zone <zone> --record-id <id> [--confirm-adoption]",
  );
}

function parseArgs(args) {
  const mode = args.shift();
  if (!["--dry-run", "--apply"].includes(mode)) usage();
  const values = {};
  let confirm = false;
  const names = new Map([
    ["--account-id", "accountId"],
    ["--database-id", "databaseId"],
    ["--repository-id", "repositoryId"],
    ["--client-key", "clientKey"],
    ["--zone", "zoneName"],
    ["--record-id", "cloudflareRecordId"],
  ]);
  while (args.length) {
    const option = args.shift();
    if (option === "--confirm-adoption" && !confirm) confirm = true;
    else if (names.has(option) && !values[names.get(option)])
      values[names.get(option)] = args.shift();
    else usage();
  }
  if (Object.values(values).length !== names.size) usage();
  if (mode === "--dry-run" && confirm) usage();
  return { mode, confirm, ...values };
}

export async function main(args, environment = process.env) {
  const options = parseArgs([...args]);
  const db = remoteD1({
    accountId: options.accountId,
    databaseId: options.databaseId,
    token: environment.FLAREFORM_D1_ADMIN_TOKEN,
  });
  const common = {
    db,
    repositoryId: options.repositoryId,
    clientKey: options.clientKey,
    zoneName: options.zoneName,
    cloudflareRecordId: options.cloudflareRecordId,
    token: environment.FLAREFORM_DNS_ADMIN_TOKEN,
  };
  const preview = await adoptRecord(common);
  process.stdout.write(`${JSON.stringify({ mode: "dry-run", ...preview })}\n`);
  if (options.mode === "--dry-run") return preview;
  if (!options.confirm && !isApprovedAdministrativeCi(environment)) usage();
  const result = await adoptRecord({ ...common, apply: true });
  process.stdout.write(`${JSON.stringify({ mode: "apply", ...result })}\n`);
  return result;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  main(process.argv.slice(2)).catch(() => {
    process.stderr.write("Record adoption failed\n");
    process.exitCode = 1;
  });
}
