import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { auditOwnership } from "../src/admin/inventory.js";
import { remoteD1 } from "./sync-config.js";

function usage() {
  throw new Error(
    "Usage: audit-ownership.js --account-id <id> --database-id <id>",
  );
}

function parseArgs(args) {
  let accountId;
  let databaseId;
  while (args.length) {
    const option = args.shift();
    if (option === "--account-id" && !accountId) accountId = args.shift();
    else if (option === "--database-id" && !databaseId)
      databaseId = args.shift();
    else usage();
  }
  if (!accountId || !databaseId) usage();
  return { accountId, databaseId };
}

export async function main(args, environment = process.env) {
  const options = parseArgs([...args]);
  const db = remoteD1({
    ...options,
    token: environment.FLAREFORM_D1_ADMIN_TOKEN,
  });
  const report = await auditOwnership({
    db,
    token: environment.FLAREFORM_DNS_ADMIN_TOKEN,
  });
  process.stdout.write(`${JSON.stringify(report)}\n`);
  if (!report.complete || report.findings.length) process.exitCode = 2;
  return report;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  main(process.argv.slice(2)).catch(() => {
    process.stderr.write("Ownership audit failed\n");
    process.exitCode = 1;
  });
}
