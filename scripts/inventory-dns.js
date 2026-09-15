import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { stringify } from "yaml";
import { generateInventory } from "../src/admin/inventory.js";
import { remoteD1 } from "./sync-config.js";

function usage() {
  throw new Error(
    "Usage: inventory-dns.js --account-id <id> --database-id <id> [--output migration/inventory.yaml] [--replace]",
  );
}

function parseArgs(args) {
  const values = { output: "migration/inventory.yaml", replace: false };
  while (args.length) {
    const option = args.shift();
    if (option === "--account-id" && !values.accountId)
      values.accountId = args.shift();
    else if (option === "--database-id" && !values.databaseId)
      values.databaseId = args.shift();
    else if (
      option === "--output" &&
      values.output === "migration/inventory.yaml"
    )
      values.output = args.shift();
    else if (option === "--replace" && !values.replace) values.replace = true;
    else usage();
  }
  if (
    !values.accountId ||
    !values.databaseId ||
    !values.output ||
    values.output.length > 4096 ||
    /[\0\r\n]/.test(values.output)
  )
    usage();
  return values;
}

export async function main(args, environment = process.env) {
  const options = parseArgs([...args]);
  const db = remoteD1({
    accountId: options.accountId,
    databaseId: options.databaseId,
    token: environment.FLAREFORM_D1_ADMIN_TOKEN,
  });
  const inventory = await generateInventory({
    db,
    token: environment.FLAREFORM_DNS_ADMIN_TOKEN,
  });
  const output = resolve(options.output);
  await mkdir(dirname(output), { recursive: true, mode: 0o700 });
  await writeFile(output, stringify(inventory, { lineWidth: 0 }), {
    encoding: "utf8",
    mode: 0o600,
    flag: options.replace ? "w" : "wx",
  });
  process.stdout.write(
    `${JSON.stringify({ output: options.output, complete: inventory.complete, zones: inventory.zones.length })}\n`,
  );
  if (!inventory.complete) process.exitCode = 2;
  return inventory;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  main(process.argv.slice(2)).catch(() => {
    process.stderr.write("DNS inventory failed\n");
    process.exitCode = 1;
  });
}
