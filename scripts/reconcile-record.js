import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  inspectIndeterminate,
  resolveIndeterminate,
} from "../src/admin/reconcile.js";
import { createCloudflareClient } from "../src/dns/cloudflare.js";
import { isApprovedAdministrativeCi } from "./adopt-record.js";
import { remoteD1 } from "./sync-config.js";

function usage() {
  throw new Error(
    "Usage: reconcile-record.js (--inspect|--resolve) --account-id <id> --database-id <id> --operation-id <id> --client-key <key> [--decision <confirm-provider|confirm-no-change> --operator-id <id> --confirm-resolution]",
  );
}

function parseArgs(args) {
  const mode = args.shift();
  if (!["--inspect", "--resolve"].includes(mode)) usage();
  const values = {};
  let confirm = false;
  const names = new Map([
    ["--account-id", "accountId"],
    ["--database-id", "databaseId"],
    ["--operation-id", "operationId"],
    ["--client-key", "clientKey"],
    ["--decision", "decision"],
    ["--operator-id", "operatorId"],
  ]);
  while (args.length) {
    const option = args.shift();
    if (option === "--confirm-resolution" && !confirm) confirm = true;
    else if (names.has(option) && !values[names.get(option)])
      values[names.get(option)] = args.shift();
    else usage();
  }
  for (const required of [
    "accountId",
    "databaseId",
    "operationId",
    "clientKey",
  ])
    if (!values[required]) usage();
  if (mode === "--inspect" && (values.decision || values.operatorId || confirm))
    usage();
  if (
    mode === "--resolve" &&
    (!["confirm-provider", "confirm-no-change"].includes(values.decision) ||
      !/^[1-9][0-9]*$/.test(values.operatorId ?? ""))
  )
    usage();
  return { mode, confirm, ...values };
}

function summary(inspected) {
  return {
    operation_id: inspected.operation.id,
    operation_status: inspected.operation.status,
    client_key: inspected.intent.client_key,
    intent_status: inspected.intent.status,
    intent_action: inspected.intent.action,
    zone: inspected.zone.name,
    evidence: inspected.evidence,
  };
}

export async function main(args, environment = process.env, dependencies = {}) {
  const options = parseArgs([...args]);
  const makeDb = dependencies.remoteD1 ?? remoteD1;
  const makeCloudflare =
    dependencies.createCloudflareClient ?? createCloudflareClient;
  const inspect = dependencies.inspectIndeterminate ?? inspectIndeterminate;
  const resolveRecord =
    dependencies.resolveIndeterminate ?? resolveIndeterminate;
  const db = makeDb({
    accountId: options.accountId,
    databaseId: options.databaseId,
    token: environment.FLAREFORM_D1_ADMIN_TOKEN,
  });
  const cloudflare = makeCloudflare({
    token: environment.FLAREFORM_DNS_ADMIN_TOKEN,
  });
  const common = {
    db,
    cloudflare,
    operationId: options.operationId,
    clientKey: options.clientKey,
  };
  const inspected = await inspect(common);
  const preview = summary(inspected);
  process.stdout.write(`${JSON.stringify({ mode: "inspect", ...preview })}\n`);
  if (options.mode === "--inspect") return preview;
  if (!options.confirm && !isApprovedAdministrativeCi(environment)) usage();
  const result = await resolveRecord({
    ...common,
    decision: options.decision,
    operatorId: options.operatorId,
  });
  process.stdout.write(`${JSON.stringify({ mode: "resolve", ...result })}\n`);
  return result;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  main(process.argv.slice(2)).catch(() => {
    process.stderr.write("Record reconciliation failed\n");
    process.exitCode = 1;
  });
}
