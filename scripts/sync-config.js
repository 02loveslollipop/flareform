import { readFile, readdir, lstat } from "node:fs/promises";
import { resolve, join } from "node:path";
import { pathToFileURL } from "node:url";
import { parsePolicyYaml, validatePolicy } from "../src/policy/config.js";
import { policyVersion, syncPolicy } from "../src/policy/sync.js";

export async function loadPolicy(configDir) {
  const root = resolve(configDir);
  const readRegular = async (path) => {
    const info = await lstat(path);
    if (!info.isFile() || info.size > 65536)
      throw new Error("Invalid configuration file");
    return parsePolicyYaml(await readFile(path, "utf8"));
  };
  const zones = await readRegular(join(root, "zones.yaml"));
  const repositoryDir = join(root, "repositories");
  const names = (await readdir(repositoryDir)).sort();
  if (
    names.length > 100 ||
    names.some((name) => !/^[a-z0-9][a-z0-9_-]*\.yaml$/.test(name))
  )
    throw new Error("Invalid repository policy files");
  const repositories = await Promise.all(
    names.map((name) => readRegular(join(repositoryDir, name))),
  );
  return validatePolicy(zones, repositories);
}

export function remoteD1({ accountId, databaseId, token, fetchImpl = fetch }) {
  if (
    !/^[0-9a-f]{32}$/i.test(accountId) ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      databaseId,
    ) ||
    typeof token !== "string" ||
    token.length < 16
  )
    throw new Error("Invalid administrative D1 connection");
  const url = `https://api.cloudflare.com/client/v4/accounts/${accountId}/d1/database/${databaseId}/query`;
  const query = async (body) => {
    const response = await fetchImpl(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(body),
      redirect: "error",
      signal: AbortSignal.timeout(30000),
    });
    if (!response.ok) throw new Error("Administrative D1 query failed");
    const payload = await response.json();
    if (
      payload.success !== true ||
      !Array.isArray(payload.result) ||
      payload.result.some((item) => item.success !== true)
    )
      throw new Error("Administrative D1 query failed");
    return payload.result;
  };
  const prepare = (sql, params = []) => ({
    bind: (...values) => prepare(sql, values),
    first: async () => (await query({ sql, params }))[0]?.results?.[0] ?? null,
    all: async () => ({
      results: (await query({ sql, params }))[0]?.results ?? [],
    }),
    run: async () => (await query({ sql, params }))[0],
    _query: { sql, params },
  });
  return {
    prepare: (sql) => prepare(sql),
    // D1 executes a REST API batch as a transaction and rolls the whole batch
    // back if any statement fails. Explicit transaction statements are not
    // supported by D1 and would make every remote policy sync fail.
    batch: async (statements) =>
      query({
        batch: statements.map((item) => item._query),
      }),
  };
}

function usage() {
  throw new Error(
    "Usage: sync-config.js (--validate|--dry-run|--apply) --config-dir <trusted-dir> [--account-id <id> --database-id <id> --confirm-remote]",
  );
}

async function main(args) {
  const mode = args.shift();
  if (!["--validate", "--dry-run", "--apply"].includes(mode)) usage();
  let configDir,
    accountId,
    databaseId,
    confirmRemote = false;
  while (args.length) {
    const option = args.shift();
    if (option === "--config-dir" && !configDir) configDir = args.shift();
    else if (option === "--account-id" && !accountId) accountId = args.shift();
    else if (option === "--database-id" && !databaseId)
      databaseId = args.shift();
    else if (option === "--confirm-remote" && !confirmRemote)
      confirmRemote = true;
    else usage();
  }
  if (!configDir) usage();
  if (mode === "--apply" && (!confirmRemote || !accountId || !databaseId))
    usage();
  if (mode !== "--apply" && (confirmRemote || accountId || databaseId)) usage();
  const policy = await loadPolicy(configDir);
  const version = policyVersion(policy);
  if (mode === "--apply") {
    const db = remoteD1({
      accountId,
      databaseId,
      token: process.env.FLAREFORM_D1_ADMIN_TOKEN,
    });
    const result = await syncPolicy(db, policy);
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } else {
    process.stdout.write(
      `${JSON.stringify({ version, zones: policy.zones.length, repositories: policy.repositories.length, grants: policy.repositories.reduce((n, repo) => n + repo.grants.length, 0), mode: mode.slice(2) })}\n`,
    );
  }
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  main(process.argv.slice(2)).catch(() => {
    // No response bodies, tokens, policy content, or filesystem paths in logs.
    process.stderr.write("Policy validation or synchronization failed\n");
    process.exitCode = 1;
  });
}
