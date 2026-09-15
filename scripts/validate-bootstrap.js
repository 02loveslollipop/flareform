import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const HEX_ID = /^[0-9a-f]{32}$/i;
const UUID =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const GITHUB_ID = /^[1-9][0-9]*$/;
const PLACEHOLDER = /placeholder|example|change[-_ ]?me|your[-_ ]/i;

function actual(value, pattern) {
  return (
    typeof value === "string" &&
    pattern.test(value) &&
    !PLACEHOLDER.test(value) &&
    !/^(.)\1+$/.test(value.replaceAll("-", ""))
  );
}

export function validateBootstrap(values) {
  if (
    !values ||
    typeof values !== "object" ||
    !actual(values.accountId, HEX_ID) ||
    !actual(values.databaseId, UUID) ||
    !actual(values.zone02labsId, HEX_ID) ||
    !actual(values.zoneUkId, HEX_ID) ||
    values.zone02labsId === values.zoneUkId ||
    !actual(values.repositoryId, GITHUB_ID) ||
    !actual(values.ownerId, GITHUB_ID) ||
    values.repositoryId === values.ownerId ||
    typeof values.runtimeDnsToken !== "string" ||
    values.runtimeDnsToken.length < 20 ||
    typeof values.deploymentToken !== "string" ||
    values.deploymentToken.length < 20 ||
    values.runtimeDnsToken === values.deploymentToken
  )
    throw new Error("Bootstrap inputs are incomplete or unsafe");
  return {
    valid: true,
    zones: ["example.com", "example.net"],
    credentials_distinct: true,
  };
}

export function fromEnvironment(environment = process.env) {
  return {
    accountId: environment.FLAREFORM_ACCOUNT_ID,
    databaseId: environment.FLAREFORM_DATABASE_ID,
    zone02labsId: environment.FLAREFORM_02LABS_ZONE_ID,
    zoneUkId: environment.FLAREFORM_UK_ZONE_ID,
    repositoryId: environment.FLAREFORM_BOOTSTRAP_REPOSITORY_ID,
    ownerId: environment.FLAREFORM_BOOTSTRAP_OWNER_ID,
    runtimeDnsToken: environment.CLOUDFLARE_DNS_TOKEN,
    deploymentToken: environment.CLOUDFLARE_DEPLOY_TOKEN,
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  try {
    const result = validateBootstrap(fromEnvironment());
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch {
    process.stderr.write("Bootstrap validation failed\n");
    process.exitCode = 1;
  }
}
