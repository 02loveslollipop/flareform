import { readFile, realpath } from "node:fs/promises";
import path from "node:path";
import { parseDocument, stringify, visit } from "yaml";

export const PRODUCTION_AUDIENCE = "https://dns.02labs.me";
const MAX_MANIFEST_BYTES = 65_536;
const MAX_RESPONSE_BYTES = 262_144;
const MAX_OIDC_BYTES = 16_384;
const VARIABLE = /\$\{([A-Z_][A-Z0-9_]*)\}/g;
const ERROR_CODE = /^[A-Z][A-Z0-9_]{2,63}$/;

export class ActionError extends Error {
  constructor(code) {
    super(code);
    this.name = "ActionError";
    this.code = code;
  }
}

function fail(code) {
  throw new ActionError(code);
}

function plainObject(value) {
  return value && typeof value === "object" && !Array.isArray(value);
}

function safeKey(key) {
  return !["__proto__", "constructor", "prototype"].includes(key);
}

function validateLocalShape(value) {
  if (
    !plainObject(value) ||
    value.version !== 1 ||
    !["keep", "prune"].includes(value.reconciliation) ||
    !Array.isArray(value.records) ||
    value.records.length < 1 ||
    value.records.length > 100 ||
    Object.keys(value).some(
      (key) =>
        !safeKey(key) ||
        !["version", "reconciliation", "prune_zones", "records"].includes(key),
    )
  )
    fail("INVALID_MANIFEST");
  if (value.reconciliation === "keep" && Object.hasOwn(value, "prune_zones"))
    fail("INVALID_MANIFEST");
  if (
    value.reconciliation === "prune" &&
    (!Array.isArray(value.prune_zones) || value.prune_zones.length < 1)
  )
    fail("INVALID_MANIFEST");
  for (const record of value.records) {
    if (
      !plainObject(record) ||
      typeof record.key !== "string" ||
      typeof record.zone !== "string" ||
      typeof record.name !== "string" ||
      typeof record.type !== "string"
    )
      fail("INVALID_MANIFEST");
  }
}

function resolveValue(value, environment) {
  if (Array.isArray(value))
    return value.map((entry) => resolveValue(entry, environment));
  if (plainObject(value)) {
    const resolved = Object.create(null);
    for (const [key, entry] of Object.entries(value)) {
      if (!safeKey(key) || key.includes("${"))
        fail("INVALID_VARIABLE_REFERENCE");
      resolved[key] = resolveValue(entry, environment);
    }
    return resolved;
  }
  if (typeof value !== "string") return value;
  VARIABLE.lastIndex = 0;
  const resolved = value.replace(VARIABLE, (_match, name) => {
    if (!Object.hasOwn(environment, name)) fail("MISSING_VARIABLE");
    const replacement = environment[name];
    if (
      typeof replacement !== "string" ||
      new TextEncoder().encode(replacement).length > 4096
    )
      fail("INVALID_VARIABLE");
    return replacement;
  });
  if (resolved.includes("${")) fail("INVALID_VARIABLE_REFERENCE");
  return resolved;
}

export function prepareManifest(source, environment = {}) {
  if (
    typeof source !== "string" ||
    new TextEncoder().encode(source).length > MAX_MANIFEST_BYTES
  )
    fail("INVALID_MANIFEST");
  let document;
  try {
    document = parseDocument(source, {
      uniqueKeys: true,
      merge: false,
      strict: true,
    });
    if (document.errors.length || document.warnings.length)
      fail("INVALID_MANIFEST");
    visit(document, {
      Node(_key, node) {
        if (node.anchor || node.tag || node.constructor.name === "Alias")
          fail("INVALID_MANIFEST");
      },
      Pair(_key, pair) {
        if (pair.key?.value === "<<") fail("INVALID_MANIFEST");
      },
    });
    const parsed = document.toJS({ maxAliasCount: 0 });
    validateLocalShape(parsed);
    const resolved = resolveValue(parsed, environment);
    const output = stringify(resolved, { lineWidth: 0 });
    if (new TextEncoder().encode(output).length > MAX_MANIFEST_BYTES)
      fail("INVALID_MANIFEST");
    return output;
  } catch (error) {
    if (error instanceof ActionError) throw error;
    fail("INVALID_MANIFEST");
  }
}

export async function loadManifest(input, environment = process.env) {
  const workspace = path.resolve(environment.GITHUB_WORKSPACE ?? process.cwd());
  const requested = path.resolve(workspace, input || "flareform.yaml");
  const requestedRelative = path.relative(workspace, requested);
  if (requestedRelative.startsWith("..") || path.isAbsolute(requestedRelative))
    fail("INVALID_MANIFEST_PATH");
  let filename;
  try {
    const realWorkspace = await realpath(workspace);
    filename = await realpath(requested);
    const relative = path.relative(realWorkspace, filename);
    if (relative.startsWith("..") || path.isAbsolute(relative))
      fail("INVALID_MANIFEST_PATH");
  } catch (error) {
    if (error instanceof ActionError) throw error;
    fail("MANIFEST_NOT_FOUND");
  }
  let source;
  try {
    source = await readFile(filename, "utf8");
  } catch {
    fail("MANIFEST_NOT_FOUND");
  }
  return prepareManifest(source, environment);
}

async function readLimited(response, maximum) {
  const declared = response.headers.get("content-length");
  if (
    declared !== null &&
    (!/^(?:0|[1-9]\d*)$/.test(declared) || Number(declared) > maximum)
  )
    fail("RESPONSE_TOO_LARGE");
  const reader = response.body?.getReader();
  if (!reader) fail("INVALID_RESPONSE");
  const chunks = [];
  let size = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maximum) {
      await reader.cancel().catch(() => {});
      fail("RESPONSE_TOO_LARGE");
    }
    chunks.push(value);
  }
  const body = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body));
  } catch {
    fail("INVALID_RESPONSE");
  }
}

function oidcEndpoint(environment) {
  if (
    typeof environment.ACTIONS_ID_TOKEN_REQUEST_URL !== "string" ||
    typeof environment.ACTIONS_ID_TOKEN_REQUEST_TOKEN !== "string" ||
    environment.ACTIONS_ID_TOKEN_REQUEST_TOKEN.length < 1
  )
    fail("OIDC_UNAVAILABLE");
  let url;
  try {
    url = new URL(environment.ACTIONS_ID_TOKEN_REQUEST_URL);
  } catch {
    fail("OIDC_UNAVAILABLE");
  }
  if (
    url.protocol !== "https:" ||
    url.port ||
    url.username ||
    url.password ||
    url.hash ||
    !(
      url.hostname === "actions.githubusercontent.com" ||
      url.hostname.endsWith(".actions.githubusercontent.com")
    )
  )
    fail("OIDC_UNAVAILABLE");
  url.searchParams.set("audience", PRODUCTION_AUDIENCE);
  return url;
}

export async function requestOidcToken({
  environment = process.env,
  fetchImpl = fetch,
  timeoutMs = 15_000,
} = {}) {
  const url = oidcEndpoint(environment);
  let response;
  try {
    response = await fetchImpl(url, {
      method: "GET",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${environment.ACTIONS_ID_TOKEN_REQUEST_TOKEN}`,
      },
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    fail("OIDC_REQUEST_FAILED");
  }
  if (response.status >= 300 && response.status < 400)
    fail("REDIRECT_REJECTED");
  if (response.status !== 200) fail("OIDC_REQUEST_FAILED");
  if (
    !response.headers
      .get("content-type")
      ?.toLowerCase()
      .startsWith("application/json")
  )
    fail("INVALID_OIDC_RESPONSE");
  const body = await readLimited(response, MAX_OIDC_BYTES);
  if (
    !plainObject(body) ||
    typeof body.value !== "string" ||
    body.value.length > MAX_OIDC_BYTES ||
    !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(body.value)
  )
    fail("INVALID_OIDC_RESPONSE");
  return body.value;
}

function stableServerCode(body) {
  const code = body?.error?.code;
  return typeof code === "string" && ERROR_CODE.test(code)
    ? code
    : "REQUEST_FAILED";
}

export async function callFlareForm({
  operation,
  manifest,
  token,
  planId,
  fetchImpl = fetch,
  timeoutMs = 20_000,
}) {
  if (!new Set(["plan", "apply"]).has(operation)) fail("INVALID_OPERATION");
  const url = `${PRODUCTION_AUDIENCE}/v1/${operation}`;
  const body = {
    manifest,
    ...(planId ? { plan_id: planId } : {}),
  };
  let response;
  try {
    response = await fetchImpl(url, {
      method: "POST",
      headers: {
        accept: "application/json",
        authorization: `Bearer ${token}`,
        "content-type": "application/json",
      },
      body: JSON.stringify(body),
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    fail("NETWORK_ERROR");
  }
  if (response.status >= 300 && response.status < 400)
    fail("REDIRECT_REJECTED");
  if (
    !response.headers
      .get("content-type")
      ?.toLowerCase()
      .startsWith("application/json")
  )
    fail("INVALID_RESPONSE");
  const data = await readLimited(response, MAX_RESPONSE_BYTES);
  if (!plainObject(data)) fail("INVALID_RESPONSE");
  return { status: response.status, data, errorCode: stableServerCode(data) };
}

function safeLabel(value) {
  return typeof value === "string" && /^[A-Za-z0-9._:-]{1,253}$/.test(value)
    ? value
    : "[invalid-label]";
}

export function planLines(data) {
  if (!plainObject(data?.changes)) fail("INVALID_RESPONSE");
  const lines = ["FlareForm plan:"];
  for (const zone of Object.keys(data.changes).sort()) {
    if (!Array.isArray(data.changes[zone])) fail("INVALID_RESPONSE");
    for (const change of data.changes[zone]) {
      if (!plainObject(change)) fail("INVALID_RESPONSE");
      lines.push(
        `[${safeLabel(zone)}] ${safeLabel(change.action)} ${safeLabel(change.type)} ${safeLabel(change.name)} (${safeLabel(change.key)})`,
      );
    }
  }
  return lines;
}

export function resultLines(data) {
  if (!plainObject(data?.zones)) fail("INVALID_RESPONSE");
  const operationId = safeLabel(data.operation_id);
  const lines = [`FlareForm operation ${operationId}:`];
  for (const zone of Object.keys(data.zones).sort()) {
    const result = data.zones[zone];
    if (!plainObject(result)) fail("INVALID_RESPONSE");
    lines.push(
      `[${safeLabel(zone)}] ${safeLabel(result.status)}${result.error ? ` (${safeLabel(result.error)})` : ""}`,
    );
  }
  return lines;
}

function requireSuccess(result) {
  if (result.status < 200 || result.status >= 300) fail(result.errorCode);
  return result.data;
}

export async function runAction({
  environment = process.env,
  fetchImpl = fetch,
  logger = console,
} = {}) {
  const operation = (environment.INPUT_OPERATION || "apply").trim();
  if (!new Set(["plan", "apply"]).has(operation)) fail("INVALID_OPERATION");
  const manifest = await loadManifest(
    (environment.INPUT_MANIFEST || "flareform.yaml").trim(),
    environment,
  );
  const getToken = () => requestOidcToken({ environment, fetchImpl });
  const plan = await callFlareForm({
    operation: "plan",
    manifest,
    token: await getToken(),
    fetchImpl,
  });
  const planData = requireSuccess(plan);
  for (const line of planLines(planData)) logger.log(line);
  if (operation === "plan") return planData;

  const hasDeletion = Object.values(planData.changes).some((changes) =>
    changes.some((change) => change.action === "delete"),
  );
  const apply = () =>
    getToken().then((token) =>
      callFlareForm({
        operation: "apply",
        manifest,
        token,
        ...(hasDeletion ? { planId: planData.plan_id } : {}),
        fetchImpl,
      }),
    );
  let result = await apply();
  if (
    (result.status < 200 || result.status >= 300) &&
    !(result.status === 502 && result.errorCode === "PARTIAL_ZONE_FAILURE")
  )
    requireSuccess(result);
  for (const line of resultLines(result.data)) logger.log(line);
  if (result.status === 502 && result.errorCode === "PARTIAL_ZONE_FAILURE") {
    logger.log(
      "FlareForm retrying pre-send zone failures with a fresh identity token.",
    );
    result = await apply();
    if (
      (result.status < 200 || result.status >= 300) &&
      !(result.status === 502 && result.errorCode === "PARTIAL_ZONE_FAILURE")
    )
      requireSuccess(result);
    for (const line of resultLines(result.data)) logger.log(line);
  }
  return requireSuccess(result);
}
