import { FlareFormError } from "../errors.js";

export const MAX_PRUNE_DELETIONS = 10;
function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stable(value[key])}`)
      .join(",")}}`;
  return JSON.stringify(value);
}
async function hmac(key, value) {
  if (typeof key !== "string" || new TextEncoder().encode(key).length < 32)
    throw new FlareFormError("SERVICE_UNAVAILABLE");
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const digest = await crypto.subtle.sign(
    "HMAC",
    cryptoKey,
    new TextEncoder().encode(stable(value)),
  );
  return Array.from(new Uint8Array(digest), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}
function desiredValue(record) {
  return record.type === "SRV"
    ? {
        priority: record.priority,
        weight: record.weight,
        port: record.port,
        target: record.target,
      }
    : record.content;
}
function actualValue(record) {
  return record?.type === "SRV" ? record.data : record?.content;
}
function safeValue(type, value) {
  return type === "TXT" ? "[REDACTED]" : value;
}
function sortChanges(changes) {
  return changes.sort((a, b) => {
    const left = `${a.zone}\0${a.name}\0${a.type}\0${a.key}\0${a.action}`;
    const right = `${b.zone}\0${b.name}\0${b.type}\0${b.key}\0${b.action}`;
    return left < right ? -1 : left > right ? 1 : 0;
  });
}
export async function digestManifest(manifest, repositoryId, digestKey) {
  if (!manifest || typeof repositoryId !== "string")
    throw new FlareFormError("INVALID_RECORD");
  const protectedRecords = await Promise.all(
    manifest.records.map(async (record) =>
      record.type === "TXT"
        ? {
            ...record,
            content: `hmac:${await hmac(digestKey, { domain: "txt-manifest-v1", value: record.content })}`,
          }
        : record,
    ),
  );
  const canonicalManifest = {
    ...manifest,
    records: protectedRecords.sort((a, b) =>
      a.key < b.key ? -1 : a.key > b.key ? 1 : 0,
    ),
    ...(manifest.prune_zones
      ? { prune_zones: [...manifest.prune_zones].sort() }
      : {}),
  };
  return hmac(digestKey, {
    domain: "manifest-v1",
    repositoryId,
    manifest: canonicalManifest,
  });
}
export async function buildPlan({
  manifest,
  state,
  policyRepository,
  repositoryId,
  digestKey,
}) {
  if (
    !manifest ||
    !state ||
    !policyRepository ||
    typeof repositoryId !== "string"
  )
    throw new FlareFormError("INVALID_RECORD");
  if (
    manifest.reconciliation === "prune" &&
    policyRepository.operations.allow_prune !== true
  )
    throw new FlareFormError("PRUNE_NOT_AUTHORIZED");
  const prune = manifest.reconciliation === "prune" ? state.prune : [];
  if (prune.length > MAX_PRUNE_DELETIONS)
    throw new FlareFormError("PRUNE_LIMIT_EXCEEDED");
  const changes = [];
  for (const entry of state.desired) {
    const { record, current } = entry;
    const to = desiredValue(record);
    const from = actualValue(current);
    const action = !current
      ? "create"
      : stable(to) === stable(from) &&
          record.ttl === current.ttl &&
          (record.proxied ?? false) === (current.proxied ?? false)
        ? "noop"
        : "update";
    changes.push({
      action,
      key: record.key,
      zone: record.zone,
      name: record.name,
      type: record.type,
      ...(current ? { from: safeValue(record.type, from) } : {}),
      to: safeValue(record.type, to),
    });
  }
  for (const entry of prune) {
    const { row, current } = entry;
    changes.push({
      action: "delete",
      key: row.client_key,
      zone: row.zone_name,
      name: row.name,
      type: row.type,
      from: safeValue(row.type, actualValue(current)),
    });
  }
  sortChanges(changes);
  const grouped = {};
  for (const change of changes) {
    const { zone, ...detail } = change;
    (grouped[zone] ??= []).push(detail);
  }
  // Keyed per-value commitments keep raw TXT out of the outer public digest
  // inputs. The inner HMAC necessarily reads the value to bind it safely.
  const manifestDigest = await digestManifest(
    manifest,
    repositoryId,
    digestKey,
  );
  const relevant = (
    await Promise.all(
      state.relevant.map(async (record) => ({
        zone: record.zone,
        id: record.id,
        name: record.name,
        type: record.type,
        content:
          record.type === "TXT" && typeof record.content === "string"
            ? `hmac:${await hmac(digestKey, { domain: "txt-state-v1", value: record.content })}`
            : record.content,
        data: record.data,
        ttl: record.ttl,
        proxied: record.proxied,
        tags: [...(record.tags ?? [])].sort(),
        comment: record.comment,
        modified_on: record.modified_on,
      })),
    )
  ).sort((a, b) => {
    const left = `${a.zone}\0${a.name}\0${a.type}\0${a.id}`;
    const right = `${b.zone}\0${b.name}\0${b.type}\0${b.id}`;
    return left < right ? -1 : left > right ? 1 : 0;
  });
  const dnsStateDigest = await hmac(digestKey, {
    domain: "dns-state-v1",
    repositoryId,
    relevant,
  });
  const zones = [
    ...new Set([
      ...manifest.records.map((record) => record.zone),
      ...(manifest.prune_zones ?? []),
    ]),
  ].sort();
  const zoneDigests = {};
  for (const zone of zones)
    zoneDigests[zone] = await hmac(digestKey, {
      domain: "dns-zone-state-v1",
      repositoryId,
      zone,
      relevant: relevant.filter((record) => record.zone === zone),
    });
  return {
    changes: grouped,
    manifestDigest,
    dnsStateDigest,
    zoneDigests,
    deletionCount: prune.length,
  };
}
