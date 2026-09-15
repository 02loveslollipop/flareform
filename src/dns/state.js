import { DnsRepository } from "../db/repository.js";
import { FlareFormError } from "../errors.js";

const COMPATIBLE_MULTI = new Set(["A", "AAAA", "SRV"]);
const ID = /^[0-9a-f]{32}$/;
function externalName(value) {
  if (typeof value !== "string" || !/^[a-z0-9_.-]{1,253}\.?$/i.test(value))
    throw new FlareFormError("CLOUDFLARE_API_ERROR");
  return value.toLowerCase().replace(/\.$/, "");
}
function identity(zone, name, type) {
  return `${zone}\0${name}\0${type}`;
}
export function managedMetadata(repositoryId, clientKey) {
  if (
    typeof repositoryId !== "string" ||
    !/^[1-9][0-9]*$/.test(repositoryId) ||
    typeof clientKey !== "string" ||
    !/^[a-z0-9][a-z0-9-]{0,63}$/.test(clientKey)
  )
    throw new FlareFormError("INVALID_RECORD");
  return {
    tags: [
      "managed-by:flareform",
      `repository-id:${repositoryId}`,
      `client-key:${clientKey}`,
    ],
    comment: `Managed by FlareForm for GitHub repository ${repositoryId}`,
  };
}
export function canonicalSrvData(data) {
  if (
    !data ||
    typeof data !== "object" ||
    !Number.isSafeInteger(data.priority) ||
    !Number.isSafeInteger(data.weight) ||
    !Number.isSafeInteger(data.port) ||
    typeof data.target !== "string"
  )
    throw new FlareFormError("STATE_INDETERMINATE");
  return JSON.stringify({
    priority: data.priority,
    weight: data.weight,
    port: data.port,
    target: data.target,
  });
}
export function verifyOwnership(row, external, repositoryId) {
  if (
    !row ||
    row.claim_repository_id !== row.repository_id ||
    row.repository_id === undefined ||
    !external ||
    !ID.test(row.cloudflare_record_id ?? "") ||
    external.id !== row.cloudflare_record_id
  )
    throw new FlareFormError("STATE_INDETERMINATE");
  if (row.claim_state !== "active")
    throw new FlareFormError("OPERATION_IN_PROGRESS");
  const expected = managedMetadata(repositoryId, row.client_key);
  if (
    !Array.isArray(external.tags) ||
    external.tags.length !== expected.tags.length ||
    expected.tags.some((tag) => !external.tags.includes(tag)) ||
    external.comment !== expected.comment ||
    externalName(external.name) !== row.name ||
    external.type !== row.type
  )
    throw new FlareFormError("STATE_INDETERMINATE");
  if (typeof row.content !== "string")
    throw new FlareFormError("STATE_INDETERMINATE");
  const actual =
    external.type === "SRV"
      ? canonicalSrvData(external.data)
      : external.content;
  if (actual !== row.content) throw new FlareFormError("STATE_INDETERMINATE");
  return true;
}

/** Complete read-only Cloudflare/D1 snapshot for all desired names and prune scope. */
export async function collectDnsState({
  manifest,
  policy,
  repository,
  db,
  cloudflare,
  allowedOperationId = null,
}) {
  if (!manifest || !policy || !repository || !db || !cloudflare)
    throw new FlareFormError("DATABASE_ERROR");
  const repositoryId = repository.github_repository_id;
  const repo = new DnsRepository(db);
  const ownedResult = await repo.listOwnedRecords(repository.id);
  const owned = ownedResult.results;
  const desiredNames = new Set(
    manifest.records.map((record) => `${record.zone}\0${record.name}`),
  );
  const desiredKeys = new Set(manifest.records.map((record) => record.key));
  const zones = [
    ...new Set([
      ...manifest.records.map((record) => record.zone),
      ...(manifest.prune_zones ?? []),
    ]),
  ].sort();
  const byZone = new Map();
  for (const zoneName of zones) {
    const zone = policy.zones.find(
      (candidate) => candidate.name === zoneName && candidate.enabled,
    );
    if (!zone) throw new FlareFormError("UNKNOWN_ZONE");
    const row = await repo.getZone(zoneName);
    if (
      !row ||
      row.enabled !== 1 ||
      row.cloudflare_zone_id !== zone.cloudflare_zone_id
    )
      throw new FlareFormError("DATABASE_ERROR");
    const records = await cloudflare.listRecords(zone);
    if (!Array.isArray(records))
      throw new FlareFormError("CLOUDFLARE_API_ERROR");
    byZone.set(zoneName, {
      zone,
      row,
      records: records.map((record) => ({
        ...record,
        name: externalName(record.name),
      })),
    });
  }
  const relevant = [];
  const desired = [];
  for (const record of manifest.records) {
    const state = byZone.get(record.zone);
    const matches = state.records.filter(
      (current) => current.name === record.name,
    );
    const sameType = matches.filter((current) => current.type === record.type);
    const lock = await repo.getOperationLock(
      state.row.id,
      record.name,
      record.type,
    );
    if (lock && lock.operation_id !== allowedOperationId)
      throw new FlareFormError("OPERATION_IN_PROGRESS");
    const claim = await repo.getClaim(state.row.id, record.name, record.type);
    if (claim && claim.repository_id !== repository.id)
      throw new FlareFormError("RECORD_OWNED_BY_OTHER_REPOSITORY");
    if (
      matches.some(
        (current) =>
          current.type === "NS" ||
          (current.type === "CNAME" && record.type !== "CNAME") ||
          (record.type === "CNAME" && current.type !== "CNAME"),
      )
    )
      throw new FlareFormError("DNS_CONFLICT");
    if (!claim && sameType.length > 0)
      throw new FlareFormError("RECORD_NOT_OWNED");
    const claimRows = owned.filter((row) => row.claim_id === claim?.id);
    const reservedByAllowedOperation =
      lock?.operation_id === allowedOperationId &&
      claim?.state === "reserved" &&
      claimRows.length === 0 &&
      sameType.length === 0;
    if (claim && claimRows.length === 0 && !reservedByAllowedOperation)
      throw new FlareFormError("STATE_INDETERMINATE");
    if (
      claim &&
      !reservedByAllowedOperation &&
      !COMPATIBLE_MULTI.has(record.type) &&
      (sameType.length !== 1 || claimRows.length !== 1)
    )
      throw new FlareFormError("DNS_CONFLICT");
    if (claim && sameType.length !== claimRows.length)
      throw new FlareFormError("STATE_INDETERMINATE");
    for (const row of claimRows)
      verifyOwnership(
        row,
        sameType.find((current) => current.id === row.cloudflare_record_id),
        repositoryId,
      );
    const managed = claimRows.find((row) => row.client_key === record.key);
    if (
      claim &&
      !managed &&
      !reservedByAllowedOperation &&
      !COMPATIBLE_MULTI.has(record.type)
    )
      throw new FlareFormError("DNS_CONFLICT");
    if (
      claim &&
      !managed &&
      sameType.some((current) =>
        record.type === "SRV"
          ? current.data?.target === record.target &&
            current.data?.priority === record.priority &&
            current.data?.weight === record.weight &&
            current.data?.port === record.port
          : current.content === record.content,
      )
    )
      throw new FlareFormError("DNS_CONFLICT");
    if (
      managed &&
      (managed.name !== record.name ||
        managed.type !== record.type ||
        managed.zone_name !== record.zone)
    )
      throw new FlareFormError("STATE_INDETERMINATE");
    if (!managed && owned.some((row) => row.client_key === record.key))
      throw new FlareFormError("STATE_INDETERMINATE");
    desired.push({
      record,
      claim,
      current: managed
        ? sameType.find((entry) => entry.id === managed.cloudflare_record_id)
        : null,
      zone: state.zone,
    });
    for (const current of matches)
      relevant.push({ zone: record.zone, ...current });
  }
  const prune = [];
  if (manifest.reconciliation === "prune")
    for (const row of owned) {
      if (
        !manifest.prune_zones.includes(row.zone_name) ||
        desiredKeys.has(row.client_key)
      )
        continue;
      const state = byZone.get(row.zone_name);
      const lock = await repo.getOperationLock(
        state.row.id,
        row.name,
        row.type,
      );
      if (lock && lock.operation_id !== allowedOperationId)
        throw new FlareFormError("OPERATION_IN_PROGRESS");
      const current = state.records.find(
        (entry) => entry.id === row.cloudflare_record_id,
      );
      const sameType = state.records.filter(
        (entry) => entry.name === row.name && entry.type === row.type,
      );
      const sameClaim = owned.filter(
        (entry) => entry.claim_id === row.claim_id,
      );
      if (sameType.length !== sameClaim.length)
        throw new FlareFormError("STATE_INDETERMINATE");
      verifyOwnership(row, current, repositoryId);
      prune.push({ row, current, zone: state.zone });
      if (!desiredNames.has(`${row.zone_name}\0${row.name}`))
        relevant.push({ zone: row.zone_name, ...current });
    }
  relevant.sort((a, b) => {
    const left = `${identity(a.zone, a.name, a.type)}\0${a.id}`;
    const right = `${identity(b.zone, b.name, b.type)}\0${b.id}`;
    return left < right ? -1 : left > right ? 1 : 0;
  });
  return { desired, prune, relevant, owned };
}
