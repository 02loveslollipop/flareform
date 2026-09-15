import { createCloudflareClient } from "../dns/cloudflare.js";
import { normalizeDnsName, normalizeSrvOwner } from "../dns/normalize.js";
import { canonicalSrvData, managedMetadata } from "../dns/state.js";
import { DnsRepository } from "../db/repository.js";
import { FlareFormError, redactRecordForAudit } from "../errors.js";
import { authorizeRecords } from "../policy/authorize.js";
import { readActivePolicy } from "../policy/storage.js";

const RECORD_ID = /^[0-9a-f]{32}$/;
const REPOSITORY_ID = /^[1-9][0-9]*$/;
const CLIENT_KEY = /^[a-z0-9][a-z0-9-]{0,63}$/;

function exactMetadata(record, expected) {
  return (
    record.comment === expected.comment &&
    Array.isArray(record.tags) &&
    record.tags.length === expected.tags.length &&
    expected.tags.every((tag) => record.tags.includes(tag))
  );
}

function hasFlareFormMetadata(record) {
  return (
    record.comment?.startsWith("Managed by FlareForm") ||
    record.tags?.some(
      (tag) =>
        tag === "managed-by:flareform" ||
        tag.startsWith("repository-id:") ||
        tag.startsWith("client-key:"),
    )
  );
}

function canonicalRecord(record) {
  const type = typeof record.type === "string" ? record.type.toUpperCase() : "";
  if (!["A", "AAAA", "CNAME", "SRV", "TXT"].includes(type))
    throw new FlareFormError("RECORD_TYPE_NOT_AUTHORIZED");
  let name;
  try {
    name =
      type === "SRV"
        ? normalizeSrvOwner(record.name)
        : normalizeDnsName(record.name);
  } catch {
    throw new FlareFormError("INVALID_RECORD");
  }
  const content =
    type === "SRV"
      ? canonicalSrvData(record.data)
      : typeof record.content === "string"
        ? record.content
        : null;
  if (content === null) throw new FlareFormError("INVALID_RECORD");
  return { ...record, type, name, content };
}

function mutationRecord(record, metadata) {
  const base = {
    type: record.type,
    name: record.name,
    ttl: record.ttl,
    tags: metadata.tags,
    comment: metadata.comment,
  };
  return record.type === "SRV"
    ? { ...base, data: record.data }
    : {
        ...base,
        content: record.content,
        ...(["A", "AAAA", "CNAME"].includes(record.type)
          ? { proxied: record.proxied === true }
          : {}),
      };
}

export async function prepareAdoption({
  db,
  repositoryId,
  clientKey,
  zoneName,
  cloudflareRecordId,
  token,
  cloudflareFactory = createCloudflareClient,
}) {
  if (
    !REPOSITORY_ID.test(repositoryId ?? "") ||
    !CLIENT_KEY.test(clientKey ?? "") ||
    !RECORD_ID.test(cloudflareRecordId ?? "") ||
    typeof zoneName !== "string"
  )
    throw new FlareFormError("INVALID_RECORD");
  let canonicalZone;
  try {
    canonicalZone = normalizeDnsName(zoneName);
  } catch {
    throw new FlareFormError("UNKNOWN_ZONE");
  }
  const repo = new DnsRepository(db);
  const repository = await repo.getRepository(repositoryId);
  if (!repository) throw new FlareFormError("UNKNOWN_REPOSITORY");
  if (repository.enabled !== 1) throw new FlareFormError("REPOSITORY_DISABLED");
  const zone = await repo.getZone(canonicalZone);
  if (!zone) throw new FlareFormError("UNKNOWN_ZONE");
  if (zone.enabled !== 1) throw new FlareFormError("ZONE_DISABLED");
  const { policy } = await readActivePolicy(db);
  const trustedZone = policy.zones.find(
    (candidate) =>
      candidate.name === canonicalZone &&
      candidate.enabled &&
      candidate.cloudflare_zone_id === zone.cloudflare_zone_id,
  );
  if (!trustedZone) throw new FlareFormError("UNKNOWN_ZONE");
  const cloudflare = cloudflareFactory({ token });
  const records = await cloudflare.listRecords(trustedZone);
  const matches = records.filter((record) => record.id === cloudflareRecordId);
  if (matches.length !== 1) throw new FlareFormError("INVALID_RECORD");
  const record = canonicalRecord(matches[0]);
  authorizeRecords(
    policy,
    repositoryId,
    [{ name: record.name, type: record.type }],
    { operation: "apply" },
  );
  const selectedZone = policy.zones
    .filter(
      (candidate) =>
        record.name === candidate.name ||
        record.name.endsWith(`.${candidate.name}`),
    )
    .sort((a, b) => b.name.length - a.name.length)[0];
  if (selectedZone?.name !== canonicalZone)
    throw new FlareFormError("UNKNOWN_ZONE");

  const expected = managedMetadata(repositoryId, clientKey);
  const metadataMatches = exactMetadata(record, expected);
  if (hasFlareFormMetadata(record) && !metadataMatches)
    throw new FlareFormError("RECORD_OWNED_BY_OTHER_REPOSITORY");
  const existingKey = await repo.getManagedRecord(repository.id, clientKey);
  if (
    existingKey &&
    (existingKey.zone_id !== zone.id ||
      existingKey.cloudflare_record_id !== cloudflareRecordId)
  )
    throw new FlareFormError("DNS_CONFLICT");
  const existingRecord = await repo
    .statement(
      "SELECT * FROM managed_records WHERE zone_id = ? AND cloudflare_record_id = ?",
      zone.id,
      cloudflareRecordId,
    )
    .first();
  if (existingRecord && existingRecord.repository_id !== repository.id)
    throw new FlareFormError("RECORD_OWNED_BY_OTHER_REPOSITORY");
  if (existingRecord && existingRecord.client_key !== clientKey)
    throw new FlareFormError("STATE_INDETERMINATE");
  const claim = await repo.getClaim(zone.id, record.name, record.type);
  if (claim && claim.repository_id !== repository.id)
    throw new FlareFormError("RECORD_OWNED_BY_OTHER_REPOSITORY");
  if (claim && claim.state !== "active")
    throw new FlareFormError("OPERATION_IN_PROGRESS");
  if (claim && !existingKey && !metadataMatches)
    throw new FlareFormError("RECORD_OWNED_BY_OTHER_REPOSITORY");

  return {
    repository,
    zone,
    trustedZone,
    record,
    claim,
    existingKey,
    metadataMatches,
    cloudflare,
    metadata: expected,
    dryRun: {
      repository_id: repositoryId,
      client_key: clientKey,
      zone: canonicalZone,
      cloudflare_record_id: cloudflareRecordId,
      name: record.name,
      type: record.type,
      current: redactRecordForAudit(record),
      metadata_change: !metadataMatches,
      database_change: !existingKey,
    },
  };
}

export async function adoptRecord(options) {
  const prepared = await prepareAdoption(options);
  if (options.apply !== true) return prepared.dryRun;
  const repo = new DnsRepository(options.db);
  const now = new Date(options.now ?? Date.now()).toISOString();
  if (prepared.existingKey) {
    if (
      !prepared.metadataMatches ||
      !prepared.claim ||
      prepared.existingKey.record_claim_id !== prepared.claim.id ||
      prepared.existingKey.content !== prepared.record.content
    )
      throw new FlareFormError("STATE_INDETERMINATE");
    return { ...prepared.dryRun, adopted: true, idempotent: true };
  }
  try {
    await repo.appendAudit({
      repositoryId: prepared.repository.id,
      action: "adoption_intent",
      zone: prepared.zone.name,
      recordName: prepared.record.name,
      recordType: prepared.record.type,
      success: false,
      now,
    });
  } catch {
    throw new FlareFormError("DATABASE_ERROR");
  }
  if (!prepared.metadataMatches) {
    try {
      await prepared.cloudflare.patch(
        prepared.trustedZone,
        prepared.record.id,
        mutationRecord(prepared.record, prepared.metadata),
      );
    } catch {
      await repo
        .appendAudit({
          repositoryId: prepared.repository.id,
          action: "adoption_metadata_failed",
          zone: prepared.zone.name,
          recordName: prepared.record.name,
          recordType: prepared.record.type,
          success: false,
          errorCode: "CLOUDFLARE_API_ERROR",
          now,
        })
        .catch(() => {});
      throw new FlareFormError("CLOUDFLARE_API_ERROR");
    }
  }
  const statements = [];
  if (!prepared.claim)
    statements.push(
      repo.statement(
        `INSERT INTO record_claims(repository_id, zone_id, name, type, state,
         version, created_at, updated_at) VALUES (?, ?, ?, ?, 'active', 1, ?, ?)`,
        prepared.repository.id,
        prepared.zone.id,
        prepared.record.name,
        prepared.record.type,
        now,
        now,
      ),
    );
  statements.push(
    repo.statement(
      `INSERT INTO managed_records(repository_id, record_claim_id, zone_id,
       client_key, cloudflare_record_id, content, created_at, updated_at)
       SELECT ?, rc.id, ?, ?, ?, ?, ?, ? FROM record_claims rc
       WHERE rc.repository_id = ? AND rc.zone_id = ? AND rc.name = ? AND rc.type = ?
       AND rc.state = 'active'`,
      prepared.repository.id,
      prepared.zone.id,
      options.clientKey,
      prepared.record.id,
      prepared.record.content,
      now,
      now,
      prepared.repository.id,
      prepared.zone.id,
      prepared.record.name,
      prepared.record.type,
    ),
    repo.statement(
      `INSERT INTO audit_log(repository_id, action, zone, record_name,
       record_type, old_value, new_value, success, created_at)
       VALUES (?, 'record_adopted', ?, ?, ?, ?, ?, 1, ?)`,
      prepared.repository.id,
      prepared.zone.name,
      prepared.record.name,
      prepared.record.type,
      JSON.stringify(redactRecordForAudit(prepared.record)),
      JSON.stringify(
        redactRecordForAudit(
          mutationRecord(prepared.record, prepared.metadata),
        ),
      ),
      now,
    ),
  );
  try {
    await options.db.batch(statements);
  } catch {
    await repo
      .appendAudit({
        repositoryId: prepared.repository.id,
        action: "adoption_database_failed",
        zone: prepared.zone.name,
        recordName: prepared.record.name,
        recordType: prepared.record.type,
        success: false,
        errorCode: "DATABASE_ERROR",
        now,
      })
      .catch(() => {});
    throw new FlareFormError("STATE_INDETERMINATE");
  }
  const adopted = await repo.getManagedRecord(
    prepared.repository.id,
    options.clientKey,
  );
  if (
    !adopted ||
    adopted.zone_id !== prepared.zone.id ||
    adopted.cloudflare_record_id !== prepared.record.id
  )
    throw new FlareFormError("STATE_INDETERMINATE");
  return { ...prepared.dryRun, adopted: true, idempotent: false };
}
