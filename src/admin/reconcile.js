import { DnsRepository } from "../db/repository.js";
import { FlareFormError, redactRecordForAudit } from "../errors.js";
import { canonicalSrvData, managedMetadata } from "../dns/state.js";

function content(record) {
  return record?.type === "SRV"
    ? canonicalSrvData(record.data)
    : record?.content;
}
function exactMetadata(record, repositoryId, clientKey) {
  const expected = managedMetadata(repositoryId, clientKey);
  return (
    record &&
    record.comment === expected.comment &&
    Array.isArray(record.tags) &&
    record.tags.length === expected.tags.length &&
    expected.tags.every((tag) => record.tags.includes(tag))
  );
}

/** Non-public operator inspection. It never resolves or mutates by inference. */
export async function inspectIndeterminate({
  db,
  cloudflare,
  operationId,
  clientKey,
}) {
  const repo = new DnsRepository(db);
  const operation = await repo.getOperation(operationId);
  const intent = await repo.getMutationIntent(operationId, clientKey);
  if (
    !operation ||
    !intent ||
    !["sent", "indeterminate"].includes(intent.status)
  )
    throw new FlareFormError("STATE_INDETERMINATE");
  const repository = await repo.getRepositoryById(operation.repository_id);
  const zones = (await repo.listZones()).results;
  const zoneRow = zones.find((zone) => zone.id === intent.zone_id);
  if (!repository || !zoneRow || zoneRow.enabled !== 1)
    throw new FlareFormError("STATE_INDETERMINATE");
  const zone = {
    id: zoneRow.id,
    name: zoneRow.name,
    cloudflare_zone_id: zoneRow.cloudflare_zone_id,
    enabled: true,
  };
  const records = await cloudflare.listRecords(zone);
  const matching = records.filter(
    (record) =>
      record.name === intent.record_name && record.type === intent.record_type,
  );
  const exact = matching.filter((record) =>
    exactMetadata(record, repository.github_repository_id, clientKey),
  );
  const audits = (await repo.getMutationAudit(operationId, clientKey)).results;
  return {
    operation,
    intent,
    repository,
    zone,
    matching,
    exact,
    auditCount: audits.length,
    evidence: {
      action: intent.action,
      provider_matches: matching.map(redactRecordForAudit),
      exact_managed_matches: exact.map(redactRecordForAudit),
      audit_events: audits.map((row) => ({
        id: row.id,
        action: row.action,
        success: row.success,
        error_code: row.error_code,
        created_at: row.created_at,
      })),
    },
  };
}

export async function resolveIndeterminate({
  db,
  cloudflare,
  operationId,
  clientKey,
  decision,
  operatorId,
  now = Date.now(),
}) {
  if (
    !["confirm-provider", "confirm-no-change"].includes(decision) ||
    typeof operatorId !== "string" ||
    !/^[1-9][0-9]*$/.test(operatorId)
  )
    throw new FlareFormError("INVALID_REQUEST");
  const inspected = await inspectIndeterminate({
    db,
    cloudflare,
    operationId,
    clientKey,
  });
  const { intent, exact, matching, repository, zone } = inspected;
  let selected = null;
  if (decision === "confirm-provider") {
    if (intent.action === "delete") {
      if (matching.some((record) => record.id === intent.cloudflare_record_id))
        throw new FlareFormError("STATE_INDETERMINATE");
    } else {
      const candidates = exact.filter((record) =>
        intent.action === "update"
          ? record.id === intent.cloudflare_record_id
          : true,
      );
      if (candidates.length !== 1)
        throw new FlareFormError("STATE_INDETERMINATE");
      selected = candidates[0];
    }
  } else {
    if (intent.action === "create" && matching.length !== 0)
      throw new FlareFormError("STATE_INDETERMINATE");
    if (
      ["update", "delete"].includes(intent.action) &&
      !matching.some(
        (record) =>
          record.id === intent.cloudflare_record_id &&
          exactMetadata(record, repository.github_repository_id, clientKey),
      )
    )
      throw new FlareFormError("STATE_INDETERMINATE");
  }
  const repo = new DnsRepository(db);
  const claim = await repo.getClaim(
    zone.id,
    intent.record_name,
    intent.record_type,
  );
  if (!claim || claim.repository_id !== repository.id)
    throw new FlareFormError("STATE_INDETERMINATE");
  await repo.resolveMutationAdmin({
    operationId,
    repositoryId: repository.id,
    zoneId: zone.id,
    zoneName: zone.name,
    clientKey,
    decision,
    claimId: claim.id,
    cloudflareRecordId:
      intent.action === "delete"
        ? intent.cloudflare_record_id
        : (selected?.id ?? null),
    content: selected ? content(selected) : null,
    operatorId,
    now: new Date(now).toISOString(),
  });
  return { operationId, clientKey, decision, resolved: true };
}
