import { DnsRepository } from "../db/repository.js";
import { FlareFormError } from "../errors.js";
import { assertCurrentRecordSet } from "./preflight.js";
import { canonicalSrvData, managedMetadata } from "./state.js";

function mutationRecord(record, repositoryId) {
  const metadata = managedMetadata(repositoryId, record.key);
  return {
    ...record,
    ...metadata,
    ...(record.type === "SRV"
      ? {
          data: {
            priority: record.priority,
            weight: record.weight,
            port: record.port,
            target: record.target,
          },
        }
      : {}),
  };
}
function storedContent(record) {
  return record.type === "SRV" ? canonicalSrvData(record.data) : record.content;
}

// Each provider request has its own durable intent and D1 confirmation. A
// zone batch would obscure which record succeeded after a partial/uncertain
// response, so batching is not appropriate for this fail-closed executor.
/** A confirmed intent is never sent again; a sent intent is never retried. */
export async function executeZone({
  db,
  prepared,
  admitted,
  repository,
  claims,
  zoneName,
  now = () => Date.now(),
}) {
  const repo = new DnsRepository(db);
  const zone = prepared.policy.zones.find(
    (item) => item.name === zoneName && item.enabled,
  );
  const zoneRow = await repo.getZone(zoneName);
  if (
    !zone ||
    !zoneRow ||
    zoneRow.enabled !== 1 ||
    zoneRow.cloudflare_zone_id !== zone.cloudflare_zone_id
  )
    throw new FlareFormError("UNKNOWN_ZONE");
  const checkpoint = await repo.getCheckpoint(
    admitted.operation.id,
    zoneRow.id,
  );
  if (!checkpoint) throw new FlareFormError("STATE_INDETERMINATE");
  if (checkpoint.status === "success")
    return { zone: zoneName, status: "success" };
  if (checkpoint.status !== "pending" && checkpoint.status !== "failed")
    throw new FlareFormError("STATE_INDETERMINATE");
  const entries = prepared.planned.changes[zoneName] ?? [];
  for (const change of entries) {
    if (change.action === "noop") continue;
    const intent = await repo.getMutationIntent(
      admitted.operation.id,
      change.key,
    );
    if (intent?.status === "confirmed") continue;
    if (intent) throw new FlareFormError("STATE_INDETERMINATE");
    const desired = prepared.state.desired.find(
      (entry) => entry.record.key === change.key,
    );
    const pruning = prepared.state.prune.find(
      (entry) => entry.row.client_key === change.key,
    );
    const record = desired?.record ?? pruning?.current;
    const expectedCurrent = desired?.current ?? pruning?.current ?? null;
    if (!record || record.name !== change.name || record.type !== change.type)
      throw new FlareFormError("STATE_INDETERMINATE");
    const owned = (await repo.listOwnedRecords(repository.id)).results;
    const current = await assertCurrentRecordSet({
      cloudflare: prepared.cloudflare,
      zone,
      record,
      ownedRows: owned,
      repositoryId: claims.repository_id,
      expectedCurrent,
    });
    if (change.action !== "create" && !current)
      throw new FlareFormError("STATE_INDETERMINATE");
    if (change.action === "create" && current)
      throw new FlareFormError("STATE_INDETERMINATE");
    const claim = await repo.getClaim(zoneRow.id, record.name, record.type);
    if (!claim || claim.repository_id !== repository.id)
      throw new FlareFormError("STATE_INDETERMINATE");
    const payload = desired
      ? mutationRecord(record, claims.repository_id)
      : null;
    const context = {
      operationId: admitted.operation.id,
      repositoryId: repository.id,
      zoneId: zoneRow.id,
      zoneName,
      clientKey: change.key,
      recordName: record.name,
      recordType: record.type,
      action: change.action,
      cloudflareRecordId: current?.id ?? null,
      oldRecord: current,
      newRecord: payload,
      githubRunId: claims.run_id,
      githubRunAttempt: claims.run_attempt,
      githubActorId: claims.actor_id,
      workflowRef: claims.workflow_ref,
      now: new Date(now()).toISOString(),
    };
    await repo.beginMutationIntent(context);
    await repo.markMutationSent(
      admitted.operation.id,
      change.key,
      new Date(now()).toISOString(),
    );
    try {
      const result =
        change.action === "create"
          ? await prepared.cloudflare.create(zone, payload)
          : change.action === "update"
            ? await prepared.cloudflare.patch(zone, current.id, payload)
            : await prepared.cloudflare.delete(zone, current.id);
      if (!result || typeof result.id !== "string")
        throw new FlareFormError("CLOUDFLARE_API_ERROR");
      if (change.action !== "create" && result.id !== current.id)
        throw new FlareFormError("CLOUDFLARE_API_ERROR");
      await repo.confirmMutation({
        ...context,
        claimId: claim.id,
        cloudflareRecordId: result.id,
        content: change.action === "delete" ? null : storedContent(record),
        now: new Date(now()).toISOString(),
      });
    } catch (error) {
      await repo.markMutationIndeterminate({
        ...context,
        errorCode: error?.code,
        now: new Date(now()).toISOString(),
      });
      throw new FlareFormError("STATE_INDETERMINATE");
    }
  }
  await repo.finishZone({
    operationId: admitted.operation.id,
    repositoryId: repository.id,
    zoneId: zoneRow.id,
    zoneName,
    now: new Date(now()).toISOString(),
  });
  return { zone: zoneName, status: "success" };
}
