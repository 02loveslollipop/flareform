import { DnsRepository } from "../db/repository.js";
import { requireD1 } from "../db/connection.js";
import { assertRunIdentity, reserveApplyAdmission } from "../dns/admission.js";
import { executeZone } from "../dns/execute.js";
import { digestManifest } from "../dns/plan.js";
import {
  prepareManifestPolicy,
  prepareReconciliation,
} from "../dns/reconcile.js";
import { FlareFormError } from "../errors.js";

async function operationResponse(repo, operation, zones) {
  const rows = (await repo.listCheckpoints(operation.id)).results;
  const allZones = (await repo.listZones()).results;
  const byId = new Map(allZones.map((zone) => [zone.id, zone.name]));
  const statuses = {};
  for (const name of zones) {
    const row = rows.find((item) => byId.get(item.zone_id) === name);
    if (!row) throw new FlareFormError("STATE_INDETERMINATE");
    statuses[name] = {
      status: row.status,
      ...(row.error_code ? { error: row.error_code } : {}),
    };
  }
  const complete = Object.values(statuses).every(
    (item) => item.status === "success",
  );
  return new Response(
    JSON.stringify({
      operation_id: operation.id,
      status: complete ? "complete" : "partial_failure",
      zones: statuses,
      ...(!complete ? { error: { code: "PARTIAL_ZONE_FAILURE" } } : {}),
    }),
    {
      status: complete ? 200 : 502,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      },
    },
  );
}

export function createApplyHandler({ cloudflareFactory } = {}) {
  return async function apply({ body, claims, repository, env, signal, now }) {
    if (signal.aborted) throw new FlareFormError("REQUEST_TIMEOUT");
    assertRunIdentity(claims, repository);
    if (claims.exp <= Math.floor(now / 1000))
      throw new FlareFormError("TOKEN_EXPIRED");
    const db = await requireD1(env);
    const repo = new DnsRepository(db);
    const authorized = await prepareManifestPolicy({
      manifestSource: body.manifest,
      claims,
      repository,
      db,
    });
    const manifestDigest = await digestManifest(
      authorized.manifest,
      claims.repository_id,
      env.PLAN_HMAC_KEY,
    );
    const zones = [
      ...new Set([
        ...authorized.manifest.records.map((record) => record.zone),
        ...(authorized.manifest.prune_zones ?? []),
      ]),
    ].sort();
    const existing = await repo.findOperation({
      repositoryId: repository.id,
      githubRunId: claims.run_id,
      githubRunAttempt: claims.run_attempt,
      operationType: authorized.manifest.reconciliation,
      manifestSha256: manifestDigest,
    });
    if (existing && existing.policy_version !== authorized.version)
      throw new FlareFormError("PLAN_PRECONDITION_FAILED");
    if (
      existing &&
      ["complete", "running", "indeterminate"].includes(existing.status)
    ) {
      const priorPlan = await repo.getPlanAdmissionByOperation(existing.id);
      if (
        priorPlan?.plan_id !== (body.plan_id ?? undefined) &&
        (priorPlan || body.plan_id)
      )
        throw new FlareFormError("PLAN_PRECONDITION_FAILED");
      await repo.reserveOperation({
        operation: {
          repositoryId: repository.id,
          githubRunId: claims.run_id,
          githubRunAttempt: claims.run_attempt,
          operationType: authorized.manifest.reconciliation,
          manifestSha256: manifestDigest,
        },
        jti: claims.jti,
        jtiExpiresAt: claims.exp,
        now: new Date(now).toISOString(),
      });
      return operationResponse(repo, existing, zones);
    }
    const prepared = await prepareReconciliation({
      manifestSource: body.manifest,
      claims,
      repository,
      env,
      db,
      signal,
      cloudflareFactory,
      allowedOperationId: existing?.id ?? null,
      authorized,
    });
    const admitted = await reserveApplyAdmission({
      db,
      repository,
      claims,
      prepared,
      planId: body.plan_id,
      now,
    });
    await repo.startOperation(admitted.operation.id, repository.id);
    for (const zoneName of admitted.zones) {
      if (signal.aborted) throw new FlareFormError("REQUEST_TIMEOUT");
      const zone = await repo.getZone(zoneName);
      const checkpoint = await repo.getCheckpoint(
        admitted.operation.id,
        zone.id,
      );
      if (checkpoint.status === "success") continue;
      try {
        await executeZone({
          db,
          prepared,
          admitted,
          repository,
          claims,
          zoneName,
        });
      } catch (error) {
        const after = await repo.getCheckpoint(admitted.operation.id, zone.id);
        if (after.status !== "indeterminate") {
          try {
            await repo.markZoneFailed({
              operationId: admitted.operation.id,
              repositoryId: repository.id,
              zoneId: zone.id,
              zoneName,
              errorCode: error?.code,
              now: new Date().toISOString(),
            });
          } catch {
            await repo.freezeZone({
              operationId: admitted.operation.id,
              repositoryId: repository.id,
              zoneId: zone.id,
              zoneName,
              now: new Date().toISOString(),
            });
          }
        }
      }
    }
    const checkpoints = (await repo.listCheckpoints(admitted.operation.id))
      .results;
    const complete = checkpoints.every((item) => item.status === "success");
    const indeterminate = checkpoints.some(
      (item) => item.status === "indeterminate",
    );
    await repo.updateOperation({
      id: admitted.operation.id,
      repositoryId: repository.id,
      status: complete
        ? "complete"
        : indeterminate
          ? "indeterminate"
          : "partial",
      completedAt: complete ? new Date().toISOString() : null,
    });
    return operationResponse(repo, admitted.operation, admitted.zones);
  };
}
