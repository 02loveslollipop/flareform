import { DnsRepository } from "../db/repository.js";
import { FlareFormError } from "../errors.js";

const GITHUB_ID = /^[1-9][0-9]*$/;
export function assertRunIdentity(claims, repository) {
  if (
    !claims ||
    claims.repository_id !== repository.github_repository_id ||
    typeof claims.run_id !== "string" ||
    !GITHUB_ID.test(claims.run_id ?? "") ||
    typeof claims.run_attempt !== "string" ||
    !GITHUB_ID.test(claims.run_attempt ?? "") ||
    typeof claims.actor_id !== "string" ||
    !GITHUB_ID.test(claims.actor_id ?? "") ||
    typeof claims.jti !== "string" ||
    claims.jti.length < 1 ||
    claims.jti.length > 512 ||
    !Number.isSafeInteger(claims.exp)
  )
    throw new FlareFormError("INVALID_TOKEN");
}

/** Admission performs no DNS call. The D1 batch is the last gate before execution. */
export async function reserveApplyAdmission({
  db,
  repository,
  claims,
  prepared,
  planId,
  now = Date.now(),
}) {
  assertRunIdentity(claims, repository);
  if (!prepared?.manifest || !prepared?.state || !prepared?.planned)
    throw new FlareFormError("SERVICE_UNAVAILABLE");
  const repo = new DnsRepository(db);
  const nowEpoch = Math.floor(now / 1000);
  if (!Number.isSafeInteger(nowEpoch) || claims.exp <= nowEpoch)
    throw new FlareFormError("TOKEN_EXPIRED");
  const zones = [
    ...new Set([
      ...prepared.manifest.records.map((record) => record.zone),
      ...(prepared.manifest.prune_zones ?? []),
    ]),
  ].sort();
  const existing = await repo.findOperation({
    repositoryId: repository.id,
    githubRunId: claims.run_id,
    githubRunAttempt: claims.run_attempt,
    operationType: prepared.manifest.reconciliation,
    manifestSha256: prepared.planned.manifestDigest,
  });
  if (existing) {
    if (existing.policy_version !== prepared.version)
      throw new FlareFormError("PLAN_PRECONDITION_FAILED");
    const priorPlan = await repo.getPlanAdmissionByOperation(existing.id);
    if (priorPlan?.plan_id !== (planId ?? undefined) && (priorPlan || planId))
      throw new FlareFormError("PLAN_PRECONDITION_FAILED");
    for (const name of zones) {
      const zone = await repo.getZone(name);
      const checkpoint = zone
        ? await repo.getCheckpoint(existing.id, zone.id)
        : null;
      if (!checkpoint) throw new FlareFormError("STATE_INDETERMINATE");
      if (
        checkpoint.status !== "success" &&
        checkpoint.dns_state_sha256 !==
          (prepared.planned.zoneDigests?.[name] ?? null)
      )
        throw new FlareFormError("PLAN_PRECONDITION_FAILED");
    }
    const admitted = await repo.reserveOperation({
      operation: {
        repositoryId: repository.id,
        githubRunId: claims.run_id,
        githubRunAttempt: claims.run_attempt,
        operationType: prepared.manifest.reconciliation,
        manifestSha256: prepared.planned.manifestDigest,
      },
      jti: claims.jti,
      jtiExpiresAt: claims.exp,
      now: new Date(now).toISOString(),
    });
    return { ...admitted, zones };
  }
  const needsPlan = prepared.planned.deletionCount > 0;
  if (needsPlan && !planId)
    throw new FlareFormError("PLAN_PRECONDITION_FAILED");
  if (!needsPlan && planId) throw new FlareFormError("INVALID_REQUEST");
  let plan = null;
  if (needsPlan) {
    const artifact = await repo.getActivePlan(planId, repository.id, nowEpoch);
    if (
      !artifact ||
      artifact.manifest_sha256 !== prepared.planned.manifestDigest ||
      artifact.policy_version !== prepared.version ||
      artifact.dns_state_sha256 !== prepared.planned.dnsStateDigest
    )
      throw new FlareFormError("PLAN_PRECONDITION_FAILED");
    plan = {
      id: planId,
      policyVersion: prepared.version,
      dnsStateSha256: prepared.planned.dnsStateDigest,
    };
  }
  const zoneRows = new Map();
  for (const name of zones) {
    const trusted = prepared.policy.zones.find(
      (zone) => zone.name === name && zone.enabled,
    );
    const row = await repo.getZone(name);
    if (
      !trusted ||
      !row ||
      row.enabled !== 1 ||
      row.cloudflare_zone_id !== trusted.cloudflare_zone_id
    )
      throw new FlareFormError("UNKNOWN_ZONE");
    zoneRows.set(name, row);
  }
  const affected = [
    ...prepared.state.desired.map(({ record }) => ({
      zoneId: zoneRows.get(record.zone).id,
      name: record.name,
      type: record.type,
    })),
    ...prepared.state.prune.map(({ row }) => ({
      zoneId: zoneRows.get(row.zone_name).id,
      name: row.name,
      type: row.type,
    })),
  ];
  const newClaims = prepared.state.desired
    .filter(({ claim }) => !claim)
    .map(({ record }) => ({
      zoneId: zoneRows.get(record.zone).id,
      name: record.name,
      type: record.type,
    }));
  const unique = (items) => [
    ...new Map(
      items.map((item) => [`${item.zoneId}\0${item.name}\0${item.type}`, item]),
    ).values(),
  ];
  const operation = {
    id: `ffop_${crypto.randomUUID().replaceAll("-", "")}`,
    repositoryId: repository.id,
    githubRunId: claims.run_id,
    githubRunAttempt: claims.run_attempt,
    operationType: prepared.manifest.reconciliation,
    manifestSha256: prepared.planned.manifestDigest,
    policyVersion: prepared.version,
  };
  const admitted = await repo.reserveOperation({
    operation,
    jti: claims.jti,
    jtiExpiresAt: claims.exp,
    claims: unique(newClaims),
    locks: unique(affected),
    zoneIds: [...zoneRows.values()].map((row) => row.id),
    zoneFingerprints: Object.fromEntries(
      [...zoneRows].map(([name, row]) => [
        row.id,
        prepared.planned.zoneDigests?.[name] ?? null,
      ]),
    ),
    plan,
    now: new Date(now).toISOString(),
    nowEpoch,
  });
  return { ...admitted, zones };
}
