import { createCloudflareClient } from "./cloudflare.js";
import { parseManifest } from "./manifest.js";
import { buildPlan } from "./plan.js";
import { collectDnsState } from "./state.js";
import { FlareFormError } from "../errors.js";
import { authorizeRecords } from "../policy/authorize.js";
import { readActivePolicy } from "../policy/storage.js";

export async function prepareManifestPolicy({
  manifestSource,
  claims,
  repository,
  db,
}) {
  const { policy, version } = await readActivePolicy(db);
  const policyRepository = policy.repositories.find(
    (candidate) => candidate.github.repository_id === claims.repository_id,
  );
  if (
    !policyRepository ||
    !policyRepository.enabled ||
    policyRepository.github.owner_id !== claims.repository_owner_id ||
    repository.github_owner_id !== claims.repository_owner_id
  )
    throw new FlareFormError("UNKNOWN_REPOSITORY");
  const allowTxt = policyRepository.grants.some((grant) =>
    grant.record_types.includes("TXT"),
  );
  const manifest = parseManifest(manifestSource, policy.zones, { allowTxt });
  authorizeRecords(policy, claims.repository_id, manifest.records, {
    operation: manifest.reconciliation === "prune" ? "prune" : "plan",
    prune: manifest.reconciliation === "prune",
  });
  return { manifest, policy, policyRepository, version };
}

// The single read-only state/diff preflight used by both plan and apply. No D1
// ownership or Cloudflare mutation can occur until this entire check passes.
export async function prepareReconciliation({
  manifestSource,
  claims,
  repository,
  env,
  db,
  signal,
  cloudflareFactory = createCloudflareClient,
  allowedOperationId = null,
  authorized = null,
}) {
  const { manifest, policy, policyRepository, version } =
    authorized ??
    (await prepareManifestPolicy({
      manifestSource,
      claims,
      repository,
      db,
    }));
  if (
    typeof env?.CLOUDFLARE_DNS_TOKEN !== "string" ||
    typeof env?.PLAN_HMAC_KEY !== "string"
  )
    throw new FlareFormError("SERVICE_UNAVAILABLE");
  const cloudflare = cloudflareFactory({ token: env.CLOUDFLARE_DNS_TOKEN });
  const state = await collectDnsState({
    manifest,
    policy,
    repository,
    db,
    cloudflare,
    allowedOperationId,
  });
  if (state.prune.length)
    authorizeRecords(
      policy,
      claims.repository_id,
      state.prune.map(({ row }) => ({ name: row.name, type: row.type })),
      { operation: "prune", prune: true },
    );
  if (signal.aborted) throw new FlareFormError("REQUEST_TIMEOUT");
  const planned = await buildPlan({
    manifest,
    state,
    policyRepository,
    repositoryId: claims.repository_id,
    digestKey: env.PLAN_HMAC_KEY,
  });
  return {
    manifest,
    policy,
    policyRepository,
    version,
    state,
    planned,
    cloudflare,
  };
}
