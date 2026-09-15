import { createCloudflareClient } from "../dns/cloudflare.js";
import { prepareReconciliation } from "../dns/reconcile.js";
import { DnsRepository } from "../db/repository.js";
import { requireD1 } from "../db/connection.js";
import { FlareFormError } from "../errors.js";
import { createApplyHandler } from "./apply.js";

export function createPlanHandler({
  cloudflareFactory = createCloudflareClient,
} = {}) {
  const apply = createApplyHandler({ cloudflareFactory });
  return async function handlePublicRequest({
    route,
    body,
    claims,
    repository,
    env,
    signal,
    now,
  }) {
    if (route !== "/v1/plan" && route !== "/v1/apply")
      throw new FlareFormError("SERVICE_UNAVAILABLE");
    if (signal.aborted) throw new FlareFormError("REQUEST_TIMEOUT");
    if (route === "/v1/apply")
      return apply({ body, claims, repository, env, signal, now });
    const db = await requireD1(env);
    const { planned, version } = await prepareReconciliation({
      manifestSource: body.manifest,
      claims,
      repository,
      env,
      db,
      signal,
      cloudflareFactory,
    });
    const id = crypto.randomUUID();
    const expiresAt = Math.floor(now / 1000) + 300;
    try {
      await new DnsRepository(db).createPlan({
        id,
        repositoryId: repository.id,
        manifestSha256: planned.manifestDigest,
        policyVersion: version,
        dnsStateSha256: planned.dnsStateDigest,
        createdAt: new Date(now).toISOString(),
        expiresAt,
      });
    } catch {
      throw new FlareFormError("DATABASE_ERROR");
    }
    return new Response(
      JSON.stringify({
        operation: "plan",
        repository_id: claims.repository_id,
        changes: planned.changes,
        plan_id: id,
        manifest_digest: planned.manifestDigest,
        dns_state_fingerprint: planned.dnsStateDigest,
        policy_version: version,
        expires_at: new Date(expiresAt * 1000).toISOString(),
      }),
      {
        status: 200,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "no-store",
        },
      },
    );
  };
}

export const handlePublicRequest = createPlanHandler();
