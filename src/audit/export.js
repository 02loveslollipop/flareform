import { DnsRepository } from "../db/repository.js";
import { FlareFormError } from "../errors.js";

function projection(row) {
  return {
    version: 1,
    id: row.id,
    operation_id: row.operation_id,
    repository_id: row.repository_id,
    action: row.action,
    zone: row.zone,
    record_name: row.record_name,
    record_type: row.record_type,
    old_value: row.old_value,
    new_value: row.new_value,
    success: row.success,
    error_code: row.error_code,
    github_run_id: row.github_run_id,
    github_run_attempt: row.github_run_attempt,
    github_actor_id: row.github_actor_id,
    workflow_ref: row.workflow_ref,
    created_at: row.created_at,
  };
}

/** Export each event to an immutable key; a retry verifies, never overwrites. */
export async function exportAuditEvents({ db, bucket, now = Date.now() }) {
  if (
    !bucket ||
    typeof bucket.put !== "function" ||
    typeof bucket.get !== "function"
  )
    throw new FlareFormError("SERVICE_UNAVAILABLE");
  const repo = new DnsRepository(db);
  const rows = (await repo.listUnexportedAudit()).results;
  let exported = 0;
  for (const row of rows) {
    const key = `audit/v1/${String(row.id).padStart(20, "0")}.json`;
    const body = JSON.stringify(projection(row));
    let object;
    try {
      object = await bucket.put(key, body, {
        onlyIf: { etagDoesNotMatch: "*" },
        httpMetadata: { contentType: "application/json" },
        customMetadata: {
          auditId: String(row.id),
          schema: "flareform-audit-v1",
        },
      });
      if (object === null) {
        const existing = await bucket.get(key);
        if (!existing || typeof existing.text !== "function")
          throw new Error("existing audit object unreadable");
        if ((await existing.text()) !== body)
          throw new Error("existing audit object differs");
      }
      await repo.markAuditExported(row.id, key, new Date(now).toISOString());
      exported++;
    } catch {
      throw new FlareFormError("DATABASE_ERROR");
    }
  }
  return exported;
}
