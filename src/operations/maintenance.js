import { exportAuditEvents } from "../audit/export.js";
import { auditOwnership, generateInventory } from "../admin/inventory.js";
import { FlareFormError } from "../errors.js";

function requireArchive(bucket) {
  if (
    !bucket ||
    typeof bucket.put !== "function" ||
    typeof bucket.get !== "function"
  )
    throw new FlareFormError("SERVICE_UNAVAILABLE");
}

async function putImmutable(bucket, key, value, schema) {
  const body = JSON.stringify(value);
  const written = await bucket.put(key, body, {
    onlyIf: { etagDoesNotMatch: "*" },
    httpMetadata: { contentType: "application/json" },
    customMetadata: { schema },
  });
  if (written === null) {
    const existing = await bucket.get(key);
    if (
      !existing ||
      typeof existing.text !== "function" ||
      (await existing.text()) !== body
    )
      throw new FlareFormError("DATABASE_ERROR");
  }
}

export async function cleanupEphemeralState(db, nowEpoch) {
  if (!Number.isSafeInteger(nowEpoch) || nowEpoch < 0)
    throw new TypeError("Invalid cleanup time");
  try {
    const [jtis, plans] = await db.batch([
      db.prepare("DELETE FROM oidc_jti WHERE expires_at < ?").bind(nowEpoch),
      db
        .prepare(
          `DELETE FROM plans WHERE expires_at < ?
           AND NOT EXISTS (SELECT 1 FROM plan_admissions pa WHERE pa.plan_id = plans.id)`,
        )
        .bind(nowEpoch),
    ]);
    return {
      jtis: Number(jtis.meta?.changes ?? jtis.changes ?? 0),
      plans: Number(plans.meta?.changes ?? plans.changes ?? 0),
    };
  } catch {
    throw new FlareFormError("DATABASE_ERROR");
  }
}

export async function runScheduledMaintenance({
  db,
  bucket,
  token,
  scheduledTime,
  cloudflareFactory,
  emit = (event) => console.log(JSON.stringify(event)),
}) {
  requireArchive(bucket);
  if (!Number.isSafeInteger(scheduledTime) || scheduledTime < 0)
    throw new TypeError("Invalid scheduled time");
  const nowEpoch = Math.floor(scheduledTime / 1000);
  const stamp = new Date(scheduledTime).toISOString().replaceAll(":", "-");
  try {
    const cleanup = await cleanupEphemeralState(db, nowEpoch);
    const audits = await exportAuditEvents({ db, bucket, now: scheduledTime });
    const inventory = await generateInventory({
      db,
      token,
      cloudflareFactory,
      now: scheduledTime,
    });
    const ownership = await auditOwnership({
      db,
      token,
      cloudflareFactory,
      now: scheduledTime,
    });
    await putImmutable(
      bucket,
      `inventory/v1/${stamp}.json`,
      inventory,
      "flareform-inventory-v1",
    );
    await putImmutable(
      bucket,
      `ownership/v1/${stamp}.json`,
      ownership,
      "flareform-ownership-v1",
    );
    const event = {
      event: "scheduled_security_maintenance",
      success:
        inventory.complete &&
        ownership.complete &&
        ownership.findings.length === 0,
      cleanup,
      audit_exports: audits,
      inventory_complete: inventory.complete,
      ownership_complete: ownership.complete,
      ownership_findings: ownership.findings.length,
      scheduled_at: new Date(scheduledTime).toISOString(),
    };
    emit(event);
    return event;
  } catch (error) {
    emit({
      event: "scheduled_security_maintenance",
      success: false,
      error_code:
        error instanceof FlareFormError ? error.code : "INTERNAL_ERROR",
      scheduled_at: new Date(scheduledTime).toISOString(),
    });
    throw error;
  }
}
