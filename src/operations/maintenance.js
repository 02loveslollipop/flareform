import { auditOwnership, generateInventory } from "../admin/inventory.js";
import { FlareFormError } from "../errors.js";

function eventFromRow(row) {
  if (!row) return null;
  return {
    event: "scheduled_security_maintenance",
    success: row.success === 1,
    cleanup: { jtis: row.cleanup_jtis, plans: row.cleanup_plans },
    inventory_complete: row.inventory_complete === 1,
    ownership_complete: row.ownership_complete === 1,
    ownership_findings: row.ownership_findings,
    scheduled_at: row.scheduled_at,
  };
}

export async function readMaintenanceRun(db, scheduledAt) {
  try {
    return eventFromRow(
      await db
        .prepare("SELECT * FROM maintenance_runs WHERE scheduled_at = ?")
        .bind(scheduledAt)
        .first(),
    );
  } catch {
    throw new FlareFormError("DATABASE_ERROR");
  }
}

export async function storeMaintenanceRun(db, { event, inventory, ownership }) {
  const inventoryJson = JSON.stringify(inventory.zones);
  const findingsJson = JSON.stringify(ownership.findings);
  try {
    await db.batch([
      db
        .prepare(
          `INSERT INTO maintenance_runs(scheduled_at, cleanup_jtis, cleanup_plans,
           inventory_complete, ownership_complete, ownership_healthy,
           ownership_findings, success, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          event.scheduled_at,
          event.cleanup.jtis,
          event.cleanup.plans,
          event.inventory_complete ? 1 : 0,
          event.ownership_complete ? 1 : 0,
          ownership.healthy,
          event.ownership_findings,
          event.success ? 1 : 0,
          event.scheduled_at,
        ),
      db
        .prepare(
          `INSERT INTO inventory_zone_snapshots(maintenance_run_id, zone, complete, error_code)
           SELECT m.id, json_extract(z.value, '$.zone'),
             CASE json_extract(z.value, '$.complete') WHEN 1 THEN 1 ELSE 0 END,
             json_extract(z.value, '$.error')
           FROM maintenance_runs m, json_each(?) z
           WHERE m.scheduled_at = ?`,
        )
        .bind(inventoryJson, event.scheduled_at),
      db
        .prepare(
          `INSERT INTO inventory_record_snapshots(maintenance_run_id, zone,
           cloudflare_record_id, name, type, content_json, proxied, ttl, comment,
           tags_json, classification, service, github_repository,
           deployment_platform, mirrored_domain)
           SELECT m.id, json_extract(z.value, '$.zone'),
             json_extract(r.value, '$.cloudflare_record_id'),
             json_extract(r.value, '$.name'), json_extract(r.value, '$.type'),
             json_quote(json_extract(r.value, '$.content')),
             CASE json_extract(r.value, '$.proxied') WHEN 1 THEN 1 ELSE 0 END,
             json_extract(r.value, '$.ttl'), json_extract(r.value, '$.comment'),
             json_extract(r.value, '$.tags'),
             json_extract(r.value, '$.classification'),
             json_extract(r.value, '$.service'),
             json_extract(r.value, '$.github_repository'),
             json_extract(r.value, '$.deployment_platform'),
             json_extract(r.value, '$.mirrored_domain')
           FROM maintenance_runs m, json_each(?) z,
             json_each(z.value, '$.records') r
           WHERE m.scheduled_at = ?`,
        )
        .bind(inventoryJson, event.scheduled_at),
      db
        .prepare(
          `INSERT INTO ownership_findings(maintenance_run_id, finding, zone, name,
           type, repository_id, client_key, cloudflare_record_id, d1_row_id)
           SELECT m.id, json_extract(f.value, '$.finding'),
             json_extract(f.value, '$.zone'), json_extract(f.value, '$.name'),
             json_extract(f.value, '$.type'),
             json_extract(f.value, '$.repository_id'),
             json_extract(f.value, '$.client_key'),
             json_extract(f.value, '$.cloudflare_record_id'),
             json_extract(f.value, '$.d1_row_id')
           FROM maintenance_runs m, json_each(?) f
           WHERE m.scheduled_at = ?`,
        )
        .bind(findingsJson, event.scheduled_at),
    ]);
    return event;
  } catch {
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
  token,
  scheduledTime,
  cloudflareFactory,
  inventoryFactory = generateInventory,
  ownershipFactory = auditOwnership,
  emit = (event) => console.log(JSON.stringify(event)),
}) {
  if (!Number.isSafeInteger(scheduledTime) || scheduledTime < 0)
    throw new TypeError("Invalid scheduled time");
  const nowEpoch = Math.floor(scheduledTime / 1000);
  const scheduledAt = new Date(scheduledTime).toISOString();
  try {
    const prior = await readMaintenanceRun(db, scheduledAt);
    if (prior) {
      emit(prior);
      return prior;
    }
    const cleanup = await cleanupEphemeralState(db, nowEpoch);
    const inventory = await inventoryFactory({
      db,
      token,
      cloudflareFactory,
      now: scheduledTime,
    });
    const ownership = await ownershipFactory({
      db,
      token,
      cloudflareFactory,
      now: scheduledTime,
    });
    const event = {
      event: "scheduled_security_maintenance",
      success:
        inventory.complete &&
        ownership.complete &&
        ownership.findings.length === 0,
      cleanup,
      inventory_complete: inventory.complete,
      ownership_complete: ownership.complete,
      ownership_findings: ownership.findings.length,
      scheduled_at: scheduledAt,
    };
    try {
      await storeMaintenanceRun(db, { event, inventory, ownership });
    } catch {
      const concurrent = await readMaintenanceRun(db, scheduledAt);
      if (!concurrent) throw new FlareFormError("DATABASE_ERROR");
      emit(concurrent);
      return concurrent;
    }
    emit(event);
    return event;
  } catch (error) {
    emit({
      event: "scheduled_security_maintenance",
      success: false,
      error_code:
        error instanceof FlareFormError ? error.code : "INTERNAL_ERROR",
      scheduled_at: scheduledAt,
    });
    throw error;
  }
}
