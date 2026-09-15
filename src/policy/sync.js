import { createHash } from "node:crypto";
import { validatePolicy } from "./config.js";

export function policyVersion(policy) {
  return createHash("sha256").update(JSON.stringify(policy)).digest("hex");
}

function statement(db, sql, ...values) {
  return db.prepare(sql).bind(...values);
}

/** One D1 transaction; old policy remains active on any failed statement. */
export async function syncPolicy(db, policy, now = new Date().toISOString()) {
  if (!db || typeof db.batch !== "function" || typeof db.prepare !== "function")
    throw new TypeError("D1 database required");
  // Revalidate here too: no caller can bypass overlap checks by passing a
  // hand-built canonical object directly to the write layer.
  const reconstructed = policy.repositories.map((repo) => ({
    github: repo.github,
    oidc: {
      ...repo.oidc,
      job_workflow_ref: repo.oidc.job_workflow_ref ?? undefined,
    },
    operations: repo.operations,
    enabled: repo.enabled,
    grants: repo.grants.map((grant) => ({
      zone: grant.zone,
      [grant.kind]: [grant.root],
      record_types: grant.record_types,
    })),
  }));
  const validated = validatePolicy({ zones: policy.zones }, reconstructed);
  if (JSON.stringify(validated) !== JSON.stringify(policy))
    throw new TypeError("Noncanonical policy");
  const canonicalJson = JSON.stringify(validated);
  const version = policyVersion(policy);
  const previous = await statement(
    db,
    "SELECT current_version FROM policy_state WHERE id = 1",
  ).first();
  if (previous?.current_version === version) return { version, changed: false };

  const statements = [
    statement(
      db,
      "INSERT OR IGNORE INTO policy_versions(version, canonical_json, applied_at) VALUES (?, ?, ?)",
      version,
      canonicalJson,
      now,
    ),
    statement(db, "UPDATE zones SET enabled = 0"),
    statement(db, "UPDATE repositories SET enabled = 0, updated_at = ?", now),
  ];
  for (const zone of policy.zones) {
    statements.push(
      statement(
        db,
        `INSERT INTO zones(name, cloudflare_zone_id, enabled, created_at) VALUES (?, ?, ?, ?)
       ON CONFLICT(name) DO UPDATE SET cloudflare_zone_id = excluded.cloudflare_zone_id,
       enabled = excluded.enabled`,
        zone.name,
        zone.cloudflare_zone_id,
        zone.enabled ? 1 : 0,
        now,
      ),
    );
  }
  for (const repo of policy.repositories) {
    const { github, oidc, operations, enabled } = repo;
    statements.push(
      statement(
        db,
        `INSERT INTO repositories(github_repository_id, github_owner_id, display_name,
       expected_workflow_ref, expected_job_workflow_ref, allowed_ref,
       allowed_environment, allowed_event, allowed_runner_environment,
       allow_prune, enabled, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(github_repository_id) DO UPDATE SET
       github_owner_id = excluded.github_owner_id,
       display_name = excluded.display_name,
       expected_workflow_ref = excluded.expected_workflow_ref,
       expected_job_workflow_ref = excluded.expected_job_workflow_ref,
       allowed_ref = excluded.allowed_ref,
       allowed_environment = excluded.allowed_environment,
       allowed_event = excluded.allowed_event,
       allowed_runner_environment = excluded.allowed_runner_environment,
       allow_prune = excluded.allow_prune,
       enabled = excluded.enabled, updated_at = excluded.updated_at`,
        github.repository_id,
        github.owner_id,
        github.display_name,
        oidc.workflow_ref,
        oidc.job_workflow_ref,
        oidc.ref,
        oidc.environment,
        oidc.event,
        oidc.runner_environment,
        operations.allow_prune ? 1 : 0,
        enabled ? 1 : 0,
        now,
        now,
      ),
    );
  }
  statements.push(statement(db, "DELETE FROM repository_grants"));
  for (const repo of policy.repositories) {
    for (const grant of repo.grants) {
      statements.push(
        statement(
          db,
          `INSERT INTO repository_grants(repository_id, zone_id, grant_kind, hostname_root,
         allow_a, allow_aaaa, allow_cname, allow_srv, allow_txt, allow_ns)
         SELECT r.id, z.id, ?, ?, ?, ?, ?, ?, ?, 0 FROM repositories r, zones z
         WHERE r.github_repository_id = ? AND z.name = ?`,
          grant.kind,
          grant.root,
          grant.record_types.includes("A") ? 1 : 0,
          grant.record_types.includes("AAAA") ? 1 : 0,
          grant.record_types.includes("CNAME") ? 1 : 0,
          grant.record_types.includes("SRV") ? 1 : 0,
          grant.record_types.includes("TXT") ? 1 : 0,
          repo.github.repository_id,
          grant.zone,
        ),
      );
    }
  }
  statements.push(
    statement(
      db,
      `INSERT INTO audit_log(action, old_value, new_value, success, created_at)
     VALUES ('policy_sync', (SELECT current_version FROM policy_state WHERE id = 1), ?, 1, ?)`,
      version,
      now,
    ),
  );
  statements.push(
    statement(
      db,
      `INSERT INTO policy_state(id, current_version, updated_at) VALUES (1, ?, ?)
     ON CONFLICT(id) DO UPDATE SET current_version = excluded.current_version,
     updated_at = excluded.updated_at`,
      version,
      now,
    ),
  );
  await db.batch(statements);
  return { version, changed: true };
}
