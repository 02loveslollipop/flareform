import { FlareFormError, redactRecordForAudit } from "../errors.js";

// Every statement is static SQL. Values supplied by a request are bound, never
// interpolated into SQL identifiers, expressions, or batch text.
export class DnsRepository {
  constructor(db) {
    if (
      !db ||
      typeof db.prepare !== "function" ||
      typeof db.batch !== "function"
    )
      throw new TypeError("D1 database required");
    this.db = db;
  }

  statement(sql, ...values) {
    return this.db.prepare(sql).bind(...values);
  }

  getZone(name) {
    return this.statement("SELECT * FROM zones WHERE name = ?", name).first();
  }

  listZones() {
    return this.statement("SELECT * FROM zones ORDER BY name").all();
  }

  getRepository(githubRepositoryId) {
    return this.statement(
      "SELECT * FROM repositories WHERE github_repository_id = ?",
      githubRepositoryId,
    ).first();
  }

  getRepositoryById(id) {
    return this.statement(
      "SELECT * FROM repositories WHERE id = ?",
      id,
    ).first();
  }

  listRepositories() {
    return this.statement(
      "SELECT * FROM repositories ORDER BY github_repository_id",
    ).all();
  }

  listGrants(repositoryId) {
    return this.statement(
      "SELECT * FROM repository_grants WHERE repository_id = ? ORDER BY zone_id, hostname_root, grant_kind",
      repositoryId,
    ).all();
  }

  getClaim(zoneId, name, type) {
    return this.statement(
      "SELECT * FROM record_claims WHERE zone_id = ? AND name = ? AND type = ?",
      zoneId,
      name,
      type,
    ).first();
  }

  compareAndSetClaim({ id, repositoryId, version, state, now }) {
    return this.statement(
      "UPDATE record_claims SET state = ?, version = version + 1, updated_at = ? WHERE id = ? AND repository_id = ? AND version = ? RETURNING *",
      state,
      now,
      id,
      repositoryId,
      version,
    ).first();
  }

  getManagedRecord(repositoryId, clientKey) {
    return this.statement(
      "SELECT * FROM managed_records WHERE repository_id = ? AND client_key = ?",
      repositoryId,
      clientKey,
    ).first();
  }

  listManagedRecords(repositoryId) {
    return this.statement(
      "SELECT * FROM managed_records WHERE repository_id = ? ORDER BY client_key",
      repositoryId,
    ).all();
  }

  listOwnedRecords(repositoryId) {
    return this.statement(
      `SELECT mr.repository_id, mr.client_key, mr.cloudflare_record_id, mr.content,
       rc.id AS claim_id, rc.repository_id AS claim_repository_id, rc.state AS claim_state,
       rc.zone_id, rc.name, rc.type, z.name AS zone_name
       FROM managed_records mr JOIN record_claims rc ON rc.id = mr.record_claim_id
       JOIN zones z ON z.id = rc.zone_id
       WHERE mr.repository_id = ? ORDER BY z.name, rc.name, rc.type, mr.client_key`,
      repositoryId,
    ).all();
  }

  upsertManagedRecord({
    repositoryId,
    claimId,
    zoneId,
    clientKey,
    cloudflareRecordId,
    content,
    now,
  }) {
    return this.statement(
      `INSERT INTO managed_records(repository_id, record_claim_id, zone_id, client_key, cloudflare_record_id, content, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT(repository_id, client_key) DO UPDATE SET
         cloudflare_record_id = excluded.cloudflare_record_id,
         content = excluded.content,
         updated_at = excluded.updated_at
       WHERE managed_records.record_claim_id = excluded.record_claim_id AND managed_records.zone_id = excluded.zone_id`,
      repositoryId,
      claimId,
      zoneId,
      clientKey,
      cloudflareRecordId,
      content,
      now,
      now,
    ).run();
  }

  deleteManagedRecord(repositoryId, clientKey) {
    return this.statement(
      "DELETE FROM managed_records WHERE repository_id = ? AND client_key = ?",
      repositoryId,
      clientKey,
    ).run();
  }

  getJti(jti) {
    return this.statement(
      "SELECT jti, repository_id, expires_at FROM oidc_jti WHERE jti = ?",
      jti,
    ).first();
  }

  getPlan(id) {
    return this.statement("SELECT * FROM plans WHERE id = ?", id).first();
  }

  getActivePlan(id, repositoryId, nowEpoch) {
    return this.statement(
      "SELECT * FROM plans WHERE id = ? AND repository_id = ? AND consumed_at IS NULL AND expires_at > ?",
      id,
      repositoryId,
      nowEpoch,
    ).first();
  }

  createPlan({
    id,
    repositoryId,
    manifestSha256,
    policyVersion,
    dnsStateSha256,
    createdAt,
    expiresAt,
  }) {
    return this.statement(
      `INSERT INTO plans(id, repository_id, manifest_sha256, policy_version, dns_state_sha256, created_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
      id,
      repositoryId,
      manifestSha256,
      policyVersion,
      dnsStateSha256,
      createdAt,
      expiresAt,
    ).run();
  }

  consumePlan({ id, repositoryId, nowEpoch, consumedAt }) {
    return this.statement(
      `UPDATE plans SET consumed_at = ? WHERE id = ? AND repository_id = ?
       AND consumed_at IS NULL AND expires_at > ? RETURNING *`,
      consumedAt,
      id,
      repositoryId,
      nowEpoch,
    ).first();
  }

  findOperation({
    repositoryId,
    githubRunId,
    githubRunAttempt,
    operationType,
    manifestSha256,
  }) {
    return this.statement(
      `SELECT * FROM operations WHERE repository_id = ? AND github_run_id = ?
       AND github_run_attempt = ? AND operation_type = ? AND manifest_sha256 = ?`,
      repositoryId,
      githubRunId,
      githubRunAttempt,
      operationType,
      manifestSha256,
    ).first();
  }

  getOperation(id) {
    return this.statement("SELECT * FROM operations WHERE id = ?", id).first();
  }

  getPlanAdmissionByOperation(operationId) {
    return this.statement(
      "SELECT * FROM plan_admissions WHERE operation_id = ?",
      operationId,
    ).first();
  }

  updateOperation({ id, repositoryId, status, completedAt }) {
    return this.statement(
      "UPDATE operations SET status = ?, completed_at = ? WHERE id = ? AND repository_id = ?",
      status,
      completedAt,
      id,
      repositoryId,
    ).run();
  }

  async startOperation(id, repositoryId) {
    const row = await this.statement(
      `UPDATE operations SET status = 'running'
       WHERE id = ? AND repository_id = ? AND status IN ('reserved', 'partial')
       RETURNING *`,
      id,
      repositoryId,
    ).first();
    if (!row) throw new FlareFormError("OPERATION_IN_PROGRESS");
    return row;
  }

  async markZoneFailed({
    operationId,
    repositoryId,
    zoneId,
    zoneName,
    errorCode,
    now,
  }) {
    const intents = (
      await this.listMutationIntents(operationId)
    ).results.filter((intent) => intent.zone_id === zoneId);
    if (intents.length) throw new FlareFormError("STATE_INDETERMINATE");
    const code =
      errorCode === "CLOUDFLARE_API_ERROR"
        ? "CLOUDFLARE_API_ERROR"
        : "STATE_INDETERMINATE";
    try {
      await this.db.batch([
        this.statement(
          `UPDATE operation_zones SET status = 'failed', error_code = ?, updated_at = ?
           WHERE operation_id = ? AND zone_id = ? AND status = 'pending'`,
          code,
          now,
          operationId,
          zoneId,
        ),
        this.statement(
          `INSERT INTO audit_log(operation_id, repository_id, action, zone, success,
           error_code, created_at) VALUES (?, ?, 'zone_failed_pre_send', ?, 0, ?, ?)`,
          operationId,
          repositoryId,
          zoneName,
          code,
          now,
        ),
      ]);
    } catch {
      throw new FlareFormError("STATE_INDETERMINATE");
    }
  }

  async freezeZone({ operationId, repositoryId, zoneId, zoneName, now }) {
    try {
      await this.db.batch([
        this.statement(
          `UPDATE operation_zones SET status = 'indeterminate',
           error_code = 'STATE_INDETERMINATE', updated_at = ?
           WHERE operation_id = ? AND zone_id = ? AND status <> 'success'`,
          now,
          operationId,
          zoneId,
        ),
        this.statement(
          `UPDATE operations SET status = 'indeterminate'
           WHERE id = ? AND repository_id = ?`,
          operationId,
          repositoryId,
        ),
        this.statement(
          `INSERT INTO audit_log(operation_id, repository_id, action, zone,
           success, error_code, created_at)
           VALUES (?, ?, 'zone_frozen', ?, 0, 'STATE_INDETERMINATE', ?)`,
          operationId,
          repositoryId,
          zoneName,
          now,
        ),
      ]);
    } catch {
      // The operation lock remains authoritative if even the freeze write fails.
      throw new FlareFormError("STATE_INDETERMINATE");
    }
  }

  async reserveOperation({
    operation,
    jti,
    jtiExpiresAt,
    claims = [],
    locks = claims,
    zoneIds = [],
    zoneFingerprints = {},
    plan = null,
    now,
    nowEpoch,
  }) {
    if (await this.getJti(jti)) throw new FlareFormError("OIDC_TOKEN_REPLAYED");
    const jtiInsert = this.statement(
      "INSERT INTO oidc_jti(jti, repository_id, expires_at, used_at) VALUES (?, ?, ?, ?)",
      jti,
      operation.repositoryId,
      jtiExpiresAt,
      now,
    );
    const existing = await this.findOperation(operation);
    if (existing) {
      try {
        await this.db.batch([jtiInsert]);
      } catch {
        if (await this.getJti(jti))
          throw new FlareFormError("OIDC_TOKEN_REPLAYED");
        throw new FlareFormError("DATABASE_ERROR");
      }
      return { operation: existing, reused: true };
    }
    const uniqueLocks = [
      ...new Map(
        locks.map((lock) => [
          `${lock.zoneId}\0${lock.name}\0${lock.type}`,
          lock,
        ]),
      ).values(),
    ];
    const statements = [
      this.statement(
        `INSERT INTO operations(id, repository_id, github_run_id, github_run_attempt,
         requested_at, status, manifest_sha256, operation_type, policy_version)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        operation.id,
        operation.repositoryId,
        operation.githubRunId,
        operation.githubRunAttempt,
        now,
        "reserved",
        operation.manifestSha256,
        operation.operationType,
        operation.policyVersion ?? null,
      ),
      jtiInsert,
      ...[...new Set(zoneIds)].map((zoneId) =>
        this.statement(
          "INSERT INTO operation_zones(operation_id, zone_id, status, updated_at, dns_state_sha256) VALUES (?, ?, 'pending', ?, ?)",
          operation.id,
          zoneId,
          now,
          zoneFingerprints[zoneId] ?? null,
        ),
      ),
      ...uniqueLocks.map((lock) =>
        this.statement(
          `INSERT INTO operation_locks(zone_id, name, type, operation_id, repository_id, created_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
          lock.zoneId,
          lock.name,
          lock.type,
          operation.id,
          operation.repositoryId,
          now,
        ),
      ),
      ...claims.map((claim) =>
        this.statement(
          `INSERT INTO record_claims(repository_id, zone_id, name, type, state, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'reserved', ?, ?)`,
          operation.repositoryId,
          claim.zoneId,
          claim.name,
          claim.type,
          now,
          now,
        ),
      ),
      ...(plan
        ? [
            this.statement(
              `INSERT INTO plan_admissions(plan_id, operation_id, repository_id,
               manifest_sha256, policy_version, dns_state_sha256, reserved_epoch, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
              plan.id,
              operation.id,
              operation.repositoryId,
              operation.manifestSha256,
              plan.policyVersion,
              plan.dnsStateSha256,
              nowEpoch,
              now,
            ),
            this.statement(
              "UPDATE plans SET consumed_at = ? WHERE id = ? AND consumed_at IS NULL",
              now,
              plan.id,
            ),
          ]
        : []),
    ];
    try {
      await this.db.batch(statements);
    } catch {
      if (await this.getJti(jti))
        throw new FlareFormError("OIDC_TOKEN_REPLAYED");
      // A concurrent retry of the same logical operation returns the existing
      // operation. Any other conflict remains a hard failure; batch rolls back.
      const raced = await this.findOperation(operation);
      if (raced) {
        try {
          await this.db.batch([jtiInsert]);
        } catch {
          if (await this.getJti(jti))
            throw new FlareFormError("OIDC_TOKEN_REPLAYED");
          throw new FlareFormError("DATABASE_ERROR");
        }
        return { operation: raced, reused: true };
      }
      if (plan) {
        const current = await this.getPlan(plan.id);
        if (
          !current ||
          current.repository_id !== operation.repositoryId ||
          current.manifest_sha256 !== operation.manifestSha256 ||
          current.policy_version !== plan.policyVersion ||
          current.dns_state_sha256 !== plan.dnsStateSha256 ||
          current.consumed_at !== null ||
          current.expires_at <= nowEpoch
        )
          throw new FlareFormError("PLAN_PRECONDITION_FAILED");
      }
      if (uniqueLocks.length || claims.length)
        throw new FlareFormError("OPERATION_IN_PROGRESS");
      throw new FlareFormError("DATABASE_ERROR");
    }
    const reserved = await this.getOperation(operation.id);
    if (!reserved) throw new FlareFormError("DATABASE_ERROR");
    return { operation: reserved, reused: false };
  }

  listOperationLocks(operationId) {
    return this.statement(
      "SELECT * FROM operation_locks WHERE operation_id = ? ORDER BY zone_id, name, type",
      operationId,
    ).all();
  }

  getOperationLock(zoneId, name, type) {
    return this.statement(
      "SELECT * FROM operation_locks WHERE zone_id = ? AND name = ? AND type = ?",
      zoneId,
      name,
      type,
    ).first();
  }

  getMutationIntent(operationId, clientKey) {
    return this.statement(
      "SELECT * FROM mutation_intents WHERE operation_id = ? AND client_key = ?",
      operationId,
      clientKey,
    ).first();
  }

  listMutationIntents(operationId) {
    return this.statement(
      "SELECT * FROM mutation_intents WHERE operation_id = ? ORDER BY zone_id, client_key",
      operationId,
    ).all();
  }

  getMutationAudit(operationId, clientKey) {
    return this.statement(
      `SELECT a.* FROM audit_log a JOIN mutation_intents m
       ON m.operation_id = a.operation_id AND m.record_name = a.record_name
       AND m.record_type = a.record_type
       WHERE m.operation_id = ? AND m.client_key = ? ORDER BY a.id`,
      operationId,
      clientKey,
    ).all();
  }

  async resolveMutationAdmin({
    operationId,
    repositoryId,
    zoneId,
    zoneName,
    clientKey,
    decision,
    claimId,
    cloudflareRecordId = null,
    content = null,
    operatorId,
    now,
  }) {
    if (!["confirm-provider", "confirm-no-change"].includes(decision))
      throw new FlareFormError("INVALID_REQUEST");
    const intent = await this.getMutationIntent(operationId, clientKey);
    if (
      !intent ||
      intent.zone_id !== zoneId ||
      !["sent", "indeterminate"].includes(intent.status)
    )
      throw new FlareFormError("STATE_INDETERMINATE");
    const statements = [];
    if (decision === "confirm-provider") {
      if (intent.action === "delete") {
        statements.push(
          this.statement(
            "DELETE FROM managed_records WHERE repository_id = ? AND client_key = ? AND record_claim_id = ? AND cloudflare_record_id = ?",
            repositoryId,
            clientKey,
            claimId,
            intent.cloudflare_record_id,
          ),
          this.statement(
            "DELETE FROM record_claims WHERE id = ? AND repository_id = ? AND NOT EXISTS (SELECT 1 FROM managed_records WHERE record_claim_id = ?)",
            claimId,
            repositoryId,
            claimId,
          ),
        );
      } else {
        statements.push(
          this.statement(
            "UPDATE record_claims SET state = 'active', version = version + 1, updated_at = ? WHERE id = ? AND repository_id = ?",
            now,
            claimId,
            repositoryId,
          ),
          this.statement(
            `INSERT INTO managed_records(repository_id, record_claim_id, zone_id,
             client_key, cloudflare_record_id, content, created_at, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(repository_id, client_key) DO UPDATE SET
               cloudflare_record_id = excluded.cloudflare_record_id,
               content = excluded.content, updated_at = excluded.updated_at
             WHERE managed_records.record_claim_id = excluded.record_claim_id
               AND managed_records.zone_id = excluded.zone_id`,
            repositoryId,
            claimId,
            zoneId,
            clientKey,
            cloudflareRecordId,
            content,
            now,
            now,
          ),
        );
      }
    } else if (intent.action === "create") {
      statements.push(
        this.statement(
          "DELETE FROM record_claims WHERE id = ? AND repository_id = ? AND state = 'reserved' AND NOT EXISTS (SELECT 1 FROM managed_records WHERE record_claim_id = ?)",
          claimId,
          repositoryId,
          claimId,
        ),
      );
    }
    statements.push(
      this.statement(
        "UPDATE mutation_intents SET status = 'resolved', confirmed_record_id = ?, updated_at = ? WHERE operation_id = ? AND client_key = ?",
        decision === "confirm-provider" ? cloudflareRecordId : null,
        now,
        operationId,
        clientKey,
      ),
      this.statement(
        `INSERT INTO audit_log(operation_id, repository_id, action, zone,
         record_name, record_type, success, github_actor_id, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)`,
        operationId,
        repositoryId,
        `admin_reconcile:${decision}`,
        zoneName,
        intent.record_name,
        intent.record_type,
        operatorId,
        now,
      ),
      this.statement(
        "DELETE FROM operation_locks WHERE operation_id = ? AND zone_id = ? AND name = ? AND type = ?",
        operationId,
        zoneId,
        intent.record_name,
        intent.record_type,
      ),
      this.statement(
        `UPDATE operation_zones SET status = 'reconciled', error_code = NULL,
         updated_at = ? WHERE operation_id = ? AND zone_id = ?
         AND NOT EXISTS (SELECT 1 FROM operation_locks WHERE operation_id = ? AND zone_id = ?)`,
        now,
        operationId,
        zoneId,
        operationId,
        zoneId,
      ),
      this.statement(
        `UPDATE operations SET status = 'reconciled', completed_at = ?
         WHERE id = ? AND repository_id = ?
         AND NOT EXISTS (SELECT 1 FROM operation_locks WHERE operation_id = ?)`,
        now,
        operationId,
        repositoryId,
        operationId,
      ),
    );
    try {
      await this.db.batch(statements);
    } catch {
      throw new FlareFormError("STATE_INDETERMINATE");
    }
  }

  async beginMutationIntent({
    operationId,
    repositoryId,
    zoneId,
    zoneName,
    clientKey,
    recordName,
    recordType,
    action,
    cloudflareRecordId = null,
    oldRecord = null,
    newRecord = null,
    githubRunId,
    githubRunAttempt,
    githubActorId,
    workflowRef,
    now,
  }) {
    const oldValue = oldRecord
      ? JSON.stringify(redactRecordForAudit(oldRecord))
      : null;
    const newValue = newRecord
      ? JSON.stringify(redactRecordForAudit(newRecord))
      : null;
    try {
      await this.db.batch([
        this.statement(
          `INSERT INTO mutation_intents(operation_id, zone_id, client_key,
           record_name, record_type, action, cloudflare_record_id, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          operationId,
          zoneId,
          clientKey,
          recordName,
          recordType,
          action,
          cloudflareRecordId,
          now,
          now,
        ),
        this.statement(
          `INSERT INTO audit_log(operation_id, repository_id, action, zone, record_name,
           record_type, old_value, new_value, success, github_run_id,
           github_run_attempt, github_actor_id, workflow_ref, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?)`,
          operationId,
          repositoryId,
          `intent:${action}`,
          zoneName,
          recordName,
          recordType,
          oldValue,
          newValue,
          githubRunId ?? null,
          githubRunAttempt ?? null,
          githubActorId ?? null,
          workflowRef ?? null,
          now,
        ),
      ]);
    } catch {
      throw new FlareFormError("DATABASE_ERROR");
    }
  }

  async markMutationSent(operationId, clientKey, now) {
    const row = await this.statement(
      `UPDATE mutation_intents SET status = 'sent', updated_at = ?
       WHERE operation_id = ? AND client_key = ? AND status = 'prepared'
       RETURNING *`,
      now,
      operationId,
      clientKey,
    ).first();
    if (!row) throw new FlareFormError("STATE_INDETERMINATE");
    return row;
  }

  async confirmMutation({
    operationId,
    repositoryId,
    zoneId,
    zoneName,
    clientKey,
    recordName,
    recordType,
    action,
    claimId,
    cloudflareRecordId,
    content,
    githubRunId,
    githubRunAttempt,
    githubActorId,
    workflowRef,
    now,
  }) {
    const statements = [];
    if (action === "delete") {
      statements.push(
        this.statement(
          `DELETE FROM managed_records WHERE repository_id = ? AND client_key = ?
           AND zone_id = ? AND record_claim_id = ? AND cloudflare_record_id = ?`,
          repositoryId,
          clientKey,
          zoneId,
          claimId,
          cloudflareRecordId,
        ),
        this.statement(
          `DELETE FROM record_claims WHERE id = ? AND repository_id = ?
           AND NOT EXISTS (SELECT 1 FROM managed_records WHERE record_claim_id = ?)`,
          claimId,
          repositoryId,
          claimId,
        ),
      );
    } else {
      statements.push(
        this.statement(
          `UPDATE record_claims SET state = 'active', version = version + 1,
           updated_at = ? WHERE id = ? AND repository_id = ?
           AND zone_id = ? AND name = ? AND type = ?
           AND state IN ('reserved', 'active')`,
          now,
          claimId,
          repositoryId,
          zoneId,
          recordName,
          recordType,
        ),
        this.statement(
          `INSERT INTO managed_records(repository_id, record_claim_id, zone_id,
           client_key, cloudflare_record_id, content, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(repository_id, client_key) DO UPDATE SET
             cloudflare_record_id = excluded.cloudflare_record_id,
             content = excluded.content, updated_at = excluded.updated_at
           WHERE managed_records.record_claim_id = excluded.record_claim_id
             AND managed_records.zone_id = excluded.zone_id`,
          repositoryId,
          claimId,
          zoneId,
          clientKey,
          cloudflareRecordId,
          content,
          now,
          now,
        ),
      );
    }
    statements.push(
      this.statement(
        `UPDATE mutation_intents SET status = 'confirmed', confirmed_record_id = ?,
         updated_at = ? WHERE operation_id = ? AND client_key = ?`,
        action === "delete" ? null : cloudflareRecordId,
        now,
        operationId,
        clientKey,
      ),
      this.statement(
        `INSERT INTO audit_log(operation_id, repository_id, action, zone, record_name,
         record_type, success, github_run_id, github_run_attempt,
         github_actor_id, workflow_ref, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`,
        operationId,
        repositoryId,
        `outcome:${action}`,
        zoneName,
        recordName,
        recordType,
        githubRunId ?? null,
        githubRunAttempt ?? null,
        githubActorId ?? null,
        workflowRef ?? null,
        now,
      ),
    );
    try {
      await this.db.batch(statements);
    } catch {
      throw new FlareFormError("STATE_INDETERMINATE");
    }
    const intent = await this.getMutationIntent(operationId, clientKey);
    if (intent?.status !== "confirmed")
      throw new FlareFormError("STATE_INDETERMINATE");
    return intent;
  }

  async markMutationIndeterminate({
    operationId,
    repositoryId,
    zoneId,
    zoneName,
    clientKey,
    recordName,
    recordType,
    githubRunId,
    githubRunAttempt,
    githubActorId,
    workflowRef,
    errorCode,
    now,
  }) {
    const safeError = ["CLOUDFLARE_API_ERROR", "DATABASE_ERROR"].includes(
      errorCode,
    )
      ? errorCode
      : "STATE_INDETERMINATE";
    try {
      await this.db.batch([
        this.statement(
          `UPDATE mutation_intents SET status = 'indeterminate', updated_at = ?
           WHERE operation_id = ? AND client_key = ?`,
          now,
          operationId,
          clientKey,
        ),
        this.statement(
          "UPDATE operation_zones SET status = 'indeterminate', error_code = ?, updated_at = ? WHERE operation_id = ? AND zone_id = ?",
          safeError,
          now,
          operationId,
          zoneId,
        ),
        this.statement(
          "UPDATE operations SET status = 'indeterminate' WHERE id = ? AND repository_id = ?",
          operationId,
          repositoryId,
        ),
        this.statement(
          `INSERT INTO audit_log(operation_id, repository_id, action, zone, record_name,
           record_type, success, error_code, github_run_id, github_run_attempt,
           github_actor_id, workflow_ref, created_at)
           VALUES (?, ?, 'outcome:indeterminate', ?, ?, ?, 0, ?, ?, ?, ?, ?, ?)`,
          operationId,
          repositoryId,
          zoneName,
          recordName,
          recordType,
          safeError,
          githubRunId ?? null,
          githubRunAttempt ?? null,
          githubActorId ?? null,
          workflowRef ?? null,
          now,
        ),
      ]);
    } catch {
      // The sent intent and operation lock are durable even if this write fails.
      throw new FlareFormError("STATE_INDETERMINATE");
    }
  }

  async finishZone({ operationId, repositoryId, zoneId, zoneName, now }) {
    try {
      await this.db.batch([
        this.statement(
          "DELETE FROM operation_locks WHERE operation_id = ? AND zone_id = ? AND repository_id = ?",
          operationId,
          zoneId,
          repositoryId,
        ),
        this.statement(
          "UPDATE operation_zones SET status = 'success', error_code = NULL, updated_at = ? WHERE operation_id = ? AND zone_id = ?",
          now,
          operationId,
          zoneId,
        ),
        this.statement(
          `INSERT INTO audit_log(operation_id, repository_id, action, zone, success,
           created_at) VALUES (?, ?, 'zone_complete', ?, 1, ?)`,
          operationId,
          repositoryId,
          zoneName,
          now,
        ),
      ]);
    } catch {
      throw new FlareFormError("STATE_INDETERMINATE");
    }
  }

  getCheckpoint(operationId, zoneId) {
    return this.statement(
      "SELECT * FROM operation_zones WHERE operation_id = ? AND zone_id = ?",
      operationId,
      zoneId,
    ).first();
  }

  upsertCheckpoint({ operationId, zoneId, status, errorCode, now }) {
    return this.statement(
      `INSERT INTO operation_zones(operation_id, zone_id, status, error_code, updated_at)
       VALUES (?, ?, ?, ?, ?) ON CONFLICT(operation_id, zone_id) DO UPDATE SET
       status = excluded.status, error_code = excluded.error_code, updated_at = excluded.updated_at`,
      operationId,
      zoneId,
      status,
      errorCode ?? null,
      now,
    ).run();
  }

  listCheckpoints(operationId) {
    return this.statement(
      "SELECT * FROM operation_zones WHERE operation_id = ? ORDER BY zone_id",
      operationId,
    ).all();
  }

  appendAudit({
    operationId,
    repositoryId,
    action,
    zone,
    recordName,
    recordType,
    success,
    errorCode,
    githubRunId,
    githubActorId,
    now,
  }) {
    return this.statement(
      `INSERT INTO audit_log(operation_id, repository_id, action, zone, record_name,
       record_type, old_value, new_value, success, error_code, github_run_id,
       github_actor_id, created_at) VALUES (?, ?, ?, ?, ?, ?, NULL, NULL, ?, ?, ?, ?, ?)`,
      operationId ?? null,
      repositoryId ?? null,
      action,
      zone ?? null,
      recordName ?? null,
      recordType ?? null,
      success ? 1 : 0,
      errorCode ?? null,
      githubRunId ?? null,
      githubActorId ?? null,
      now,
    ).run();
  }
}
