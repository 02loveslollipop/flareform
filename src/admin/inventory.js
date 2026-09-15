import { createCloudflareClient } from "../dns/cloudflare.js";
import { normalizeDnsName, normalizeSrvOwner } from "../dns/normalize.js";
import { canonicalSrvData, managedMetadata } from "../dns/state.js";
import { DnsRepository } from "../db/repository.js";
import { readActivePolicy } from "../policy/storage.js";

const MANUAL_TYPES = new Set(["MX", "CAA", "DNSKEY", "DS", "NAPTR"]);
const SECRET_PATTERN =
  /authorization\s*:|bearer\s+[a-z0-9._-]{8,}|cloudflare.{0,20}(?:token|secret)|-----begin [^-]*private key-----/i;

function sanitizeText(value) {
  if (typeof value !== "string") return null;
  return SECRET_PATTERN.test(value) ? "[REDACTED]" : value;
}

function canonicalName(record) {
  try {
    return record.type === "SRV"
      ? normalizeSrvOwner(record.name)
      : normalizeDnsName(record.name);
  } catch {
    return "[INVALID_NAME]";
  }
}

function inventoryRecord(zone, record) {
  const type =
    typeof record.type === "string" ? record.type.toUpperCase() : "UNKNOWN";
  const content =
    type === "SRV" && record.data && typeof record.data === "object"
      ? Object.fromEntries(
          ["priority", "weight", "port", "target"].map((key) => [
            key,
            typeof record.data[key] === "string"
              ? sanitizeText(record.data[key])
              : (record.data[key] ?? null),
          ]),
        )
      : sanitizeText(record.content);
  return {
    zone,
    cloudflare_record_id: sanitizeText(record.id),
    name: canonicalName({ ...record, type }),
    type,
    content,
    proxied: record.proxied === true,
    ttl: Number.isSafeInteger(record.ttl) ? record.ttl : null,
    comment: sanitizeText(record.comment),
    tags: Array.isArray(record.tags) ? record.tags.map(sanitizeText) : [],
    classification: MANUAL_TYPES.has(type) ? "global/manual" : "unknown",
    service: null,
    github_repository: null,
    deployment_platform: null,
    mirrored_domain: null,
  };
}

async function configuredZones(db) {
  const repo = new DnsRepository(db);
  const { policy } = await readActivePolicy(db);
  const rows = (await repo.listZones()).results;
  return policy.zones.map((zone) => ({
    policy: zone,
    row: rows.find(
      (candidate) =>
        candidate.name === zone.name &&
        candidate.cloudflare_zone_id === zone.cloudflare_zone_id,
    ),
    readZone: { ...zone, enabled: true },
  }));
}

export async function generateInventory({
  db,
  token,
  cloudflareFactory = createCloudflareClient,
  now = Date.now(),
}) {
  const zones = await configuredZones(db);
  const cloudflare = cloudflareFactory({ token });
  const results = [];
  for (const zone of zones) {
    if (!zone.row) {
      results.push({
        zone: zone.policy.name,
        complete: false,
        error: "POLICY_MISMATCH",
        records: [],
      });
      continue;
    }
    try {
      const records = await cloudflare.listRecords(zone.readZone);
      results.push({
        zone: zone.policy.name,
        complete: true,
        records: records
          .map((record) => inventoryRecord(zone.policy.name, record))
          .sort((a, b) => {
            const left = `${a.name}\0${a.type}\0${a.cloudflare_record_id}`;
            const right = `${b.name}\0${b.type}\0${b.cloudflare_record_id}`;
            return left < right ? -1 : left > right ? 1 : 0;
          }),
      });
    } catch {
      results.push({
        zone: zone.policy.name,
        complete: false,
        error: "CLOUDFLARE_API_ERROR",
        records: [],
      });
    }
  }
  return {
    generated_at: new Date(now).toISOString(),
    complete: results.every((zone) => zone.complete),
    zones: results,
  };
}

function metadataMatches(row, record) {
  const expected = managedMetadata(row.github_repository_id, row.client_key);
  return (
    record.comment === expected.comment &&
    Array.isArray(record.tags) &&
    record.tags.length === expected.tags.length &&
    expected.tags.every((tag) => record.tags.includes(tag))
  );
}

function recordContent(record) {
  try {
    return record.type === "SRV"
      ? canonicalSrvData(record.data)
      : record.content;
  } catch {
    return null;
  }
}

export async function auditOwnership({
  db,
  token,
  cloudflareFactory = createCloudflareClient,
  now = Date.now(),
}) {
  const zones = await configuredZones(db);
  const cloudflare = cloudflareFactory({ token });
  const external = new Map();
  const findings = [];
  for (const zone of zones) {
    if (!zone.row) {
      findings.push({ finding: "zone_incomplete", zone: zone.policy.name });
      continue;
    }
    try {
      external.set(zone.row.id, await cloudflare.listRecords(zone.readZone));
    } catch {
      findings.push({ finding: "zone_incomplete", zone: zone.policy.name });
    }
  }
  const owned = (
    await db
      .prepare(
        `SELECT mr.repository_id, mr.client_key, mr.cloudflare_record_id, mr.content,
         rc.id AS claim_id, rc.repository_id AS claim_repository_id,
         rc.state AS claim_state, rc.zone_id, rc.name, rc.type,
         z.name AS zone_name, r.github_repository_id
         FROM managed_records mr
         JOIN record_claims rc ON rc.id = mr.record_claim_id
         JOIN zones z ON z.id = rc.zone_id
         JOIN repositories r ON r.id = mr.repository_id
         ORDER BY z.name, rc.name, rc.type, mr.client_key`,
      )
      .all()
  ).results;
  const tracked = new Set();
  let healthy = 0;
  for (const row of owned) {
    const records = external.get(row.zone_id);
    if (!records) continue;
    const record = records.find(
      (candidate) => candidate.id === row.cloudflare_record_id,
    );
    tracked.add(`${row.zone_id}\0${row.cloudflare_record_id}`);
    const base = {
      zone: row.zone_name,
      name: row.name,
      type: row.type,
      repository_id: row.github_repository_id,
      client_key: row.client_key,
    };
    if (!record) {
      const moved = records.find(
        (candidate) =>
          canonicalName(candidate) === row.name &&
          candidate.type === row.type &&
          metadataMatches(row, candidate),
      );
      if (moved) tracked.add(`${row.zone_id}\0${moved.id}`);
      findings.push({
        ...base,
        finding: moved ? "changed_id" : "missing_record",
      });
      continue;
    }
    if (
      row.claim_repository_id !== row.repository_id ||
      row.claim_state !== "active"
    ) {
      findings.push({ ...base, finding: "orphan_d1_row" });
      continue;
    }
    if (canonicalName(record) !== row.name || record.type !== row.type) {
      findings.push({ ...base, finding: "changed_identity" });
      continue;
    }
    if (recordContent(record) !== row.content) {
      findings.push({ ...base, finding: "changed_content" });
      continue;
    }
    if (!metadataMatches(row, record)) {
      findings.push({ ...base, finding: "altered_metadata" });
      continue;
    }
    healthy++;
  }
  for (const zone of zones) {
    const records = external.get(zone.row?.id);
    if (!records) continue;
    for (const record of records) {
      if (
        record.tags?.includes("managed-by:flareform") &&
        !tracked.has(`${zone.row.id}\0${record.id}`)
      )
        findings.push({
          finding: "untracked_metadata",
          zone: zone.policy.name,
          name: canonicalName(record),
          type: record.type,
          cloudflare_record_id: sanitizeText(record.id),
        });
    }
  }
  const orphans = (
    await db
      .prepare(
        `SELECT mr.id FROM managed_records mr
         LEFT JOIN record_claims rc ON rc.id = mr.record_claim_id
         LEFT JOIN zones z ON z.id = mr.zone_id
         LEFT JOIN repositories r ON r.id = mr.repository_id
         WHERE rc.id IS NULL OR z.id IS NULL OR r.id IS NULL`,
      )
      .all()
  ).results;
  for (const row of orphans)
    findings.push({
      finding: "orphan_d1_row",
      zone: null,
      d1_row_id: row.id,
    });
  return {
    generated_at: new Date(now).toISOString(),
    complete: !findings.some(
      (finding) => finding.finding === "zone_incomplete",
    ),
    healthy,
    findings,
  };
}
