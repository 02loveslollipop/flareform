import { parseDocument, visit } from "yaml";
import { normalizeDnsName, selectConfiguredZone } from "../dns/normalize.js";

const TYPES = new Set(["A", "AAAA", "CNAME", "SRV", "TXT"]);
const ID = /^[1-9][0-9]*$/;
const ZONE_ID = /^[0-9a-f]{32}$/;
const WORKFLOW =
  /^[^\s@]+\/[^\s@]+\/\.github\/workflows\/[^\s@]+\.ya?ml@refs\/heads\/[^\s@]+$/;

const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);

function invalid(message) {
  throw new TypeError(`Invalid policy: ${message}`);
}

function object(value, keys, required = keys) {
  if (!value || typeof value !== "object" || Array.isArray(value))
    invalid("expected mapping");
  for (const key of Object.keys(value))
    if (!keys.includes(key)) invalid(`unknown field ${key}`);
  for (const key of required)
    if (!Object.hasOwn(value, key)) invalid(`missing field ${key}`);
  return value;
}

function string(value, label, pattern) {
  if (typeof value !== "string" || !value || (pattern && !pattern.test(value)))
    invalid(label);
  return value;
}

function list(value, label) {
  if (!Array.isArray(value) || value.length === 0) invalid(label);
  return value;
}

function boolean(value, label) {
  if (typeof value !== "boolean") invalid(label);
  return value;
}

function canonicalName(value, label) {
  try {
    return normalizeDnsName(value);
  } catch {
    invalid(label);
  }
}

// YAML is only a human-readable serialization here, not a programming language.
// No aliases, anchors, tags, duplicate keys, merge keys, or oversized documents.
export function parsePolicyYaml(source) {
  if (
    typeof source !== "string" ||
    new TextEncoder().encode(source).length > 65536
  )
    invalid("document size");
  const document = parseDocument(source, {
    uniqueKeys: true,
    merge: false,
    strict: true,
  });
  if (document.errors.length || document.warnings.length)
    invalid("YAML syntax");
  visit(document, {
    Node(_key, node) {
      if (node.anchor || node.tag || node.constructor.name === "Alias")
        invalid("YAML extensions");
    },
    Pair(_key, pair) {
      if (pair.key?.value === "<<") invalid("YAML merge key");
    },
  });
  return document.toJS({ maxAliasCount: 0 });
}

export function validateZones(raw) {
  const zones = list(object(raw, ["zones"]).zones, "zones");
  const seenNames = new Set();
  const seenIds = new Set();
  return zones
    .map((entry) => {
      object(entry, ["name", "cloudflare_zone_id", "enabled"]);
      const name = canonicalName(entry.name, "zone name");
      const cloudflare_zone_id = string(
        entry.cloudflare_zone_id,
        "zone ID",
        ZONE_ID,
      );
      const enabled = boolean(entry.enabled, "zone enabled");
      if (seenNames.has(name) || seenIds.has(cloudflare_zone_id))
        invalid("duplicate zone");
      seenNames.add(name);
      seenIds.add(cloudflare_zone_id);
      return { name, cloudflare_zone_id, enabled };
    })
    .sort((a, b) => compare(a.name, b.name));
}

export function validateRepository(raw, zones) {
  object(
    raw,
    ["github", "oidc", "operations", "grants", "enabled"],
    ["github", "oidc", "operations", "grants"],
  );
  const github = object(raw.github, [
    "repository_id",
    "owner_id",
    "display_name",
  ]);
  const oidc = object(
    raw.oidc,
    [
      "event",
      "ref",
      "environment",
      "workflow_ref",
      "runner_environment",
      "job_workflow_ref",
    ],
    ["event", "ref", "environment", "workflow_ref", "runner_environment"],
  );
  const operations = object(raw.operations, ["allow_prune"]);
  const repository_id = string(github.repository_id, "repository ID", ID);
  const owner_id = string(github.owner_id, "owner ID", ID);
  const display_name = string(github.display_name, "display name");
  if (display_name.length > 200) invalid("display name");
  if (oidc.event !== "push") invalid("event");
  if (oidc.ref !== "refs/heads/main") invalid("ref");
  if (oidc.environment !== "production") invalid("environment");
  if (oidc.runner_environment !== "github-hosted")
    invalid("runner environment");
  const workflow_ref = string(oidc.workflow_ref, "workflow ref", WORKFLOW);
  const job_workflow_ref =
    oidc.job_workflow_ref === undefined
      ? null
      : string(oidc.job_workflow_ref, "job workflow ref", WORKFLOW);
  const enabled =
    raw.enabled === undefined
      ? true
      : boolean(raw.enabled, "repository enabled");
  const allow_prune = boolean(operations.allow_prune, "prune permission");
  const seen = new Set();
  const grants = list(raw.grants, "grants")
    .flatMap((entry) => {
      object(
        entry,
        ["zone", "exact", "descendants", "record_types"],
        ["zone", "record_types"],
      );
      const zoneName = canonicalName(entry.zone, "grant zone");
      if (!zones.some((zone) => zone.name === zoneName))
        invalid("unknown zone");
      const types = list(entry.record_types, "record types");
      if (
        types.some((type) => typeof type !== "string" || !TYPES.has(type)) ||
        new Set(types).size !== types.length
      )
        invalid("record types");
      const result = [];
      for (const kind of ["exact", "descendants"]) {
        const roots = entry[kind] === undefined ? [] : entry[kind];
        if (!Array.isArray(roots)) invalid(kind);
        for (const value of roots) {
          const root = canonicalName(value, "grant hostname");
          if (selectConfiguredZone(root, zones)?.name !== zoneName)
            invalid("cross-zone grant");
          const key = `${zoneName}\0${kind}\0${root}`;
          if (seen.has(key)) invalid("duplicate grant");
          seen.add(key);
          result.push({
            zone: zoneName,
            kind,
            root,
            record_types: [...types].sort(),
          });
        }
      }
      if (result.length === 0) invalid("empty grant");
      return result;
    })
    .sort((a, b) =>
      compare(
        `${a.zone}\0${a.kind}\0${a.root}`,
        `${b.zone}\0${b.kind}\0${b.root}`,
      ),
    );
  return {
    github: { repository_id, owner_id, display_name },
    oidc: {
      event: "push",
      ref: "refs/heads/main",
      environment: "production",
      workflow_ref,
      job_workflow_ref,
      runner_environment: "github-hosted",
    },
    operations: { allow_prune },
    enabled,
    grants,
  };
}

export function validatePolicy(zonesRaw, repositoryRaws) {
  const zones = validateZones(zonesRaw);
  if (!Array.isArray(repositoryRaws)) invalid("repositories");
  const repositories = repositoryRaws.map((raw) =>
    validateRepository(raw, zones),
  );
  const ids = new Set();
  for (const repo of repositories) {
    const id = repo.github.repository_id;
    if (ids.has(id)) invalid("duplicate repository ID");
    ids.add(id);
  }
  // A namespace has one owner independent of record type. Two repositories
  // cannot split the exact root from its descendants even though those DNS
  // name sets are disjoint: this is an intentional stricter ownership rule.
  const grants = repositories.flatMap((repo) =>
    repo.grants.map((grant) => ({
      ...grant,
      owner: repo.github.repository_id,
    })),
  );
  for (let i = 0; i < grants.length; i++) {
    for (let j = i + 1; j < grants.length; j++) {
      const a = grants[i],
        b = grants[j];
      if (a.owner === b.owner || a.zone !== b.zone) continue;
      const overlaps =
        a.kind === "exact" && b.kind === "exact"
          ? a.root === b.root
          : a.kind === "exact" && b.kind === "descendants"
            ? a.root === b.root || a.root.endsWith(`.${b.root}`)
            : a.kind === "descendants" && b.kind === "exact"
              ? b.root === a.root || b.root.endsWith(`.${a.root}`)
              : a.root === b.root ||
                a.root.endsWith(`.${b.root}`) ||
                b.root.endsWith(`.${a.root}`);
      if (overlaps) invalid("cross-repository grant overlap");
    }
  }
  repositories.sort((a, b) =>
    compare(a.github.repository_id, b.github.repository_id),
  );
  return { zones, repositories };
}
