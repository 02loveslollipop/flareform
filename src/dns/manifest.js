import { parseDocument, visit } from "yaml";
import {
  normalizeDnsName,
  normalizeSrvOwner,
  selectConfiguredZone,
} from "./normalize.js";
import { FlareFormError } from "../errors.js";
import { parseStrictJson } from "../strict-json.js";

const TYPES = new Set(["A", "AAAA", "CNAME", "SRV", "TXT"]);
const KEY = /^[a-z0-9][a-z0-9-]{0,63}$/;
function invalid() {
  throw new FlareFormError("INVALID_RECORD");
}
function object(value, allowed, required = allowed) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).some((key) => !allowed.includes(key)) ||
    required.some((key) => !Object.hasOwn(value, key))
  )
    invalid();
  return value;
}
function name(value) {
  if (typeof value !== "string" || value.trim() !== value) invalid();
  try {
    return normalizeDnsName(value);
  } catch {
    invalid();
  }
}
function integer(value, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) invalid();
  return value;
}
function ipv4(value) {
  if (
    typeof value !== "string" ||
    !/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(value) ||
    value.split(".").some((part) => Number(part) > 255)
  )
    invalid();
  return value;
}
function ipv6(value) {
  if (
    typeof value !== "string" ||
    value.length > 45 ||
    !/^[0-9a-fA-F:.]+$/.test(value) ||
    !value.includes(":")
  )
    invalid();
  try {
    const canonical = new URL(`http://[${value}]/`).hostname;
    if (!canonical.startsWith("[")) invalid();
    return canonical.slice(1, -1);
  } catch {
    invalid();
  }
}
function srvOwner(value) {
  try {
    return normalizeSrvOwner(value);
  } catch {
    invalid();
  }
}
function ttl(value, proxied) {
  if (proxied) {
    if (value !== 1) invalid();
  } else if (value !== 1) integer(value, 60, 86400);
  return value;
}
function parseRecord(raw, zones, allowTxt) {
  object(
    raw,
    [
      "key",
      "zone",
      "name",
      "type",
      "content",
      "proxied",
      "ttl",
      "priority",
      "weight",
      "port",
      "target",
    ],
    ["key", "zone", "name", "type", "ttl"],
  );
  if (typeof raw.key !== "string" || !KEY.test(raw.key.toLowerCase()))
    invalid();
  if (typeof raw.type !== "string" || !TYPES.has(raw.type)) invalid();
  const zone = name(raw.zone);
  const owner = raw.type === "SRV" ? srvOwner(raw.name) : name(raw.name);
  const selected = selectConfiguredZone(
    raw.type === "SRV" ? owner.split(".").slice(2).join(".") : owner,
    zones,
  );
  if (
    !selected ||
    selected.name !== zone ||
    selected.enabled === false ||
    selected.enabled === 0
  )
    invalid();
  const proxied = raw.proxied === undefined ? false : raw.proxied;
  if (
    typeof proxied !== "boolean" ||
    (proxied && !["A", "AAAA", "CNAME"].includes(raw.type))
  )
    invalid();
  ttl(raw.ttl, proxied);
  const record = {
    key: raw.key.toLowerCase(),
    zone,
    name: owner,
    type: raw.type,
    proxied,
    ttl: raw.ttl,
  };
  if (raw.type === "SRV") {
    if ("content" in raw || "proxied" in raw) invalid();
    for (const field of ["priority", "weight", "port", "target"])
      if (!(field in raw)) invalid();
    record.priority = integer(raw.priority, 0, 65535);
    record.weight = integer(raw.weight, 0, 65535);
    record.port = integer(raw.port, 1, 65535);
    record.target = name(raw.target);
  } else {
    if (
      ["priority", "weight", "port", "target"].some((field) => field in raw) ||
      !("content" in raw)
    )
      invalid();
    if (raw.type === "A") record.content = ipv4(raw.content);
    else if (raw.type === "AAAA") record.content = ipv6(raw.content);
    else if (raw.type === "CNAME") {
      record.content = name(raw.content);
      if (record.content === owner || /^[0-9.]+$/.test(record.content))
        invalid();
    } else {
      if (
        !allowTxt ||
        typeof raw.content !== "string" ||
        raw.content.length < 1 ||
        new TextEncoder().encode(raw.content).length > 255 ||
        /[\x00-\x1f\x7f]/.test(raw.content)
      )
        invalid();
      record.content = raw.content;
    }
  }
  return record;
}

export function parseManifestObject(raw, zones, { allowTxt = false } = {}) {
  object(
    raw,
    ["version", "reconciliation", "prune_zones", "records"],
    ["version", "reconciliation", "records"],
  );
  if (
    raw.version !== 1 ||
    !["keep", "prune"].includes(raw.reconciliation) ||
    !Array.isArray(zones) ||
    !Array.isArray(raw.records) ||
    raw.records.length < 1 ||
    raw.records.length > 100
  )
    invalid();
  if (raw.reconciliation === "keep" && "prune_zones" in raw) invalid();
  let pruneZones;
  if (raw.reconciliation === "prune") {
    if (
      !Array.isArray(raw.prune_zones) ||
      raw.prune_zones.length < 1 ||
      raw.prune_zones.length > zones.length
    )
      invalid();
    pruneZones = raw.prune_zones.map(name);
    if (
      new Set(pruneZones).size !== pruneZones.length ||
      pruneZones.some(
        (zone) =>
          !zones.some(
            (candidate) => candidate.name === zone && candidate.enabled,
          ),
      )
    )
      invalid();
  }
  const records = raw.records.map((record) =>
    parseRecord(record, zones, allowTxt),
  );
  const keys = new Set();
  const identities = new Map();
  const nameTypes = new Map();
  for (const record of records) {
    if (keys.has(record.key)) invalid();
    keys.add(record.key);
    const name = `${record.zone}\0${record.name}`;
    const types = nameTypes.get(name) ?? new Set();
    if (
      (record.type === "CNAME" && types.size > 0) ||
      (record.type !== "CNAME" && types.has("CNAME"))
    )
      invalid();
    types.add(record.type);
    nameTypes.set(name, types);
    const identity = `${record.zone}\0${record.name}\0${record.type}`;
    const values = identities.get(identity) ?? new Set();
    if (values.size > 0 && !["A", "AAAA", "SRV"].includes(record.type))
      invalid();
    const value =
      record.type === "SRV"
        ? `${record.priority}\0${record.weight}\0${record.port}\0${record.target}`
        : record.content;
    if (values.has(value)) invalid();
    values.add(value);
    identities.set(identity, values);
  }
  return {
    version: 1,
    reconciliation: raw.reconciliation,
    ...(pruneZones ? { prune_zones: pruneZones } : {}),
    records,
  };
}

export function parseManifest(source, zones, options) {
  if (
    typeof source !== "string" ||
    new TextEncoder().encode(source).length > 65536
  )
    invalid();
  let raw;
  try {
    if (source.trimStart().startsWith("{"))
      raw = parseStrictJson(source, {
        maxBytes: 65536,
        maxDepth: 24,
        maxNodes: 2048,
      });
    else {
      const document = parseDocument(source, {
        uniqueKeys: true,
        merge: false,
        strict: true,
      });
      if (document.errors.length || document.warnings.length) invalid();
      visit(document, {
        Node(_key, node) {
          if (node.anchor || node.tag || node.constructor.name === "Alias")
            invalid();
        },
        Pair(_key, pair) {
          if (pair.key?.value === "<<") invalid();
        },
      });
      raw = document.toJS({ maxAliasCount: 0 });
    }
    return parseManifestObject(raw, zones, options);
  } catch {
    invalid();
  }
}
