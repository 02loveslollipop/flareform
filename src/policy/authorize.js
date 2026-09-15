import {
  normalizeDnsName,
  normalizeSrvOwner,
  selectConfiguredZone,
} from "../dns/normalize.js";
import { FlareFormError } from "../errors.js";

/**
 * Authorize the complete requested record set before any caller can mutate state.
 * Input is the canonical policy returned by validatePolicy (or an equivalent D1
 * snapshot), never untrusted repository-supplied policy.
 */
export function authorizeRecords(policy, repositoryId, records, options = {}) {
  if (
    !policy ||
    !Array.isArray(policy.zones) ||
    !Array.isArray(policy.repositories)
  )
    throw new FlareFormError("DATABASE_ERROR");
  const repo = policy.repositories.find(
    (candidate) => candidate.github.repository_id === repositoryId,
  );
  if (!repo) throw new FlareFormError("UNKNOWN_REPOSITORY");
  if (!repo.enabled) throw new FlareFormError("REPOSITORY_DISABLED");
  if (!Array.isArray(records) || records.length === 0)
    throw new FlareFormError("INVALID_RECORD");
  if (
    options.operation !== undefined &&
    !["plan", "apply", "prune"].includes(options.operation)
  )
    throw new FlareFormError("INVALID_RECORD");
  if (options.operation === "prune" && options.prune !== true)
    throw new FlareFormError("INVALID_RECORD");
  if (
    (options.prune === true || options.operation === "prune") &&
    !repo.operations.allow_prune
  )
    throw new FlareFormError("PRUNE_NOT_AUTHORIZED");
  if (options.prune !== undefined && typeof options.prune !== "boolean")
    throw new FlareFormError("INVALID_RECORD");

  const authorized = [];
  for (const record of records) {
    if (!record || typeof record !== "object" || Array.isArray(record))
      throw new FlareFormError("INVALID_RECORD");
    if (typeof record.type !== "string" || !/^[A-Z]+$/.test(record.type))
      throw new FlareFormError("INVALID_RECORD");
    let name;
    try {
      name =
        record.type === "SRV"
          ? normalizeSrvOwner(record.name)
          : normalizeDnsName(record.name);
    } catch {
      throw new FlareFormError("INVALID_RECORD");
    }
    const zone = selectConfiguredZone(
      record.type === "SRV" ? name.split(".").slice(2).join(".") : name,
      policy.zones,
    );
    if (!zone) throw new FlareFormError("UNKNOWN_ZONE");
    if (!zone.enabled) throw new FlareFormError("ZONE_DISABLED");
    const grants = repo.grants.filter(
      (grant) =>
        grant.zone === zone.name &&
        (grant.kind === "exact"
          ? name === grant.root
          : name.endsWith(`.${grant.root}`)),
    );
    if (grants.length === 0)
      throw new FlareFormError("HOSTNAME_NOT_AUTHORIZED");
    if (!grants.some((grant) => grant.record_types.includes(record.type)))
      throw new FlareFormError("RECORD_TYPE_NOT_AUTHORIZED");
    authorized.push({ ...record, name, zone: zone.name });
  }
  return authorized;
}
