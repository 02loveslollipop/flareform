import { FlareFormError } from "../errors.js";
import { verifyOwnership } from "./state.js";

function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(",")}]`;
  if (value && typeof value === "object")
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${stable(value[key])}`)
      .join(",")}}`;
  return JSON.stringify(value);
}
function snapshot(record) {
  return {
    id: record.id,
    name: record.name,
    type: record.type,
    content: record.content ?? null,
    data: record.data ?? null,
    ttl: record.ttl,
    proxied: record.proxied ?? false,
    tags: [...(record.tags ?? [])].sort(),
    comment: record.comment ?? null,
    modified_on: record.modified_on ?? null,
  };
}

/** Read every same-set value just before a provider mutation. */
export async function assertCurrentRecordSet({
  cloudflare,
  zone,
  record,
  ownedRows,
  repositoryId,
  expectedCurrent = null,
}) {
  const all = await cloudflare.listRecords(zone);
  if (!Array.isArray(all)) throw new FlareFormError("CLOUDFLARE_API_ERROR");
  const atName = all.filter((item) => item.name === record.name);
  if (
    atName.some(
      (item) =>
        item.type === "NS" ||
        (record.type === "CNAME" && item.type !== "CNAME") ||
        (record.type !== "CNAME" && item.type === "CNAME"),
    )
  )
    throw new FlareFormError("DNS_CONFLICT");
  const sameType = atName.filter((item) => item.type === record.type);
  const expectedRows = ownedRows.filter(
    (row) =>
      row.zone_name === zone.name &&
      row.name === record.name &&
      row.type === record.type,
  );
  if (sameType.length !== expectedRows.length)
    throw new FlareFormError("STATE_INDETERMINATE");
  for (const row of expectedRows) {
    const external = sameType.find(
      (item) => item.id === row.cloudflare_record_id,
    );
    verifyOwnership(row, external, repositoryId);
  }
  const current = expectedCurrent
    ? sameType.find((item) => item.id === expectedCurrent.id)
    : null;
  if (
    expectedCurrent &&
    (!current ||
      stable(snapshot(current)) !== stable(snapshot(expectedCurrent)))
  )
    throw new FlareFormError("STATE_INDETERMINATE");
  return current;
}
