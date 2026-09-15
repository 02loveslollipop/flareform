import { FlareFormError } from "../errors.js";

/** Read one committed policy snapshot; never assemble policy from partial rows. */
export async function readActivePolicy(db) {
  try {
    const row = await db
      .prepare(
        `SELECT pv.version, pv.canonical_json FROM policy_state ps
       JOIN policy_versions pv ON pv.version = ps.current_version WHERE ps.id = 1`,
      )
      .first();
    if (
      !row ||
      typeof row.version !== "string" ||
      typeof row.canonical_json !== "string"
    )
      throw new Error("No active policy");
    const policy = JSON.parse(row.canonical_json);
    if (!Array.isArray(policy.zones) || !Array.isArray(policy.repositories))
      throw new Error("Invalid stored policy");
    return { version: row.version, policy };
  } catch {
    throw new FlareFormError("DATABASE_ERROR");
  }
}
