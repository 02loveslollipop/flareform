import { FlareFormError } from "../errors.js";

// D1 enforces foreign keys by default and does not allow a normal query to
// toggle them inside its implicit transaction. Verify the binding before any
// repository module uses it, rather than assuming a compatible mock does so.
export async function requireD1(env) {
  const db = env?.DB;
  if (!db || typeof db.prepare !== "function")
    throw new FlareFormError("DATABASE_ERROR");
  try {
    const row = await db.prepare("PRAGMA foreign_keys").first();
    if (row?.foreign_keys !== 1)
      throw new Error("Foreign keys are not enforced");
  } catch {
    throw new FlareFormError("DATABASE_ERROR");
  }
  return db;
}
