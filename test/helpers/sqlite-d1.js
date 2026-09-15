import { readFileSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";

const migration =
  readFileSync(
    new URL("../../migrations/0001_initial.sql", import.meta.url),
    "utf8",
  ) +
  readFileSync(
    new URL("../../migrations/0002_policy_versions.sql", import.meta.url),
    "utf8",
  ) +
  readFileSync(
    new URL("../../migrations/0003_apply_admission.sql", import.meta.url),
    "utf8",
  ) +
  readFileSync(
    new URL(
      "../../migrations/0004_d1_maintenance_storage.sql",
      import.meta.url,
    ),
    "utf8",
  );

export function sqliteD1(filename = ":memory:", initialize = true) {
  const sqlite = new DatabaseSync(filename);
  sqlite.exec("PRAGMA foreign_keys = ON");
  if (initialize) sqlite.exec(migration);
  const prepared = (sql, values = []) => ({
    bind: (...next) => prepared(sql, next),
    first: async () => sqlite.prepare(sql).get(...values) ?? null,
    all: async () => ({ results: sqlite.prepare(sql).all(...values) }),
    run: async () => sqlite.prepare(sql).run(...values),
    _run: () => sqlite.prepare(sql).run(...values),
  });
  const db = {
    prepare: (sql) => prepared(sql),
    batch: async (statements) => {
      sqlite.exec("BEGIN IMMEDIATE");
      try {
        const results = statements.map((statement) => statement._run());
        sqlite.exec("COMMIT");
        return results;
      } catch (error) {
        sqlite.exec("ROLLBACK");
        throw error;
      }
    },
  };
  return { db, sqlite, close: () => sqlite.close() };
}
