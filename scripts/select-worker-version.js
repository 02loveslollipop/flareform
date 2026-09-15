import { readFile } from "node:fs/promises";

const file = process.argv[2];
if (!file || process.argv.length !== 3)
  throw new Error("Worker version JSON path required");
const parsed = JSON.parse(await readFile(file, "utf8"));
if (!Array.isArray(parsed)) throw new Error("Invalid Worker version response");
if (parsed.length === 0) process.stdout.write("version=\n");
else {
  const id = parsed[0]?.id;
  if (
    typeof id !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      id,
    )
  )
    throw new Error("Invalid Worker version response");
  process.stdout.write(`version=${id}\n`);
}
