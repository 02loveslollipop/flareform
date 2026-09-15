import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { extname, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const FORBIDDEN_PATHS = new Set([
  ".github/workflows/adopt-record.yml",
  ".github/workflows/deploy.yml",
  ".github/workflows/sync-policy.yml",
  "config/zones.yaml",
]);
const FORBIDDEN_EXTENSIONS = new Set([
  ".db",
  ".key",
  ".p12",
  ".pem",
  ".pfx",
  ".sqlite",
  ".sqlite3",
]);
export function inspectPublicFiles(files, readFile) {
  const findings = [];
  for (const file of files) {
    if (
      FORBIDDEN_PATHS.has(file) ||
      (file.startsWith("config/repositories/") &&
        !file.endsWith("/.gitkeep")) ||
      FORBIDDEN_EXTENSIONS.has(extname(file)) ||
      file === ".dev.vars" ||
      file.startsWith(".dev.vars.") ||
      file === ".env" ||
      file.startsWith(".env.")
    ) {
      findings.push({ file, reason: "private-path" });
      continue;
    }
    const buffer = readFile(file);
    if (buffer.length > 2 * 1024 * 1024 || buffer.includes(0)) continue;
  }
  return findings;
}

export function checkPublicRelease(root = process.cwd()) {
  const files = execFileSync("git", ["ls-files", "-z"], {
    cwd: root,
    encoding: "utf8",
  })
    .split("\0")
    .filter(Boolean);
  return inspectPublicFiles(files, (file) => readFileSync(resolve(root, file)));
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  const findings = checkPublicRelease();
  for (const finding of findings)
    process.stderr.write(`${finding.file}: ${finding.reason}\n`);
  if (findings.length) process.exitCode = 1;
  else process.stdout.write("Public release boundary passed\n");
}
