import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const LOCKFILES = ["package-lock.json", "github-action/package-lock.json"];
const FORBIDDEN_LICENSE = /(?:^|\s|\()(?:(?:A?GPL|SSPL)-)/i;

export function inspectLockfile(lock, filename) {
  const findings = [];
  if (
    lock?.lockfileVersion !== 3 ||
    !lock.packages ||
    typeof lock.packages !== "object"
  )
    return [
      {
        file: filename,
        package: "[lockfile]",
        reason: "unsupported-lockfile",
      },
    ];
  for (const [path, metadata] of Object.entries(lock.packages)) {
    if (!path || metadata.link === true) continue;
    const item = { file: filename, package: path };
    if (typeof metadata.resolved !== "string")
      findings.push({ ...item, reason: "missing-resolution" });
    else {
      try {
        const url = new URL(metadata.resolved);
        if (
          url.protocol !== "https:" ||
          url.hostname !== "registry.npmjs.org" ||
          url.username ||
          url.password ||
          url.search ||
          url.hash
        )
          findings.push({ ...item, reason: "untrusted-resolution" });
      } catch {
        findings.push({ ...item, reason: "invalid-resolution" });
      }
    }
    if (
      typeof metadata.integrity !== "string" ||
      !/^sha512-[A-Za-z0-9+/]+=*$/.test(metadata.integrity)
    )
      findings.push({ ...item, reason: "missing-sha512-integrity" });
    if (typeof metadata.license !== "string")
      findings.push({ ...item, reason: "missing-license" });
    else if (FORBIDDEN_LICENSE.test(metadata.license))
      findings.push({ ...item, reason: "forbidden-license" });
  }
  return findings;
}

export async function reviewDependencies(root = process.cwd()) {
  const findings = [];
  for (const filename of LOCKFILES) {
    const lock = JSON.parse(await readFile(resolve(root, filename), "utf8"));
    findings.push(...inspectLockfile(lock, filename));
  }
  return findings;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  reviewDependencies()
    .then((findings) => {
      for (const finding of findings)
        process.stderr.write(`${JSON.stringify(finding)}\n`);
      if (findings.length) process.exitCode = 1;
      else process.stdout.write("Dependency lockfile review passed\n");
    })
    .catch(() => {
      process.stderr.write("Dependency lockfile review failed\n");
      process.exitCode = 1;
    });
}
