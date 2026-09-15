import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const RULES = [
  ["private-key", /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g],
  ["github-token", /\bgh[opusr]_[A-Za-z0-9]{30,}\b/g],
  ["aws-access-key", /\bAKIA[0-9A-Z]{16}\b/g],
  [
    "literal-cloudflare-secret",
    /\bCLOUDFLARE_(?:API_)?(?:TOKEN|KEY)\s*[:=]\s*["']?[A-Za-z0-9_-]{24,}/gi,
  ],
  ["literal-bearer", /\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9._-]{32,}\b/gi],
];

export function scanText(text) {
  if (typeof text !== "string") throw new TypeError("text required");
  const findings = [];
  for (const [rule, expression] of RULES) {
    expression.lastIndex = 0;
    for (const match of text.matchAll(expression))
      findings.push({
        rule,
        line: text.slice(0, match.index).split("\n").length,
      });
  }
  return findings;
}

export function scanTrackedFiles(root = process.cwd()) {
  const names = execFileSync("git", ["ls-files", "-z"], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 4 * 1024 * 1024,
  })
    .split("\0")
    .filter(Boolean);
  const findings = [];
  for (const name of names) {
    const buffer = readFileSync(resolve(root, name));
    if (buffer.length > 2 * 1024 * 1024 || buffer.includes(0)) continue;
    for (const finding of scanText(buffer.toString("utf8")))
      findings.push({ file: name, ...finding });
  }
  return findings;
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  const findings = scanTrackedFiles();
  for (const finding of findings)
    process.stderr.write(
      `Potential secret: ${finding.file}:${finding.line} (${finding.rule})\n`,
    );
  if (findings.length) process.exitCode = 1;
  else process.stdout.write("No tracked secret patterns found\n");
}
