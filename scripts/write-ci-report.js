import { mkdir, writeFile } from "node:fs/promises";

const status = ["success", "failure", "cancelled"].includes(
  process.env.CI_RESULT,
)
  ? process.env.CI_RESULT
  : "unknown";
const sha = /^[0-9a-f]{40}$/.test(process.env.GITHUB_SHA ?? "")
  ? process.env.GITHUB_SHA
  : null;
await mkdir("artifacts", { recursive: true });
await writeFile(
  "artifacts/ci-summary.json",
  `${JSON.stringify(
    {
      schema: 1,
      status,
      commit: sha,
      checks: [
        "clean npm installs",
        "dependency audits",
        "tracked secret patterns",
        "format",
        "lint",
        "unit",
        "integration",
        "security",
        "build",
        "Action bundle parity",
      ],
    },
    null,
    2,
  )}\n`,
  { mode: 0o600 },
);
