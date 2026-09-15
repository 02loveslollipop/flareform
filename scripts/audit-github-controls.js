import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const REPOSITORY_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export function evaluateControls({ branch, environments }) {
  const findings = [];
  const checks = new Set(branch?.required_status_checks?.contexts ?? []);
  for (const required of ["check", "dependency-review"])
    if (!checks.has(required))
      findings.push(`missing-required-check:${required}`);
  if (branch?.required_status_checks?.strict !== true)
    findings.push("strict-status-checks-disabled");
  if (!branch?.required_pull_request_reviews)
    findings.push("pull-request-requirement-disabled");
  if (branch?.required_pull_request_reviews?.dismiss_stale_reviews !== true)
    findings.push("stale-review-dismissal-disabled");
  if (branch?.enforce_admins?.enabled !== true)
    findings.push("admin-enforcement-disabled");
  if (branch?.required_conversation_resolution?.enabled !== true)
    findings.push("conversation-resolution-disabled");
  if (branch?.allow_force_pushes?.enabled !== false)
    findings.push("force-push-enabled");
  if (branch?.allow_deletions?.enabled !== false)
    findings.push("protected-branch-deletion-enabled");
  for (const name of ["production", "dns-administration"]) {
    const environment = environments?.find(
      (candidate) => candidate.name === name,
    );
    if (!environment) {
      findings.push(`missing-environment:${name}`);
      continue;
    }
    if (
      environment.deployment_branch_policy?.custom_branch_policies !== true ||
      environment.branchPolicies?.length !== 1 ||
      environment.branchPolicies[0].name !== "main" ||
      environment.branchPolicies[0].type !== "branch"
    )
      findings.push(`unsafe-environment-branch-policy:${name}`);
  }
  return { valid: findings.length === 0, findings };
}

async function github(repository, path, token) {
  const response = await fetch(
    `https://api.github.com/repos/${repository}${path}`,
    {
      headers: {
        accept: "application/vnd.github+json",
        authorization: `Bearer ${token}`,
        "x-github-api-version": "2022-11-28",
      },
      redirect: "error",
      signal: AbortSignal.timeout(15_000),
    },
  );
  if (!response.ok) throw new Error("GitHub control query failed");
  return response.json();
}

export async function auditGithubControls(
  token = process.env.GITHUB_TOKEN,
  repository = process.env.GITHUB_REPOSITORY,
) {
  if (typeof token !== "string" || token.length < 20)
    throw new Error("GitHub token required");
  if (typeof repository !== "string" || !REPOSITORY_PATTERN.test(repository))
    throw new Error("GitHub repository required");
  const [branch, listed] = await Promise.all([
    github(repository, "/branches/main/protection", token),
    github(repository, "/environments", token),
  ]);
  const environments = await Promise.all(
    listed.environments.map(async (environment) => ({
      ...environment,
      branchPolicies: (
        await github(
          repository,
          `/environments/${encodeURIComponent(environment.name)}/deployment-branch-policies`,
          token,
        )
      ).branch_policies,
    })),
  );
  return evaluateControls({ branch, environments });
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(resolve(process.argv[1])).href
) {
  auditGithubControls()
    .then((result) => {
      process.stdout.write(`${JSON.stringify(result)}\n`);
      if (!result.valid) process.exitCode = 2;
    })
    .catch(() => {
      process.stderr.write("GitHub control audit failed\n");
      process.exitCode = 1;
    });
}
