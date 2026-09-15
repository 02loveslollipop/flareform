# Trusted-main deployment and rollback

The deployment workflow is inert unless the repository variable
`FLAREFORM_DEPLOY_ENABLED` is exactly `true`, and the environment itself accepts
only `main`. Do not enable it until M2–M7 are approved and merged, real policy is
committed, the smoke grant uses the immutable FlareForm repository/owner IDs,
and all protected secrets are configured.

The production environment contains a Worker deployment token as
`CLOUDFLARE_DEPLOY_TOKEN`, D1 policy credential, real account/database IDs, and
the complete Wrangler binding configuration. It must not contain or recreate
the runtime `CLOUDFLARE_DNS_TOKEN`; that token remains only in the Worker secret
store and cannot deploy the Worker. Client repositories receive neither
credential.

The workflow installs from lockfiles, audits dependencies, scans tracked files,
runs every check, captures the previous Worker version, applies only reviewed
forward-compatible migrations, atomically syncs policy, deploys, checks the
fixed health response, and performs an authenticated read-only two-zone plan.
A failed migration or policy sync stops before deployment. A failed policy sync
does not replace the active policy. A failed post-deploy smoke test rolls the
Worker back to the captured version.

D1 migrations are forward-only; never deploy a schema change that makes the
previous Worker unsafe. Policy is not guessed or automatically reversed after
a later failure. If rollback occurs, disable deployment/apply, compare the
active policy version with the reviewed prior Git commit, and explicitly sync a
reviewed compatible policy if required. Preserve the failed run, operation IDs,
inventory, and audit records.

Initial deployment has no previous version to restore. Keep
`FLAREFORM_DEPLOY_ENABLED` false, deploy the bootstrap version manually through
the same environment credential, verify health and plan, then enable trusted
main deployment. Never run deployment from a pull request or a milestone
branch.
