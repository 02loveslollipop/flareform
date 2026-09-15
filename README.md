# FlareForm

FlareForm is a secure, declarative Cloudflare DNS control plane for GitHub Actions. It is being built to let approved application workflows reconcile A, AAAA, CNAME, and SRV records in specific DNS namespaces without giving those repositories Cloudflare credentials. TXT is opt-in; NS delegation and other record types are out of v1 scope.

This public repository contains the reviewed application source, tests, and
inert operator examples. It intentionally contains no active production
workflow, deployment policy, infrastructure identifier, credential, inventory,
or audit evidence. Operators must maintain those values in a separate private
deployment repository.

## Architecture

The intended trust path is: a protected GitHub Actions job obtains a short-lived OIDC token; the FlareForm Worker verifies its identity and trusted policy; the Worker reconciles records through a Cloudflare token held only as a Worker secret; D1 records ownership, replay protection, plans, operations, and audit events. The initial Cloudflare token must be limited to exactly `example.com` and `example.net`, not all account zones. A repository policy may separately grant exact names and strict descendants in either zone.

Mirrored services may request both zones in one operation, but the provider calls are not atomic across zones. A failure in one zone must be reported and recovered explicitly. FlareForm never automatically adopts an existing unmanaged record, and access to a hostname does not imply ownership of records already there.

Namespace ownership is deliberately stricter than hostname-set overlap: two
repositories cannot split the exact root and descendants of the same root.
This keeps one trusted owner for a service namespace even though those grants
match disjoint DNS names. Model separate application namespaces under a zone
instead of granting one repository a zone-wide descendant namespace.

## Local development

Use Node.js 24 and npm 11. From a clean checkout:

```sh
npm ci
npm run check
```

`npm run check` verifies formatting, lint, unit/integration/security tests, the Worker/Action bundles, and that the committed Action bundle matches source. `npm run build` refreshes generated bundles; `github-action/dist/index.js` is intentionally committed and must be reviewed with source changes. Local tests must not use real GitHub or Cloudflare credentials.

The production Action accepts only the workspace-relative manifest path and
`plan` or `apply`. It resolves explicitly referenced `${VARIABLE}` values as
YAML scalar content, obtains a new GitHub OIDC token for each request, and sends
that token only to the compiled `https://dns.02labs.me` origin with redirects
disabled. Apply first renders a current plan and performs at most one retry for
an explicit partial-zone failure. The Action never accepts an API endpoint or
audience override.

All changes to `main` go through pull requests with the public CI and dependency
review checks. See [CONTRIBUTING.md](./CONTRIBUTING.md).

The repository has no configured D1 database or production deployment credentials yet. `wrangler.jsonc` contains only development-safe settings, including a per-repository Worker rate-limit binding. Any operator-supplied deployment config must bind the production D1 database as `DB` and retain `RATE_LIMITER`. D1 is the sole persistence layer: it holds operational audit events plus immutable, relational inventory and ownership snapshots written by the UTC Cron Trigger. The rate limit is defense-in-depth, not authorization. Do not commit Cloudflare account/zone IDs, API tokens, OIDC tokens, `.dev.vars`, or local databases.

The public API is fixed to `https://dns.02labs.me`: `GET /healthz`, `POST /v1/plan`, and `POST /v1/apply`. Plan/apply require `application/json`, a GitHub-issued JWT with audience `https://dns.02labs.me`, and a trusted D1 policy match for immutable repository/owner IDs, exact subject, workflow, protected ref, event, production environment, and GitHub-hosted runner. Apply additionally requires typed GitHub run, attempt, actor, JTI, and expiry claims. The request body may contain only `manifest` (and optional `plan_id` on apply); deletion requires a matching, unexpired, one-time plan. The endpoints need trusted D1 policy, `CLOUDFLARE_DNS_TOKEN`, and a separate 32-byte-or-longer `PLAN_HMAC_KEY` Worker secret. Public digests are keyed so low-entropy TXT data cannot be guessed from a plain hash. Apply authorizes and snapshots all zones before admission, reserves record sets atomically, re-reads each set before mutation, and never retries a sent-but-unconfirmed provider request. Cross-zone execution is intentionally not atomic: confirmed zones are retained, pre-send failures can resume, and uncertain outcomes freeze their record sets for explicit operator reconciliation. `scripts/cleanup-jti.js` is an operator-only local/remote maintenance command; it removes expired replay entries and requires explicit confirmation for remote use.

The initial D1 schema is in `migrations/`. Once an operator has created a D1
database and an uncommitted Wrangler config binding it as `DB`, apply migrations
with `npm run migrate:local -- --config <config-path>` for local development or
`npm run migrate:remote -- --config <config-path> --confirm-remote` from a
protected administrative environment. Wrangler tracks applied versions in
`d1_migrations`; remote migration is not part of the public Worker API.

The trusted policy format is illustrated in `config/examples/`. Copy the
examples into `config/zones.yaml` and `config/repositories/*.yaml`, replacing
all placeholder IDs with real immutable GitHub and Cloudflare IDs before any
production sync. `node scripts/sync-config.js --validate --config-dir config`
and `--dry-run` require no credential. The operator-only `--apply` mode needs
an explicit `--confirm-remote`, account/database IDs, and a separate
`FLAREFORM_D1_ADMIN_TOKEN` with D1 write access. It never uses the runtime DNS
token or an application OIDC token. Policy changes are one D1 batch transaction,
with an immutable version snapshot and audit entry. No public administration
route exists.

Inert examples of deployment and administrative workflows live under
`examples/github-workflows/`. Copy and review them only in a private deployment
repository. GitHub does not execute workflows from that directory.

## Onboarding path

After the security-sensitive implementation and tests are complete, the operator creates D1 and a two-zone-scoped Cloudflare DNS token, configures the binding and secret in the protected deployment environment, syncs reviewed repository policies, and first runs plan-only integration. Production adoption of existing records requires an explicit trusted administrative step. Deployment must remain disabled until those gates are documented and verified.

Indeterminate operations cannot be repaired through the public API. Follow the [operator recovery procedure](./docs/indeterminate-recovery.md); inspection is read-only, ambiguous evidence is rejected, and every resolution requires an explicit operator decision recorded in audit history.

Administrative migration is likewise absent from the public API. The protected
control-plane workflow can adopt exactly one existing record after
`scripts/adopt-record.js` validates the repository ID, client key, canonical
zone, record ID, grant, type, D1 ownership, and provider metadata. Use
`scripts/inventory-dns.js` for a read-only all-zone inventory and
`scripts/audit-ownership.js` for non-repairing mismatch reports. See the
[bootstrap](./docs/bootstrap.md) and [staged migration](./docs/migration.md)
runbooks before configuring any real ID or credential.

## Security

Read [SECURITY.md](./SECURITY.md) before enabling a repository grant. A maintainer who can change and approve a protected production workflow can exercise that repository's DNS grant. FlareForm does not defend against compromise of the Cloudflare account itself.
