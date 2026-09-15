# Secure bootstrap and disposable verification

Do not deploy from a milestone branch. Complete this procedure only from a
reviewed protected `main` commit, with the `dns-administration` and production
environment gates configured. Never invent IDs or copy the fixture IDs from
tests or example policy files.

## 1. Collect immutable identifiers

From the Cloudflare and GitHub administrative interfaces, collect the real
Cloudflare account ID, D1 database UUID, zone IDs for exactly `example.com` and
`example.net`, and the immutable GitHub repository and owner IDs for each
client. Keep production values in protected environment secrets or variables,
not source files. Run `node scripts/validate-bootstrap.js` with the environment
variables named in that script; it rejects missing, repeated, placeholder, and
confused identifiers and rejects reuse of the runtime token as the deployment
credential.

## 2. Create independent credentials

Create an account-owned runtime API token with only `Zone / DNS / Write` and a
resource selector containing exactly the two named zones. Do not select all
zones. Store it only as the Worker secret `CLOUDFLARE_DNS_TOKEN`. Independently
review its live permission and resource list in Cloudflare; the token itself
cannot prove to FlareForm that Cloudflare issued it with no wider scope.

Create a separate Worker deployment credential. It must not be supplied as
`CLOUDFLARE_DNS_TOKEN`, exposed to the public Worker, or made available to a
client repository. Use separate protected administrative credentials for D1
policy/adoption and DNS adoption. Revoke any credential whose scope cannot be
verified.

## 3. Provision and configure

1. Create D1 database `flareform`.
2. Create an uncommitted production Wrangler configuration binding D1 as `DB`
   and the required `RATE_LIMITER`; configure a UTC maintenance cron trigger.
3. Add the fixed custom route `dns.02labs.me` and store a separate random
   `PLAN_HMAC_KEY` Worker secret of at least 32 bytes.
4. Apply migrations in numeric order with `npm run migrate:remote -- --config
   <operator-config> --confirm-remote`. Stop on any failure.
5. Replace example policy values with the collected IDs, review grants in both
   zones, run policy validation/dry-run, and synchronize through the protected
   policy workflow. Confirm the active policy version before deploying.
6. Deploy the reviewed Worker using only the deployment credential. Verify
   `/healthz`, then run an authenticated, non-mutating plan from the exact
   protected client workflow.

## 4. Disposable two-zone lifecycle

Use unique disposable names under a grant created solely for verification. Save
an external inventory first. In `keep` mode, plan and create A records in both
zones, then verify Cloudflare content/metadata, D1 claims/managed rows, operation
   checkpoints, audit intent/outcome, and relational maintenance snapshots. Update both values and repeat all
checks. Finally enable prune through a separate reviewed policy change, obtain a
fresh deletion plan, delete both records, and verify DNS, D1, and audit state.

Record the real workflow run IDs, FlareForm operation IDs, policy version,
maintenance run ID, relevant audit row IDs, and reviewer/date in the release evidence.
Do not treat local mocks as this production gate. If either zone is partial or
indeterminate, stop and follow `docs/indeterminate-recovery.md`; never compensate
by blindly deleting or recreating records.
