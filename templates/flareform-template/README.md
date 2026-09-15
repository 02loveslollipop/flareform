# FlareForm client template

This template reconciles one service across `service.example.com` and
`service.example.net`. Rename the keys and names to the namespace granted
to this repository. The trusted FlareForm policy must contain this repository's
immutable repository and owner IDs and the exact workflow reference for
`.github/workflows/deploy-and-dns.yml` on `refs/heads/main`.

The example production job runs only after a push to `main`, uses the protected
`production` environment, serializes DNS deployments without cancelling an
in-flight run, and grants only `contents: read` plus job-scoped
`id-token: write`. It passes a non-secret deployment output to the manifest.
Replace the illustrative repository variable with the validated output from
your deployment provider.

Client repositories do not store a Cloudflare token, FlareForm API key, account
ID, zone ID, or configurable API endpoint. GitHub issues a short-lived OIDC
token to the job. FlareForm validates that identity and the server-side policy,
then uses its own zone-scoped Cloudflare credential.

`reconciliation: keep` creates or updates listed records and leaves omitted
owned records unchanged. Start every repository in this mode. Change to
`reconciliation: prune` only after a separate policy review enables prune, add
an explicit `prune_zones` list, and inspect the plan: apply will delete only
omitted records already owned by this repository, within the server deletion
limit.

The Action reference is pinned to the immutable M5 implementation commit for
reviewability. For production, replace it only with a newer reviewed full
40-character commit SHA; never replace it with a branch or mutable major tag.
