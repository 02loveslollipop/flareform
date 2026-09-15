# Operations, monitoring, and incident response

The daily scheduled handler deletes only expired replay JTIs and expired plans
that have no admission evidence. It exports each audit event immutably, writes a
complete DNS inventory and an ownership report to R2, and emits one bounded JSON
summary. Configure monitoring on `success:false`, `inventory_complete:false`,
`ownership_complete:false`, or a nonzero `ownership_findings`. Also alert on
application audit/error counts for authorization denials, replay, prune attempts,
partial or indeterminate operations, and audit-export failure. Alert payloads
must contain only counts, stable error codes, operation IDs, and canonical names;
never forward headers, JWTs, tokens, upstream bodies, or TXT content.

Cloudflare separately alerts on API-token changes. Review the runtime token after
every alert and at release: DNS Write only, exactly the two configured zone
resources, with no Worker, account-setting, token, or third-zone permission.
Compare the active zone IDs with reviewed policy. Treat any unexplained token or
zone-scope change as a control-plane compromise.

## Rotation and emergency revocation

Create a replacement token with the same exact two-zone DNS scope, add it to the
Worker secret store through the protected administration environment, deploy a
configuration-only version, and run health plus read-only plan checks before
revoking the old token. Never print, persist in a file/artifact, or pass the token
to a client repository. For emergency revocation, revoke first, disable apply and
deployment, preserve audit/inventory evidence, and verify mutation requests fail
closed. Planning may also be unavailable because it needs a current DNS read;
that is safer than using stale state. Restore service only with a newly scoped
token after ownership audit is clean.

## Incident runbooks

- Leaked runtime token: revoke it, disable apply, inspect Cloudflare audit events
  and both-zone inventory, reconcile ownership, rotate, and exercise a read-only
  plan before re-enabling mutations.
- Compromised application repository: disable that immutable repository ID in
  policy, cancel workflows, rotate any repository secrets, inventory its grants,
  and do not transfer claims automatically.
- Compromised control plane or maintainer: disable deployment and runtime token,
  preserve GitHub/Cloudflare/R2 logs outside the account, restore a reviewed
  commit and policy using recovered administrative access, then rotate all
  credentials and account recovery factors.
- Ownership mismatch: freeze the affected operation/namespace, preserve the
  immutable inventory and audit export, and follow `indeterminate-recovery.md`.
  Never repair or adopt based only on a matching name or value.
- Zone/provider outage: stop apply, retain operation locks and partial status,
  avoid retries with unknown mutation outcome, and reconcile each zone after the
  provider recovers. Do not describe the mirrored operation as atomic.

Quarterly, restore an inventory into an isolated fake/staging zone and compare
the reconstructed record set without giving application repositories an admin
credential. Separately retrieve audit objects with D1 unavailable. Record token
rotation/revocation and compromised-repository/control-plane tabletop evidence.
