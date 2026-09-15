# Indeterminate DNS operation recovery

An operation becomes indeterminate when FlareForm persisted a mutation as sent but cannot prove both the Cloudflare result and its D1 confirmation. The affected record-set lock must remain in place. Do not delete the lock, claim, mutation intent, checkpoint, or operation row manually, and do not rerun the DNS mutation from a project workflow.

Recovery is an operator-only control-plane procedure. It is deliberately absent from the public Worker routes. Run the administrative reconciliation module from a protected environment with a D1 binding, the same zone-limited Cloudflare DNS token, and an immutable numeric operator identity. First invoke `inspectIndeterminate` for the exact operation ID and client key. Preserve its redacted evidence with the incident record and independently compare the D1 intent/audit history, record ID, complete same-name/type Cloudflare set, and FlareForm tags/comment.

Choose one resolution explicitly:

- `confirm-provider` only when the provider state proves the requested outcome. Create/update requires exactly one record carrying the expected repository/client metadata; update must retain the expected record ID. Delete requires the expected record ID to be absent.
- `confirm-no-change` only when the provider state proves no mutation took effect. Create requires no matching record. Update/delete requires the original record ID and FlareForm ownership metadata to remain present.

If evidence is missing, duplicated, unmanaged, conflicting, or otherwise ambiguous, stop. Leave the operation frozen and investigate Cloudflare audit logs and account activity. The reconciliation code never guesses ownership and never issues a DNS mutation. A successful resolution updates D1, records the operator ID and decision in `audit_log`, releases only the exact resolved record-set lock, and marks the zone/operation reconciled only after all locks are resolved.

The Worker's scheduled handler retains audit events and periodic DNS evidence in D1. `audit_log` is append-only; each scheduled execution writes one immutable `maintenance_runs` row plus relational zone, record, and ownership-finding rows in a single batch. A retry reuses the existing run for the same scheduled timestamp. Restrict D1 administration separately from the runtime DNS credential and retain reviewed D1 backups according to the operator's incident-retention requirements.
