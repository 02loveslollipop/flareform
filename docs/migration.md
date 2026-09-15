# Staged DNS migration

Migrate one service and repository at a time. This workflow never bulk-adopts
records and never assigns unknown, shared, mail, verification, or global records
to an application repository.

1. Run `scripts/inventory-dns.js` to create a new mode-0600
   `migration/inventory.yaml`. An incomplete zone is a hard stop. Preserve a
   read-only copy as recovery evidence.
2. Inspect each candidate repository's deployment workflows, provider files,
   container files, documentation, environment templates, and deployment
   scripts. Record its production destination, current domain names, expected
   records, and mirrored domains in the inventory.
3. Classify every record as `repository-managed candidate`, `shared
   infrastructure`, `global/manual`, or `unknown`. MX, SPF, DKIM, DMARC, CAA,
   mail, verification, shared proxy, and unknown records remain unassigned by
   default.
4. Write a candidate repository policy and manifest only for confident matches.
   Start with `reconciliation: keep`, `allow_prune: false`, and Action operation
   `plan`. A plan must contain no unexpected create, update, or delete.
5. For each exact existing record, run `scripts/adopt-record.js --dry-run` with
   repository ID, client key, canonical zone, and Cloudflare record ID. Review
   its full output, then adopt that one record through the protected
   administrative workflow. Run `scripts/audit-ownership.js` after each record.
6. Enable Action apply only after the plan, metadata, D1 ownership, and audit
   evidence are clean. Observe a stable period before considering prune.
7. Enable prune only in a separate policy review. Require explicit prune zones,
   bounded deletions, and a recent matching plan.

Rollback means disabling the repository policy and trusted apply workflow,
preserving audit/inventory evidence, and restoring records from the pre-migration
inventory through an independently authorized operator. Do not delete ownership
rows or strip metadata until provider and D1 state agree. An ambiguous or
partially adopted record follows the indeterminate recovery procedure; it is not
automatically reassigned.
