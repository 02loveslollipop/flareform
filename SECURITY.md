# Security policy

FlareForm is not production-ready. Do not deploy this scaffold as a DNS control plane.

## Threat model and boundaries

The public Worker endpoint is untrusted input. GitHub OIDC proves the identity of a particular job, not its authorization; immutable repository/owner IDs, workflow context, protected ref/environment, namespace grants, record type, operation permission, and ownership must all pass independently. Client repositories never receive a Cloudflare credential and cannot choose Cloudflare zone/record IDs or API origins.

The `flareform` repository, policy files, migration and adoption tools, deployment workflow, D1, and Worker secret store are administrative trust boundaries. A malicious or compromised maintainer who can change **and approve** a protected production workflow can exercise that repository's DNS grant. Branch protection, CODEOWNERS, protected environments, minimal collaborators, passkeys/2FA, and independent review where possible are required operator controls; a solo maintainer cannot create an independent approval by approving their own work.

FlareForm cannot protect records if the Cloudflare account, its administrators, or its DNS token are compromised. Limit the runtime token to DNS write on the two intended zones, keep the deployment credential separate, rotate tokens on suspicion, and compare DNS inventory against an external backup. A Worker or D1 compromise can also affect DNS and local audit evidence; export audit events to an append-only external destination and retain recoverable DNS snapshots.

Access to a hostname does not confer ownership of existing records. Unmanaged records require explicit administrative adoption. Prune is separately authorized and bounded. Cross-zone operations are **not atomic**: one zone may change while another fails. Operations must checkpoint partial outcomes, fail clearly, and require safe reconciliation before further mutation when state is indeterminate.

## Reporting a vulnerability

Do not file a public issue containing exploit details, tokens, private DNS data, or personally identifying information. Contact the repository owner through a private GitHub security advisory for this repository. Include affected component, reproduction, expected/observed boundary, and a safe contact channel. If advisories are unavailable, ask the owner for a private channel without disclosing the details publicly. No response-time SLA is promised.

## Incident response entry points

On suspected unauthorized DNS changes: pause trusted apply/deployment workflows; revoke or rotate the Worker DNS token and relevant deployment credential; inspect Cloudflare audit events and compare the two-zone DNS inventory to a known-good external snapshot; inspect FlareForm operation/audit records and GitHub workflow approvals; recover affected records through a separately authorized operator path; and restore service only after the authorization or ownership gap is resolved. Preserve evidence before cleanup. A stolen GitHub OIDC JWT is short-lived but may still permit mutation until expiry unless its job or repository grant is disabled.

The detailed design and adversarial test catalogue are maintained locally outside Git during early development.
