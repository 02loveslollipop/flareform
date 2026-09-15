## Change and risk

What changed:

Security boundaries affected:

Rollback or recovery plan:

## Verification

- [ ] `npm ci` and `npm ci --prefix github-action` pass from a clean checkout.
- [ ] `npm run check` passes, including relevant security tests.
- [ ] New or changed security behavior has negative and boundary tests.
- [ ] No credential, raw OIDC token, or environment-specific identifier is committed.
- [ ] Generated `github-action/dist` matches reviewed Action source, if changed.
- [ ] `node scripts/check-public-release.js` finds no private deployment data.

Test IDs and run evidence: <!-- Include links to CI and any local/staging evidence. Do not paste secrets. -->

## Review

Reviewer, reviewed head SHA, test evidence, and unresolved findings:
