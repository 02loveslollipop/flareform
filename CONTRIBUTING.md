# Contributing

Open changes against `main` through a pull request. Run `npm ci`,
`npm ci --prefix github-action`, `npm run check`, both dependency audits,
`node scripts/scan-secrets.js`, and `node scripts/check-public-release.js`
before requesting review.

Never submit credentials, account or zone IDs, production policy, DNS inventory,
audit evidence, private repository identities, or active operator workflows.
Use `example.com`, `example.net`, and placeholder numeric IDs in tests and
documentation. Report security problems through the private process in
[SECURITY.md](./SECURITY.md), not a public issue.
