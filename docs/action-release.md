# Action release procedure

The production Action lives in `github-action/` and is published from this
repository. Do not create a separate Action repository or publish a development
bundle under the production Action name.

After the release PR is independently approved, merged to protected `main`,
and clean-checkout CI passes on the merge commit:

1. Confirm `npm ci`, `npm ci --prefix github-action`, `npm run check`, and
   `npm audit --prefix github-action --omit=dev` pass from a clean checkout.
2. Confirm `github-action/dist/index.js` exactly matches its source build and
   `github-action/THIRD_PARTY_NOTICES.md` matches the locked bundled packages.
3. Create a signed immutable release tag such as `action-v1.0.0` on the reviewed
   merge commit. Never move or reuse an immutable release tag.
4. A mutable `action-v1` discovery tag may be advanced only through the trusted
   release process after the target immutable release is approved. Client
   examples and production workflows must still consume the reviewed full
   40-character commit SHA, not either tag.
5. Attach the CI run, dependency audit, reviewed source SHA, generated bundle
   SHA-256, and independent approvals to the GitHub release notes.

No release tag is created from a draft or unmerged branch. Local and
test endpoint injection exists only through source-level dependency injection;
the production metadata and bundle expose no development endpoint or audience.
