# Public source and private deployment

This repository is the canonical public source. It contains no production
configuration. The files under `examples/github-workflows/` are inert examples;
copying them into `.github/workflows/` activates them and must happen only in a
separately protected private deployment repository.

Promote reviewed public commits into the private repository in one direction.
Do not add the private repository as a remote in a public working clone. In the
private clone, make the public remote fetch-only and merge a recorded public
commit through a reviewed pull request. Private fixes must be recreated as a
sanitized public patch; never push or cherry-pick a private deployment commit
into this repository.

The private repository owns active deployment and administration workflows,
real policy and immutable IDs, smoke configuration, and operational evidence.
Credentials remain in protected GitHub environments or the Worker secret store,
never in either Git tree.
