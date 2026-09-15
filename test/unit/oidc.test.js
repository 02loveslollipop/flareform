import assert from "node:assert/strict";
import test from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import {
  authorizeOidcClaims,
  createOidcVerifier,
  OIDC_AUDIENCE,
  OIDC_ISSUER,
} from "../../src/auth/oidc.js";

const discovery = {
  issuer: OIDC_ISSUER,
  jwks_uri: `${OIDC_ISSUER}/.well-known/jwks`,
  id_token_signing_alg_values_supported: ["RS256"],
};
const policy = {
  github_repository_id: "123",
  github_owner_id: "456",
  enabled: 1,
  expected_workflow_ref:
    "owner/repo/.github/workflows/deploy.yml@refs/heads/main",
  expected_job_workflow_ref: null,
  allowed_ref: "refs/heads/main",
  allowed_environment: "production",
  allowed_event: "push",
  allowed_runner_environment: "github-hosted",
};
const base = {
  iss: OIDC_ISSUER,
  aud: OIDC_AUDIENCE,
  sub: "repo:owner/repo:environment:production",
  jti: "unique-jti",
  repository_id: "123",
  repository_owner_id: "456",
  event_name: "push",
  ref: "refs/heads/main",
  environment: "production",
  workflow_ref: policy.expected_workflow_ref,
  runner_environment: "github-hosted",
};

async function fixture() {
  const pair = await generateKeyPair("RS256", { extractable: true });
  const jwk = {
    ...(await exportJWK(pair.publicKey)),
    kid: "key1",
    use: "sig",
    alg: "RS256",
  };
  let jwks = { keys: [jwk] };
  let metadata = discovery;
  let redirectDiscovery = false;
  let privateKey = pair.privateKey;
  let kid = "key1";
  let requests = 0;
  let clock = Date.now();
  const fetchImpl = async (url, options) => {
    requests++;
    assert.equal(options.redirect, "error");
    if (url.endsWith("openid-configuration"))
      return redirectDiscovery
        ? Response.redirect("https://evil.test/jwks")
        : Response.json(metadata);
    if (url.endsWith("jwks")) return Response.json(jwks);
    throw Error("untrusted URL");
  };
  const verify = createOidcVerifier({ fetchImpl, now: () => clock });
  const sign = (claims = {}, header = {}) =>
    new SignJWT({
      ...base,
      iat: Math.floor(clock / 1000),
      exp: Math.floor(clock / 1000) + 300,
      ...claims,
    })
      .setProtectedHeader({ alg: "RS256", typ: "JWT", kid, ...header })
      .sign(privateKey);
  return {
    verify,
    sign,
    pair,
    jwk,
    setJwks: (value) => {
      jwks = value;
    },
    setMetadata: (value) => {
      metadata = value;
    },
    redirectDiscovery: () => {
      redirectDiscovery = true;
    },
    rotate: async () => {
      const next = await generateKeyPair("RS256", { extractable: true });
      privateKey = next.privateKey;
      kid = "key2";
      jwks = {
        keys: [
          {
            ...(await exportJWK(next.publicKey)),
            kid,
            use: "sig",
            alg: "RS256",
          },
        ],
      };
    },
    advance: (milliseconds) => {
      clock += milliseconds;
    },
    count: () => requests,
  };
}

test("OIDC-UNIT-001 valid signed token and contextual claims pass", async () => {
  const f = await fixture();
  const claims = await f.verify(
    await f.sign({}, { x5t: "1B2M2Y8AsgTpgAmY7PhCfg".padEnd(27, "A") }),
  );
  assert.equal(authorizeOidcClaims(claims, policy).repository, policy);
});

test("OIDC-UNIT-002/004/005/006/013/014 invalid signature, issuer, audience, time and header fail", async () => {
  const f = await fixture();
  for (const claims of [
    { iss: "https://evil.test" },
    { aud: "https://evil.test" },
    { exp: 1 },
    { iat: 1 },
    { nbf: Math.floor(Date.now() / 1000) + 1000 },
  ])
    await assert.rejects(f.verify(await f.sign(claims)));
  for (const header of [
    { typ: "at+jwt" },
    { kid: "no-key" },
    { x5t: "not-a-sha1-thumbprint" },
    { jku: "https://evil.test/key" },
  ])
    await assert.rejects(f.verify(await f.sign({}, header)));
  const broken = await f.sign();
  const [brokenHeader, brokenPayload, brokenSignature] = broken.split(".");
  const flipped = brokenSignature[0] === "A" ? "B" : "A";
  await assert.rejects(
    f.verify(
      `${brokenHeader}.${brokenPayload}.${flipped}${brokenSignature.slice(1)}`,
    ),
  );
});

test("OIDC-UNIT-007/015/016 missing and mistyped identity fields fail", async () => {
  const f = await fixture();
  for (const field of [
    "jti",
    "sub",
    "repository_id",
    "repository_owner_id",
    "event_name",
    "ref",
    "environment",
    "workflow_ref",
    "runner_environment",
  ]) {
    await assert.rejects(f.verify(await f.sign({ [field]: undefined })), field);
    await assert.rejects(
      f.verify(await f.sign({ [field]: [base[field]] })),
      field,
    );
  }
  assert.throws(() =>
    authorizeOidcClaims({ ...base, sub: `${base.sub}:extra` }, policy),
  );
});

test("OIDC-UNIT-008/009/010/011/012 contextual policy checks fail independently", async () => {
  for (const mutation of [
    { repository_id: "999" },
    { repository_owner_id: "999" },
    { event_name: "pull_request" },
    { ref: "refs/heads/evil" },
    { environment: "staging" },
    { workflow_ref: "wrong" },
    { runner_environment: "self-hosted" },
    { sub: "repo:owner/repo:ref:refs/heads/main" },
  ])
    assert.throws(() => authorizeOidcClaims({ ...base, ...mutation }, policy));
  assert.throws(() =>
    authorizeOidcClaims(base, {
      ...policy,
      expected_job_workflow_ref:
        "owner/repo/.github/workflows/reuse.yml@refs/heads/main",
    }),
  );
  assert.doesNotThrow(() =>
    authorizeOidcClaims(
      {
        ...base,
        job_workflow_ref:
          "owner/repo/.github/workflows/reuse.yml@refs/heads/main",
      },
      {
        ...policy,
        expected_job_workflow_ref:
          "owner/repo/.github/workflows/reuse.yml@refs/heads/main",
      },
    ),
  );
});

test("OIDC-INT-001/004/005/006 fixed discovery, bounded rotation and cache failure", async () => {
  const f = await fixture();
  assert.equal((await f.verify(await f.sign())).jti, base.jti);
  const count = f.count();
  assert.equal((await f.verify(await f.sign())).jti, base.jti);
  assert.equal(f.count(), count);
  await f.rotate();
  await assert.rejects(f.verify(await f.sign())); // refresh cooldown is bounded
  f.advance(31000);
  assert.equal((await f.verify(await f.sign())).jti, base.jti);
  f.setJwks({ keys: [] });
  // A validated cached key remains usable until its fixed expiration.
  assert.equal((await f.verify(await f.sign())).jti, base.jti);
  f.advance(301000);
  await assert.rejects(f.verify(await f.sign()));
});

test("OIDC-INT-002/003 and SEC-JWT-001/002 redirect, malformed JWKS and duplicate payload fail", async () => {
  const redirected = await fixture();
  redirected.redirectDiscovery();
  await assert.rejects(redirected.verify(await redirected.sign()));
  const malformed = await fixture();
  malformed.setMetadata({ ...discovery, jwks_uri: "https://evil.test/jwks" });
  await assert.rejects(malformed.verify(await malformed.sign()));
  const unsupported = await fixture();
  unsupported.setJwks({ keys: [{ ...unsupported.jwk, kty: "EC" }] });
  await assert.rejects(unsupported.verify(await unsupported.sign()));
  const f = await fixture();
  f.setJwks({ keys: [f.jwk, f.jwk] });
  await assert.rejects(f.verify(await f.sign()));
  const token = await f.sign();
  const [header, payload, signature] = token.split(".");
  const duplicate = btoa(JSON.stringify(base).slice(0, -1) + ',"sub":"evil"}')
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
  await assert.rejects(f.verify(`${header}.${duplicate}.${signature}`));
  await assert.rejects(f.verify(`${header}.${payload}.!`));
  await assert.rejects(f.verify("x".repeat(13000)));
});
