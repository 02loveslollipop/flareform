import assert from "node:assert/strict";
import test from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import {
  createOidcVerifier,
  OIDC_AUDIENCE,
  OIDC_ISSUER,
} from "../../src/auth/oidc.js";
import { createWorker } from "../../src/http/router.js";
import { sqliteD1 } from "../helpers/sqlite-d1.js";

test("M2 exit: only a valid signed GitHub identity and valid HTTP envelope reach business", async (t) => {
  const { db, sqlite, close } = sqliteD1();
  t.after(close);
  sqlite
    .prepare(
      "INSERT INTO repositories(github_repository_id, github_owner_id, display_name, expected_workflow_ref, created_at, updated_at) VALUES (?,?,?,?,?,?)",
    )
    .run(
      "123",
      "456",
      "repo",
      "owner/repo/.github/workflows/deploy.yml@refs/heads/main",
      "now",
      "now",
    );
  const pair = await generateKeyPair("RS256", { extractable: true });
  const jwk = {
    ...(await exportJWK(pair.publicKey)),
    kid: "test-key",
    use: "sig",
    alg: "RS256",
  };
  const verify = createOidcVerifier({
    fetchImpl: async (url) =>
      Response.json(
        url.endsWith("jwks")
          ? { keys: [jwk] }
          : {
              issuer: OIDC_ISSUER,
              jwks_uri: `${OIDC_ISSUER}/.well-known/jwks`,
              id_token_signing_alg_values_supported: ["RS256"],
            },
      ),
  });
  const now = Math.floor(Date.now() / 1000);
  const token = (claims = {}) =>
    new SignJWT({
      iss: OIDC_ISSUER,
      aud: OIDC_AUDIENCE,
      sub: "repo:owner/repo:environment:production",
      jti: "test-jti",
      repository_id: "123",
      repository_owner_id: "456",
      event_name: "push",
      ref: "refs/heads/main",
      environment: "production",
      workflow_ref: "owner/repo/.github/workflows/deploy.yml@refs/heads/main",
      runner_environment: "github-hosted",
      iat: now,
      exp: now + 300,
      ...claims,
    })
      .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: "test-key" })
      .sign(pair.privateKey);
  let reached = 0;
  const worker = createWorker({
    verify,
    business: async () => {
      reached++;
      return Response.json({ planned: true });
    },
  });
  const env = {
    DB: db,
    RATE_LIMITER: { limit: async () => ({ success: true }) },
  };
  const request = (jwt, body = '{"manifest":"version: 1"}') =>
    new Request("https://dns.02labs.me/v1/plan", {
      method: "POST",
      headers: {
        authorization: `Bearer ${jwt}`,
        "content-type": "application/json",
      },
      body,
    });
  assert.equal((await worker.fetch(request(await token()), env)).status, 200);
  assert.equal(reached, 1);
  assert.equal(
    (await worker.fetch(request(await token({ repository_id: "999" })), env))
      .status,
    403,
  );
  assert.equal(
    (
      await worker.fetch(
        request(await token(), '{"manifest":"a","manifest":"b"}'),
        env,
      )
    ).status,
    400,
  );
  assert.equal(reached, 1);
});
