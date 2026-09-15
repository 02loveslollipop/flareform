import { createLocalJWKSet, errors, jwtVerify } from "jose";
import { FlareFormError } from "../errors.js";
import { parseStrictJson } from "../strict-json.js";

export const OIDC_ISSUER = "https://token.actions.githubusercontent.com";
export const OIDC_AUDIENCE = "https://dns.02labs.me";
const DISCOVERY_URL = `${OIDC_ISSUER}/.well-known/openid-configuration`;
const JWKS_URL = `${OIDC_ISSUER}/.well-known/jwks`;
const MAX_TOKEN_BYTES = 12288;
const CACHE_MS = 300000;
const ROTATION_REFRESH_MS = 30000;
const SKEW_SECONDS = 30;
const MAX_AGE_SECONDS = 300;

function invalid() {
  throw new FlareFormError("INVALID_TOKEN");
}
function decodePart(part, limit) {
  if (!/^[A-Za-z0-9_-]+$/.test(part) || part.length > limit) invalid();
  try {
    const binary = atob(part.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = Uint8Array.from(binary, (character) =>
      character.charCodeAt(0),
    );
    return parseStrictJson(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
      { maxBytes: limit },
    );
  } catch {
    invalid();
  }
}
function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function nonempty(value, max = 512) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= max &&
    !/[\x00-\x1f\x7f]/.test(value)
  );
}
function typedClaims(payload) {
  if (payload.iss !== OIDC_ISSUER || payload.aud !== OIDC_AUDIENCE) invalid();
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
  ])
    if (!nonempty(payload[field])) invalid();
  if (
    !/^[1-9][0-9]*$/.test(payload.repository_id) ||
    !/^[1-9][0-9]*$/.test(payload.repository_owner_id)
  )
    invalid();
  if (
    payload.job_workflow_ref !== undefined &&
    !nonempty(payload.job_workflow_ref)
  )
    invalid();
  if (!["exp", "iat"].every((field) => Number.isSafeInteger(payload[field])))
    invalid();
  if (payload.nbf !== undefined && !Number.isSafeInteger(payload.nbf))
    invalid();
  return payload;
}
function validateJwks(jwks) {
  if (
    !plainObject(jwks) ||
    Object.keys(jwks).join() !== "keys" ||
    !Array.isArray(jwks.keys) ||
    jwks.keys.length < 1 ||
    jwks.keys.length > 12
  )
    invalid();
  const seen = new Set();
  for (const key of jwks.keys) {
    if (
      !plainObject(key) ||
      key.kty !== "RSA" ||
      !nonempty(key.kid, 128) ||
      key.use !== "sig" ||
      (key.alg !== undefined && key.alg !== "RS256") ||
      (key.key_ops !== undefined &&
        (!Array.isArray(key.key_ops) || key.key_ops.join() !== "verify")) ||
      !/^[A-Za-z0-9_-]{342,}$/.test(key.n ?? "") ||
      key.e !== "AQAB" ||
      seen.has(key.kid) ||
      ["d", "p", "q", "dp", "dq", "qi", "jku", "x5u"].some(
        (field) => field in key,
      )
    )
      invalid();
    seen.add(key.kid);
  }
  return jwks;
}

/** The fetch implementation may be injected by tests, but destination URLs cannot. */
export function createOidcVerifier({
  fetchImpl = fetch,
  now = () => Date.now(),
} = {}) {
  let cache = null;
  let pending = null;
  async function fetchJson(url, limit) {
    const signal = AbortSignal.timeout(3000);
    const bounded = (promise) =>
      new Promise((resolve, reject) => {
        const timeout = () => reject(new FlareFormError("INVALID_TOKEN"));
        signal.addEventListener("abort", timeout, { once: true });
        Promise.resolve(promise)
          .then(resolve, reject)
          .finally(() => signal.removeEventListener("abort", timeout));
      });
    const response = await bounded(
      fetchImpl(url, {
        redirect: "error",
        signal,
        headers: { accept: "application/json" },
      }),
    );
    if (
      !response.ok ||
      response.redirected ||
      (response.url && response.url !== url)
    )
      invalid();
    const reader = response.body?.getReader();
    if (!reader) invalid();
    const chunks = [];
    let size = 0;
    try {
      while (true) {
        const { done, value } = await bounded(reader.read());
        if (done) break;
        size += value.byteLength;
        if (size > limit) invalid();
        chunks.push(value);
      }
    } finally {
      if (signal.aborted) await reader.cancel().catch(() => {});
      reader.releaseLock();
    }
    const body = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.length;
    }
    return parseStrictJson(
      new TextDecoder("utf-8", { fatal: true }).decode(body),
      { maxBytes: limit, maxDepth: 12, maxNodes: 128 },
    );
  }
  async function refresh() {
    if (pending) return pending;
    pending = (async () => {
      const metadata = await fetchJson(DISCOVERY_URL, 8192);
      if (
        !plainObject(metadata) ||
        metadata.issuer !== OIDC_ISSUER ||
        metadata.jwks_uri !== JWKS_URL ||
        !Array.isArray(metadata.id_token_signing_alg_values_supported) ||
        !metadata.id_token_signing_alg_values_supported.includes("RS256")
      )
        invalid();
      const jwks = validateJwks(await fetchJson(JWKS_URL, 65536));
      const next = {
        resolve: createLocalJWKSet(jwks),
        loaded: now(),
        expires: now() + CACHE_MS,
      };
      cache = next;
      return next;
    })();
    try {
      return await pending;
    } finally {
      pending = null;
    }
  }
  return async function verify(token) {
    if (
      typeof token !== "string" ||
      token.length > MAX_TOKEN_BYTES ||
      token.split(".").length !== 3
    )
      invalid();
    const [headerPart, payloadPart] = token.split(".");
    const header = decodePart(headerPart, 4096);
    const rawPayload = decodePart(payloadPart, 8192);
    if (
      !plainObject(header) ||
      header.alg !== "RS256" ||
      header.typ !== "JWT" ||
      !nonempty(header.kid, 128) ||
      Object.keys(header).some((key) => !["alg", "typ", "kid"].includes(key)) ||
      !plainObject(rawPayload)
    )
      invalid();
    typedClaims(rawPayload);
    const options = {
      algorithms: ["RS256"],
      issuer: OIDC_ISSUER,
      audience: OIDC_AUDIENCE,
      clockTolerance: SKEW_SECONDS,
      maxTokenAge: `${MAX_AGE_SECONDS}s`,
      currentDate: new Date(now()),
    };
    try {
      let current = cache && cache.expires > now() ? cache : await refresh();
      let verified;
      try {
        verified = await jwtVerify(token, current.resolve, options);
      } catch (error) {
        if (
          !(error instanceof errors.JWKSNoMatchingKey) ||
          now() - current.loaded < ROTATION_REFRESH_MS
        )
          throw error;
        current = await refresh();
        verified = await jwtVerify(token, current.resolve, options);
      }
      return typedClaims(verified.payload);
    } catch (error) {
      if (error instanceof errors.JWTExpired)
        throw new FlareFormError("TOKEN_EXPIRED");
      invalid();
    }
  };
}

export function authorizeOidcClaims(claims, repository) {
  if (!repository || repository.enabled !== 1)
    throw new FlareFormError("UNKNOWN_REPOSITORY");
  if (
    claims.repository_id !== repository.github_repository_id ||
    claims.repository_owner_id !== repository.github_owner_id
  )
    throw new FlareFormError("INVALID_OWNER");
  const workflow = repository.expected_workflow_ref;
  const repositoryName = workflow?.split("/.github/workflows/")[0];
  const subject = `repo:${repositoryName}:environment:${repository.allowed_environment}`;
  if (!repositoryName || claims.sub !== subject)
    throw new FlareFormError("INVALID_SUBJECT");
  if (claims.event_name !== repository.allowed_event)
    throw new FlareFormError("INVALID_EVENT");
  if (claims.ref !== repository.allowed_ref)
    throw new FlareFormError("INVALID_REF");
  if (claims.environment !== repository.allowed_environment)
    throw new FlareFormError("INVALID_ENVIRONMENT");
  if (
    claims.workflow_ref !== workflow ||
    (repository.expected_job_workflow_ref &&
      claims.job_workflow_ref !== repository.expected_job_workflow_ref)
  )
    throw new FlareFormError("INVALID_WORKFLOW");
  if (
    claims.runner_environment !== "github-hosted" ||
    repository.allowed_runner_environment !== "github-hosted"
  )
    throw new FlareFormError("INVALID_RUNNER_ENVIRONMENT");
  return { ...claims, repository };
}

export const oidcVerifier = createOidcVerifier();
