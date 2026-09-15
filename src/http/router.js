import { DnsRepository } from "../db/repository.js";
import { requireD1 } from "../db/connection.js";
import {
  authorizeOidcClaims,
  oidcVerifier,
  OIDC_AUDIENCE,
} from "../auth/oidc.js";
import { FlareFormError, unexpectedErrorResponse } from "../errors.js";
import { parseStrictJson } from "../strict-json.js";

export const MAX_BODY_BYTES = 65536;
const ROUTES = Object.freeze({
  "/healthz": "GET",
  "/v1/plan": "POST",
  "/v1/apply": "POST",
});
const BAD_HEADERS = [
  "forwarded",
  "x-forwarded-host",
  "x-http-method-override",
  "x-method-override",
  "x-original-url",
  "x-rewrite-url",
];
function invalid() {
  throw new FlareFormError("INVALID_REQUEST");
}
function awaitWithDeadline(promise, signal) {
  if (signal.aborted) throw new FlareFormError("REQUEST_TIMEOUT");
  return new Promise((resolve, reject) => {
    const timeout = () => reject(new FlareFormError("REQUEST_TIMEOUT"));
    signal.addEventListener("abort", timeout, { once: true });
    Promise.resolve(promise)
      .then(resolve, reject)
      .finally(() => signal.removeEventListener("abort", timeout));
  });
}
async function readBody(request, signal) {
  const length = request.headers.get("content-length");
  if (
    length !== null &&
    (!/^(?:0|[1-9]\d*)$/.test(length) || Number(length) > MAX_BODY_BYTES)
  )
    throw new FlareFormError("REQUEST_TOO_LARGE");
  const reader = request.body?.getReader();
  if (!reader) invalid();
  const chunks = [];
  let size = 0;
  try {
    while (true) {
      if (signal.aborted) throw new FlareFormError("REQUEST_TIMEOUT");
      const { done, value } = await awaitWithDeadline(reader.read(), signal);
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) throw new FlareFormError("REQUEST_TOO_LARGE");
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
  try {
    return parseStrictJson(
      new TextDecoder("utf-8", { fatal: true }).decode(body),
      { maxBytes: MAX_BODY_BYTES, maxDepth: 20, maxNodes: 1200 },
    );
  } catch {
    invalid();
  }
}
function validateEnvelope(body, route) {
  if (!body || typeof body !== "object" || Array.isArray(body)) invalid();
  const allowed =
    route === "/v1/apply" ? ["manifest", "plan_id"] : ["manifest"];
  if (
    Object.keys(body).some((key) => !allowed.includes(key)) ||
    typeof body.manifest !== "string" ||
    body.manifest.length < 1 ||
    body.manifest.length > MAX_BODY_BYTES
  )
    invalid();
  if (
    "plan_id" in body &&
    (typeof body.plan_id !== "string" || !/^[0-9a-f-]{36}$/i.test(body.plan_id))
  )
    invalid();
  return body;
}
async function defaultBusiness() {
  throw new FlareFormError("SERVICE_UNAVAILABLE");
}
async function defaultRepository(env, repositoryId) {
  const db = await requireD1(env);
  return new DnsRepository(db).getRepository(repositoryId);
}

export function createWorker({
  verify = oidcVerifier,
  lookupRepository = defaultRepository,
  business = defaultBusiness,
  now = () => Date.now(),
  requestTimeoutMs = 10000,
} = {}) {
  return {
    async fetch(request, env) {
      const correlationId = crypto.randomUUID();
      const deadline = AbortSignal.timeout(requestTimeoutMs);
      try {
        const url = new URL(request.url);
        if (
          url.origin !== OIDC_AUDIENCE ||
          url.username ||
          url.password ||
          url.search ||
          url.hash ||
          url.pathname.includes("%") ||
          url.pathname.includes("\\") ||
          (request.headers.has("host") &&
            request.headers.get("host") !== url.host) ||
          request.headers.has("content-encoding") ||
          BAD_HEADERS.some((header) => request.headers.has(header))
        )
          invalid();
        const requiredMethod = ROUTES[url.pathname];
        if (!requiredMethod) invalid();
        if (request.method !== requiredMethod)
          throw new FlareFormError("METHOD_NOT_ALLOWED");
        if (url.pathname === "/healthz")
          return new Response('{"status":"ok"}', {
            status: 200,
            headers: {
              "content-type": "application/json; charset=utf-8",
              "cache-control": "no-store",
            },
          });
        if (
          request.headers.get("content-type")?.toLowerCase() !==
          "application/json"
        )
          invalid();
        const length = request.headers.get("content-length");
        if (
          length !== null &&
          (!/^(?:0|[1-9]\d*)$/.test(length) || Number(length) > MAX_BODY_BYTES)
        )
          throw new FlareFormError("REQUEST_TOO_LARGE");
        const authorization = request.headers.get("authorization");
        if (!authorization || !/^Bearer [A-Za-z0-9_.-]+$/.test(authorization))
          throw new FlareFormError("INVALID_TOKEN");
        const token = authorization.slice(7);
        const claims = await awaitWithDeadline(verify(token), deadline);
        if (deadline.aborted) throw new FlareFormError("REQUEST_TIMEOUT");
        const repository = await awaitWithDeadline(
          lookupRepository(env, claims.repository_id),
          deadline,
        );
        authorizeOidcClaims(claims, repository);
        const body = validateEnvelope(
          await readBody(request, deadline),
          url.pathname,
        );
        if (deadline.aborted) throw new FlareFormError("REQUEST_TIMEOUT");
        if (!env?.RATE_LIMITER || typeof env.RATE_LIMITER.limit !== "function")
          throw new FlareFormError("SERVICE_UNAVAILABLE");
        const result = await awaitWithDeadline(
          env.RATE_LIMITER.limit({
            key: `${claims.repository_id}:${url.pathname}`,
          }),
          deadline,
        );
        if (!result.success) throw new FlareFormError("RATE_LIMITED");
        // Business handlers receive only verified identity and a deadline. M2's
        // default handler remains fail-closed until M3/M4 implement DNS work.
        return await business({
          route: url.pathname,
          body,
          claims,
          repository,
          env,
          signal: deadline,
          correlationId,
          now: now(),
        });
      } catch (error) {
        return unexpectedErrorResponse(error, correlationId);
      }
    },
  };
}
