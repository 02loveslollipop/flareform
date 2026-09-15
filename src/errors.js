// Public messages are constants. Never pass an exception message to a client.
export const ERROR_DEFINITIONS = Object.freeze({
  INVALID_TOKEN: [401, "Authentication failed"],
  INVALID_REQUEST: [400, "Invalid request"],
  METHOD_NOT_ALLOWED: [405, "Method not allowed"],
  REQUEST_TOO_LARGE: [413, "Request too large"],
  REQUEST_TIMEOUT: [504, "Request timed out"],
  RATE_LIMITED: [429, "Too many requests"],
  TOKEN_EXPIRED: [401, "Authentication failed"],
  INVALID_ISSUER: [401, "Authentication failed"],
  INVALID_AUDIENCE: [401, "Authentication failed"],
  INVALID_SUBJECT: [401, "Authentication failed"],
  INVALID_RUNNER_ENVIRONMENT: [403, "Access denied"],
  OIDC_TOKEN_REPLAYED: [409, "Token already used"],
  UNKNOWN_REPOSITORY: [403, "Access denied"],
  REPOSITORY_DISABLED: [403, "Access denied"],
  INVALID_OWNER: [403, "Access denied"],
  INVALID_WORKFLOW: [403, "Access denied"],
  INVALID_REF: [403, "Access denied"],
  INVALID_EVENT: [403, "Access denied"],
  INVALID_ENVIRONMENT: [403, "Access denied"],
  UNKNOWN_ZONE: [403, "Access denied"],
  ZONE_DISABLED: [403, "Access denied"],
  HOSTNAME_NOT_AUTHORIZED: [403, "Access denied"],
  RECORD_TYPE_NOT_AUTHORIZED: [403, "Access denied"],
  INVALID_RECORD: [400, "Invalid record"],
  RECORD_NOT_OWNED: [403, "Record is not owned by this repository"],
  RECORD_OWNED_BY_OTHER_REPOSITORY: [409, "Record is already owned"],
  DNS_CONFLICT: [409, "DNS record conflict"],
  OPERATION_IN_PROGRESS: [409, "Operation in progress"],
  STATE_INDETERMINATE: [409, "DNS state must be inspected"],
  PRUNE_NOT_AUTHORIZED: [403, "Access denied"],
  PRUNE_LIMIT_EXCEEDED: [409, "Prune safety limit exceeded"],
  PLAN_PRECONDITION_FAILED: [409, "Plan is no longer valid"],
  CLOUDFLARE_API_ERROR: [502, "DNS provider error"],
  PARTIAL_ZONE_FAILURE: [502, "Some zones failed"],
  DATABASE_ERROR: [503, "Storage unavailable"],
  SERVICE_UNAVAILABLE: [503, "Service unavailable"],
  INTERNAL_ERROR: [500, "Internal error"],
});

export class FlareFormError extends Error {
  constructor(code) {
    if (!Object.hasOwn(ERROR_DEFINITIONS, code)) {
      throw new TypeError("Unknown FlareForm error code");
    }
    super(code);
    this.name = "FlareFormError";
    this.code = code;
  }
}

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function safeCode(code) {
  return Object.hasOwn(ERROR_DEFINITIONS, code) ? code : "INTERNAL_ERROR";
}

function safeCorrelationId(correlationId) {
  return typeof correlationId === "string" && UUID_PATTERN.test(correlationId)
    ? correlationId
    : crypto.randomUUID();
}

export function errorResponse(code, correlationId) {
  const selected = safeCode(code);
  const [status, message] = ERROR_DEFINITIONS[selected];
  return new Response(
    JSON.stringify({
      error: {
        code: selected,
        message,
        correlation_id: safeCorrelationId(correlationId),
      },
    }),
    {
      status,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
      },
    },
  );
}

export function unexpectedErrorResponse(error, correlationId) {
  const code = error instanceof FlareFormError ? error.code : "INTERNAL_ERROR";
  const id = safeCorrelationId(correlationId);
  logError({ code, correlationId: id });
  return errorResponse(code, id);
}

// Log fields are deliberately allowlisted. Never serialize Error objects, request
// bodies, response bodies, headers, DNS values, or arbitrary caller metadata.
export function logError({ code, correlationId }, sink = console.error) {
  const event = {
    event: "request_error",
    code: safeCode(code),
    correlation_id: safeCorrelationId(correlationId),
    timestamp: new Date().toISOString(),
  };
  sink(JSON.stringify(event));
}

// For audit/log payloads that must contain DNS data, only explicitly public
// record values may pass. TXT values and all comments are always sensitive.
export function redactRecordForAudit(record) {
  return {
    type: typeof record?.type === "string" ? record.type.toUpperCase() : null,
    name: typeof record?.name === "string" ? record.name : null,
    content:
      record?.type?.toUpperCase() === "TXT"
        ? "[REDACTED]"
        : (record?.content ?? null),
    comment: record?.comment == null ? null : "[REDACTED]",
  };
}
