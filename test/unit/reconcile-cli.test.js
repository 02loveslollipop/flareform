import assert from "node:assert/strict";
import test from "node:test";
import { main } from "../../scripts/reconcile-record.js";

const args = (mode = "--inspect") => [
  mode,
  "--account-id",
  "a".repeat(32),
  "--database-id",
  "11111111-1111-4111-8111-111111111111",
  "--operation-id",
  "ffop_test",
  "--client-key",
  "main",
];
const inspected = {
  operation: { id: "ffop_test", status: "indeterminate" },
  intent: { client_key: "main", status: "indeterminate", action: "create" },
  zone: { name: "example.com" },
  evidence: {
    action: "create",
    provider_matches: [],
    exact_managed_matches: [],
    audit_events: [],
  },
};
function dependencies(calls) {
  return {
    remoteD1: () => ({ db: true }),
    createCloudflareClient: () => ({ cloudflare: true }),
    inspectIndeterminate: async () => inspected,
    resolveIndeterminate: async (input) => {
      calls.push(input);
      return {
        operationId: input.operationId,
        clientKey: input.clientKey,
        decision: input.decision,
        resolved: true,
      };
    },
  };
}

test("REC-CLI-001 inspect is read-only and returns redacted evidence", async () => {
  const calls = [];
  const result = await main(args(), {}, dependencies(calls));
  assert.equal(result.operation_id, "ffop_test");
  assert.deepEqual(result.evidence.provider_matches, []);
  assert.equal(calls.length, 0);
});

test("REC-CLI-002 resolution needs an explicit decision and trusted confirmation", async () => {
  const calls = [];
  await assert.rejects(main([...args("--resolve")], {}, dependencies(calls)));
  await assert.rejects(
    main(
      [
        ...args("--resolve"),
        "--decision",
        "confirm-no-change",
        "--operator-id",
        "900",
      ],
      {},
      dependencies(calls),
    ),
  );
  const result = await main(
    [
      ...args("--resolve"),
      "--decision",
      "confirm-no-change",
      "--operator-id",
      "900",
      "--confirm-resolution",
    ],
    {},
    dependencies(calls),
  );
  assert.equal(result.resolved, true);
  assert.equal(calls.length, 1);
});
