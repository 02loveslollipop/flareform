import { ActionError, runAction } from "./client.js";

runAction().catch((error) => {
  const code = error instanceof ActionError ? error.code : "INTERNAL_ERROR";
  console.error(`::error::FlareForm failed: ${code}`);
  process.exitCode = 1;
});
