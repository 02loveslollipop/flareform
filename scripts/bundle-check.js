export function assertBundleCurrent(generated, committed) {
  if (generated !== committed) {
    throw new Error(
      "github-action/dist is stale; run npm run build and commit it",
    );
  }
}
