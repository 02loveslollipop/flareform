import { build } from "esbuild";

await build({
  entryPoints: ["src/index.js"],
  outfile: "dist/worker/index.js",
  bundle: true,
  format: "esm",
  platform: "browser",
  target: "es2022",
  logLevel: "warning",
});

await build({
  entryPoints: ["github-action/src/index.js"],
  outfile: "github-action/dist/index.js",
  bundle: true,
  format: "cjs",
  platform: "node",
  target: "node24",
  logLevel: "warning",
});
