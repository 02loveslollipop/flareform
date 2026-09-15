import { readFile } from "node:fs/promises";
import { build } from "esbuild";
import { assertBundleCurrent } from "./bundle-check.js";

const result = await build({
  entryPoints: ["github-action/src/index.js"],
  bundle: true,
  format: "cjs",
  platform: "node",
  target: "node24",
  write: false,
  logLevel: "silent",
});
const committed = await readFile("github-action/dist/index.js", "utf8");
assertBundleCurrent(result.outputFiles[0].text, committed);
