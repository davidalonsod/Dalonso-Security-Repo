import { cpSync, copyFileSync, existsSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const output = path.join(root, "dist");

for (const filename of [
  ".nojekyll",
  "graph-data.json",
  "graph-schema.json",
  "action-provenance-finance-agent.json",
  "provenance-graph.md"
]) {
  const source = path.join(root, filename);
  if (existsSync(source)) copyFileSync(source, path.join(output, filename));
}

for (const directory of ["investigation", "detections", "examples"]) {
  const source = path.join(root, directory);
  if (!existsSync(source)) continue;
  const target = path.join(output, directory);
  mkdirSync(target, { recursive: true });
  cpSync(source, target, { recursive: true });
}

console.log("Copied static graph, investigation, and detection assets to dist.");
