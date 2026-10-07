import { readFile } from "node:fs/promises";
import path from "node:path";

const targetPath = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.resolve(new URL("../graph-data.json", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const graph = JSON.parse(await readFile(targetPath, "utf8"));
const schema = JSON.parse(await readFile(new URL("../graph-schema.json", import.meta.url), "utf8"));

const errors = [];
const requiredGraphKeys = schema.required ?? [];
for (const key of requiredGraphKeys) {
  if (!(key in graph)) errors.push(`Missing graph property: ${key}`);
}

if (!/^\d+\.\d+\.\d+$/.test(graph.version ?? "")) {
  errors.push("version must use semantic version format");
}

const allowedStatuses = new Set(schema.properties.metadata.properties.deploymentStatus.enum);
if (!allowedStatuses.has(graph.metadata?.deploymentStatus)) {
  errors.push(`Unknown deployment status: ${graph.metadata?.deploymentStatus}`);
}

const allowedTypes = new Set(schema.$defs.node.properties.type.enum);
const allowedConfidence = new Set(schema.$defs.node.properties.confidence.enum);
const identifier = /^[a-z][a-z0-9-]*$/;
const stageIds = new Set();
for (const stage of graph.stages ?? []) {
  if (!identifier.test(stage.id)) errors.push(`Invalid stage ID: ${stage.id}`);
  if (stageIds.has(stage.id)) errors.push(`Duplicate stage ID: ${stage.id}`);
  stageIds.add(stage.id);
}

const nodeIds = new Set();
for (const node of graph.nodes ?? []) {
  if (!identifier.test(node.id)) errors.push(`Invalid node ID: ${node.id}`);
  if (nodeIds.has(node.id)) errors.push(`Duplicate node ID: ${node.id}`);
  nodeIds.add(node.id);
  if (!stageIds.has(node.stage)) errors.push(`Node ${node.id} has unknown stage ${node.stage}`);
  if (!allowedTypes.has(node.type)) errors.push(`Node ${node.id} has unknown type ${node.type}`);
  if (!allowedConfidence.has(node.confidence)) errors.push(`Node ${node.id} has invalid confidence ${node.confidence}`);
  if (!Array.isArray(node.evidence)) errors.push(`Node ${node.id} evidence must be an array`);
}

const edgeIds = new Set();
const allowedEvidenceTypes = new Set(schema.$defs.edge.properties.evidenceType.enum);
for (const edge of graph.edges ?? []) {
  if (!identifier.test(edge.id)) errors.push(`Invalid edge ID: ${edge.id}`);
  if (edgeIds.has(edge.id)) errors.push(`Duplicate edge ID: ${edge.id}`);
  edgeIds.add(edge.id);
  if (!nodeIds.has(edge.from)) errors.push(`Edge ${edge.id} has unknown source ${edge.from}`);
  if (!nodeIds.has(edge.to)) errors.push(`Edge ${edge.id} has unknown target ${edge.to}`);
  if (!identifier.test(edge.relation)) errors.push(`Edge ${edge.id} has invalid relation ${edge.relation}`);
  if (!allowedEvidenceTypes.has(edge.evidenceType)) errors.push(`Edge ${edge.id} has invalid or missing evidenceType: ${edge.evidenceType}`);
}

if (errors.length) {
  console.error(`Validation failed with ${errors.length} error(s):`);
  errors.forEach((error) => console.error(`- ${error}`));
  process.exit(1);
}

console.log(`Validated ${path.basename(targetPath)} v${graph.version}: ${nodeIds.size} nodes, ${edgeIds.size} edges, ${stageIds.size} stages.`);
