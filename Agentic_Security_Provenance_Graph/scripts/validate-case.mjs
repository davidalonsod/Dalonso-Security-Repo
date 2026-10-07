// No-dependency validator for investigation case files (investigation/case-schema.json contract).
// Mirrors the style of scripts/validate.mjs but for incident cases instead of the provenance graph.
//
// Usage:
//   node scripts/validate-case.mjs investigation/case-example-finance-agent.json
//   node scripts/validate-case.mjs investigation/*.json   (PowerShell expands the glob itself)

import { readFile } from "node:fs/promises";

const files = process.argv.slice(2);
if (!files.length) {
  console.error("Usage: node scripts/validate-case.mjs <case-file.json> [more-case-files.json ...]");
  process.exit(1);
}

const allowedRisk = new Set(["low", "medium", "high", "critical"]);
const allowedEvidence = new Set(["exact", "correlated", "audit", "inferred"]);
let hadErrors = false;

for (const file of files) {
  const errors = validateCase(JSON.parse(await readFile(file, "utf8")));
  if (errors.length) {
    hadErrors = true;
    console.error(`${file}: ${errors.length} error(s)`);
    errors.forEach((error) => console.error(`  - ${error}`));
  } else {
    console.log(`${file}: valid`);
  }
}

if (hadErrors) process.exit(1);

function validateCase(data) {
  const errors = [];
  for (const key of ["version", "incident", "steps", "evidenceTable", "anomalies", "blastRadius", "recommendation"]) {
    if (!(key in data)) errors.push(`Missing top-level property: ${key}`);
  }
  if (!/^\d+\.\d+\.\d+$/.test(data.version ?? "")) errors.push("version must use semantic version format");

  const incident = data.incident ?? {};
  for (const key of ["title", "risk", "agentName", "agentId", "agentIdentity", "initiatingUser", "conversationId", "investigationConfidencePercent"]) {
    if (!(key in incident)) errors.push(`incident is missing property: ${key}`);
  }
  if (incident.risk && !allowedRisk.has(incident.risk)) errors.push(`incident.risk has invalid value: ${incident.risk}`);
  if (typeof incident.investigationConfidencePercent === "number") {
    if (incident.investigationConfidencePercent < 0 || incident.investigationConfidencePercent > 100) {
      errors.push("incident.investigationConfidencePercent must be between 0 and 100");
    }
  }

  if (!Array.isArray(data.steps) || !data.steps.length) {
    errors.push("steps must be a non-empty array");
  } else {
    data.steps.forEach((step, index) => {
      if (!step.actor) errors.push(`steps[${index}] is missing actor`);
      if (!step.action) errors.push(`steps[${index}] is missing action`);
      if (!allowedEvidence.has(step.evidenceType)) errors.push(`steps[${index}] has invalid evidenceType: ${step.evidenceType}`);
    });
  }

  if (!Array.isArray(data.evidenceTable) || !data.evidenceTable.length) {
    errors.push("evidenceTable must be a non-empty array");
  } else {
    data.evidenceTable.forEach((row, index) => {
      for (const key of ["time", "entity", "action", "evidence", "confidencePercent"]) {
        if (!(key in row)) errors.push(`evidenceTable[${index}] is missing property: ${key}`);
      }
    });
  }

  if (!Array.isArray(data.anomalies)) errors.push("anomalies must be an array");
  if (!data.blastRadius?.rootLabel) errors.push("blastRadius.rootLabel is required");
  if (!Array.isArray(data.blastRadius?.branches)) errors.push("blastRadius.branches must be an array");

  const recommendation = data.recommendation ?? {};
  if (!allowedRisk.has(recommendation.priority)) errors.push(`recommendation.priority has invalid value: ${recommendation.priority}`);
  if (!Array.isArray(recommendation.investigate) || !recommendation.investigate.length) {
    errors.push("recommendation.investigate must be a non-empty array");
  }

  return errors;
}
