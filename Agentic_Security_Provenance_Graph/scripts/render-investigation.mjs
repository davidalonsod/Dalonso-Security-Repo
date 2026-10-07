// Renders an Agentic Action investigation case (see case-schema.json) into a
// Markdown report and an HTML report, matching the incident-narrative format:
// header fields, an auto-generated "What happened" ASCII flow, an evidence
// table, anomaly findings, a blast-radius tree, and an analyst recommendation.
//
// Usage:
//   node scripts/render-investigation.mjs investigation/case-example-finance-agent.json
//
// Output is written next to the input file as <name>.md and <name>.html.

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const inputPath = process.argv[2];
if (!inputPath) {
  console.error("Usage: node scripts/render-investigation.mjs <case-file.json>");
  process.exit(1);
}

const caseData = JSON.parse(await readFile(inputPath, "utf8"));
validateCase(caseData);

const markdown = renderMarkdown(caseData);
const html = renderHtml(caseData, markdown);

const outDir = path.dirname(inputPath);
const baseName = path.basename(inputPath, ".json");
await writeFile(path.join(outDir, `${baseName}.md`), markdown, "utf8");
await writeFile(path.join(outDir, `${baseName}.html`), html, "utf8");

console.log(`Wrote ${baseName}.md and ${baseName}.html in ${outDir}`);

function validateCase(data) {
  const errors = [];
  for (const key of ["incident", "steps", "evidenceTable", "anomalies", "blastRadius", "recommendation"]) {
    if (!(key in data)) errors.push(`Missing top-level property: ${key}`);
  }
  if (!Array.isArray(data.steps) || !data.steps.length) errors.push("steps must be a non-empty array");
  if (!Array.isArray(data.evidenceTable) || !data.evidenceTable.length) errors.push("evidenceTable must be a non-empty array");
  const allowedEvidence = new Set(["exact", "correlated", "audit", "inferred"]);
  for (const step of data.steps ?? []) {
    if (!allowedEvidence.has(step.evidenceType)) errors.push(`Step "${step.actor}" has invalid evidenceType: ${step.evidenceType}`);
  }
  if (errors.length) {
    console.error(`Case validation failed:\n${errors.map((e) => `- ${e}`).join("\n")}`);
    process.exit(1);
  }
}

function evidenceLabel(step) {
  const type = step.evidenceType.toUpperCase();
  return step.confidencePercent != null ? `${type} — ${step.confidencePercent}%` : type;
}

function renderFlow(steps) {
  const lines = [];
  steps.forEach((step, index) => {
    lines.push(step.actor);
    if (index === steps.length - 1) return;
    lines.push("");
    lines.push("  │");
    lines.push("");
    lines.push(`  │ ${step.action}`);
    if (step.detail) lines.push(`  │ ${step.detail}`);
    lines.push(`  │ Evidence: ${evidenceLabel(step)}`);
    if (step.branches?.length) {
      lines.push("  │");
      step.branches.forEach((branch, branchIndex) => {
        const isLast = branchIndex === step.branches.length - 1;
        lines.push(`  ${isLast ? "└──" : "├──"} ${branch}`);
      });
      if (step.flag) {
        lines.push("        │");
        lines.push(`        │ ${step.flag}`);
        lines.push("        ▼");
      } else {
        lines.push("");
        lines.push("  ▼");
      }
    } else {
      lines.push("");
      lines.push("  ▼");
    }
    lines.push("");
  });
  return lines.join("\n");
}

function renderBlastRadius(blastRadius) {
  const lines = [blastRadius.rootLabel, "   │"];
  blastRadius.branches.forEach((branch, index) => {
    const isLast = index === blastRadius.branches.length - 1;
    const label = branch.count != null ? `${branch.count} ${branch.label}` : branch.label;
    lines.push(`   ${isLast ? "└──" : "├──"} ${label}`);
    if (!isLast) lines.push("   │");
  });
  return lines.join("\n");
}

function renderMarkdown(data) {
  const { incident, steps, evidenceTable, anomalies, blastRadius, recommendation } = data;
  const lines = [];
  lines.push("> ⚠ **NOT VALIDATED AGAINST TENANT DATA.** This report is a template/example rendering.");
  lines.push("> Every row's confidence percentage and source table below was authored by hand or transcribed from a narrative --");
  lines.push("> none of it was queried live from `CloudAppEvents`, `AppDependencies`, `BehaviorInfo`, or any other tenant table by this script.");
  lines.push("> Confirm every row against your own tenant before treating this incident as real or acting on it.");
  lines.push("");
  lines.push(`# ${incident.title}`);
  lines.push("");
  lines.push(`**Risk:** ${capitalize(incident.risk)}`);
  lines.push("");
  lines.push(`**Agent:** \`${incident.agentName}\``);
  lines.push("");
  lines.push(`**Agent ID:** \`${incident.agentId}\``);
  lines.push("");
  lines.push(`**Agent Identity:** \`${incident.agentIdentity}\``);
  lines.push("");
  lines.push(`**Initiating user:** \`${incident.initiatingUser}\``);
  lines.push("");
  lines.push(`**Conversation:** \`${incident.conversationId}\``);
  lines.push("");
  lines.push(`**Investigation confidence:** **${incident.investigationConfidencePercent}%**`);
  lines.push("");
  lines.push("## What happened");
  lines.push("");
  lines.push("```text");
  lines.push(renderFlow(steps));
  lines.push("```");
  lines.push("");
  lines.push("## Evidence table");
  lines.push("");
  lines.push("| Time | Entity | Action | Evidence | Confidence |");
  lines.push("| --- | --- | --- | --- | --- |");
  for (const row of evidenceTable) {
    lines.push(`| ${row.time} | ${row.entity} | ${row.action} | ${row.evidence} | ${row.confidencePercent}% |`);
  }
  lines.push("");
  lines.push("## Why this is suspicious");
  lines.push("");
  lines.push(`**${anomalies.length} anomalies detected**`);
  lines.push("");
  anomalies.forEach((anomaly, index) => {
    lines.push(`${index + 1}. **${anomaly.title}**`);
    lines.push("");
    if (anomaly.baseline || anomaly.current) {
      if (anomaly.baseline) lines.push(`   - Baseline: ${anomaly.baseline}`);
      if (anomaly.current) lines.push(`   - Current: ${anomaly.current}`);
    } else {
      lines.push(`   - ${anomaly.description}`);
    }
    lines.push("");
  });
  lines.push("## Blast radius");
  lines.push("");
  lines.push("```text");
  lines.push(renderBlastRadius(blastRadius));
  lines.push("```");
  lines.push("");
  lines.push("## Analyst recommendation");
  lines.push("");
  lines.push(`**Priority: ${recommendation.priority.toUpperCase()}**`);
  lines.push("");
  lines.push("Investigate:");
  lines.push("");
  for (const item of recommendation.investigate) lines.push(`- ${item};`);
  lines.push("");
  lines.push("## Evidence-to-telemetry map");
  lines.push("");
  lines.push("| Time | Evidence | Source table |");
  lines.push("| --- | --- | --- |");
  for (const row of evidenceTable) {
    lines.push(`| ${row.time} | ${row.evidence} | ${row.sourceTable ?? "_not specified_"} |`);
  }
  return lines.join("\n") + "\n";
}

function capitalize(value) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
}

function renderHtml(data, markdownFallback) {
  const { incident, steps, evidenceTable, anomalies, blastRadius, recommendation } = data;
  const evidenceRow = (row) => `
    <tr>
      <td>${escapeHtml(row.time)}</td>
      <td>${escapeHtml(row.entity)}</td>
      <td>${escapeHtml(row.action)}</td>
      <td>${escapeHtml(row.evidence)}</td>
      <td>${row.confidencePercent}%</td>
    </tr>`;
  const anomalyItem = (anomaly) => `
    <li>
      <strong>${escapeHtml(anomaly.title)}</strong>
      <p>${escapeHtml(anomaly.description)}</p>
      ${anomaly.baseline ? `<p>Baseline: ${escapeHtml(anomaly.baseline)}</p>` : ""}
      ${anomaly.current ? `<p>Current: ${escapeHtml(anomaly.current)}</p>` : ""}
    </li>`;

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${escapeHtml(incident.title)}</title>
<link rel="stylesheet" href="investigation-report.css">
</head>
<body>
<div id="validation-banner" role="alert">
  <strong>⚠ NOT VALIDATED AGAINST TENANT DATA.</strong>
  This report is a template/example rendering. Every confidence percentage and source table below was authored by hand or transcribed from a narrative &mdash;
  none of it was queried live from <code>CloudAppEvents</code>, <code>AppDependencies</code>, <code>BehaviorInfo</code>, or any other tenant table by this script.
  Confirm every row against your own tenant before treating this incident as real or acting on it.
</div>
<h1>${escapeHtml(incident.title)}</h1>
<p><strong>Risk:</strong> <span class="risk-${incident.risk}">${capitalize(incident.risk)}</span></p>
<p><strong>Agent:</strong> <code>${escapeHtml(incident.agentName)}</code></p>
<p><strong>Agent ID:</strong> <code>${escapeHtml(incident.agentId)}</code></p>
<p><strong>Agent Identity:</strong> <code>${escapeHtml(incident.agentIdentity)}</code></p>
<p><strong>Initiating user:</strong> <code>${escapeHtml(incident.initiatingUser)}</code></p>
<p><strong>Conversation:</strong> <code>${escapeHtml(incident.conversationId)}</code></p>
<p><strong>Investigation confidence:</strong> <strong>${incident.investigationConfidencePercent}%</strong></p>

<h2>What happened</h2>
<pre>${escapeHtml(renderFlow(steps))}</pre>

<h2>Evidence table</h2>
<table>
<thead><tr><th>Time</th><th>Entity</th><th>Action</th><th>Evidence</th><th>Confidence</th></tr></thead>
<tbody>${evidenceTable.map(evidenceRow).join("")}
</tbody>
</table>

<h2>Why this is suspicious</h2>
<p><strong>${anomalies.length} anomalies detected</strong></p>
<ol>${anomalies.map(anomalyItem).join("")}
</ol>

<h2>Blast radius</h2>
<pre>${escapeHtml(renderBlastRadius(blastRadius))}</pre>

<h2>Analyst recommendation</h2>
<p><strong>Priority: ${recommendation.priority.toUpperCase()}</strong></p>
<p>Investigate:</p>
<ul>${recommendation.investigate.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
</ul>

<h2>Evidence-to-telemetry map</h2>
<table>
<thead><tr><th>Time</th><th>Evidence</th><th>Source table</th></tr></thead>
<tbody>${evidenceTable
    .map(
      (row) => `
    <tr><td>${escapeHtml(row.time)}</td><td>${escapeHtml(row.evidence)}</td><td>${escapeHtml(row.sourceTable ?? "not specified")}</td></tr>`
    )
    .join("")}
</tbody>
</table>
</body>
</html>
`;
}
