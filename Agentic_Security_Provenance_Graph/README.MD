 Agentic Security Provenance Graph

A local-first React Progressive Web App for visualizing AI-agent security evidence as an interactive graph: source claim → behavior → agent action → telemetry → correlation → finding → security-framework mapping (MITRE ATT&CK). It also includes a searchable monitoring-table catalog and a matching incident investigation report template and generator.

The PWA has no backend, account, API key, or cloud synchronization endpoint. Imported graphs and table-health snapshots remain in browser storage. A production build is fully static and can be installed for offline use.

 ⚠️ Project status

- The example graphs ([`graph-data.json`](./graph-data.json) and [`action-provenance-finance-agent.json`](./action-provenance-finance-agent.json)) are illustrative sample content, not real incidents. They exist to show the schema in use and to give you something to look at before you build your own.
- A node or edge marked "high confidence" in the example data means well-documented in public sources, not confirmed in your environment. Nothing in this repository has queried anyone's live tenant.
- The tool itself (the viewer, the schema, the report generator) is the reusable part. The example content is a demo, not a deliverable.
- [`access-graph/`](./access-graph) (Agent 365 Permission Intelligence) keeps its synthetic fixture clearly labeled, while its collector, Azure infrastructure, canonical table contract, and live-first workbook have been validated as an end-to-end deployment path. Tenant-specific permissions, resource classifications, and results still require deployment and verification in your own environment.

 What's included

| Capability | Files |
| --- | --- |
| React PWA graph and table explorer | [`src/`](./src), [`index.html`](./index.html), [`vite.config.ts`](./vite.config.ts) |
| Monitoring-table catalog (37 tables across eight planes) | [`src/data/telemetryTables.ts`](./src/data/telemetryTables.ts) |
ProvenancePwaDemo.ps1`](./scripts/Start-ProvenancePwaDemo.ps1) |
| | Legacy dependency-free viewer reference | [`app.js`](./app.js), [`styles.css`](./styles.css) |
| Graph data contract (JSON Schema) | [`graph-schema.json`](./graph-schema.json) |
| Example graph data (replace with your own) | [`graph-data.json`](./graph-data.json), [`action-provenance-finance-agent.json`](./action-provenance-finance-agent.json) |
| Narrative walkthrough of the example graph | [`provenance-graph.md`](./provenance-graph.md) |
| Incident investigation report generator | [`investigation/case-schema.json`](./investigation/case-schema.json), [`scripts/render-investigation.mjs`](./scripts/render-investigation.mjs) |
| Draft KQL detection queries (untested, example only) | [`detections/`](./detections) |
| No-dependency validators | [`scripts/validate.mjs`](./scripts/validate.mjs), [`scripts/validate-case.mjs`](./scripts/validate-case.mjs) |
| GitHub Pages deployment workflow | [`.github/workflows/deploy-pages.yml`](./.github/workflows/deploy-pages.yml) |
| Agent 365 Permission Intelligence — canonical permission-edge model, configured/observed/reachable separation, deterministic evaluator, Agent 365 Data lake queries, and an eleven-view Azure Workbook implementing all 16 proposed capabilities | [`access-graph/`](./access-graph) ([details](./access-graph/README.md)) |
| Live permission-edge collector | [`access-graph/collector/`](./access-graph/collector), [`access-graph/infra/`](./access-graph/infra), [`.azure/deployment-plan.md`](./.azure/deployment-plan.md) |
| Agent 365 publication assets | [`access-graph/docs/substack-agent-365-permission-intelligence.md`](./access-graph/docs/substack-agent-365-permission-intelligence.md), [`access-graph/docs/youtube-agent-365-permission-intelligence-script.md`](./access-graph/docs/youtube-agent-365-permission-intelligence-script.md) |

 Two graph modes

This viewer supports two distinct kinds of graph, both using the same `graph-schema.json` contract:

| Mode | File | Answers | Stages |
| --- | --- | --- | --- |
| Evidence Provenance | [`graph-data.json`](./graph-data.json) | Why do we believe this is suspicious? Source → behavior → agent action → telemetry → correlation → detection → finding → MITRE mapping. | Source, Threat behavior, Agent action, Telemetry, Correlation, Decision, Mapping |
| Action Provenance | [`action-provenance-finance-agent.json`](./action-provenance-finance-agent.json) | What did the agent actually do? User → agent/identity → prompt/trigger → model/tool execution → MCP/API integration → resource → outcome. | Who, Agent, Trigger, Execution, Integration, Resource, Outcome |

Evidence Provenance — why do we believe this is suspicious

<p align="center">
  <a href="./docs/screenshots/evidence-provenance.png">
    <img src="./docs/screenshots/evidence-provenance.png" alt="Evidence Provenance graph screenshot" width="900">
  </a>
</p>

Action Provenance — what did the agent actually do

<p align="center">
  <a href="./docs/screenshots/action-provenance.png">
    <img src="./docs/screenshots/action-provenance.png" alt="Action Provenance graph screenshot" width="900">
  </a>
</p>

Switch between them three ways, all using the same PWA:
1. Use the graph selector in the toolbar.
2. Open `?graph=action-provenance-finance-agent.json` for a shareable Action Provenance URL.
3. Select Import JSON and choose any local file conforming to the schema. Imported data stays in browser storage and can be exported again.

The Action Provenance example is a worked illustration, not a real incident: it's built from the transcribed [`investigation/case-example-finance-agent.json`](./investigation/case-example-finance-agent.json) narrative, with two hops (the model-call span, the MCP-to-Graph call) added as plausible-but-unconfirmed architecture to fill out the pattern -- both are explicitly marked `contextual`/`conditional` in the file, and its `deploymentStatus` is `draft` for that reason.

 Evidence typing on every edge

Every edge carries a required `evidenceType`, shown as a distinct edge color in the viewer and as a colored chip in the detail panel:

| Type | Color | Meaning |
| --- | --- | --- |
| `exact` | 🟢 green | A shared trace/session ID or native column deterministically ties the two records together |
| `correlated` | 🟡 amber | Joined by identity + a bounded time window, with no shared ID -- a real but probabilistic join |
| `contextual` | 🔵 blue | Same resource/type/timeframe, or an unverified/hypothesized inference -- weaker than `correlated` |
| `conflict` | 🔴 red | The two nodes directly contradict each other |

This is independent of the older `conditional` boolean (still present, dashed in the viewer), which marks whether an edge only sometimes holds rather than how strong it is -- an edge can be both `correlated` and `conditional`.

 Requirements

- A modern web browser (Edge, Chrome, Firefox, or Safari)
- Node.js 22+ and npm for development, tests, and production builds
- A text editor with JSON Schema and TypeScript support

Nothing else. No cloud account, no API keys, and no telemetry access are required to use the tool itself. A Microsoft Sentinel/Defender or Application Insights environment is only needed if you choose to adapt the example KQL queries in [`detections/`](./detections) to real telemetry — that step is optional and separate from viewing/authoring graphs.

 Getting started

1. Clone or download this repository.
   powershell
   git clone https://github.com/OWNER/REPOSITORY.git
   cd REPOSITORY
   
2. Install dependencies and start the local PWA:
   powershell
   npm install
   npm run dev
   
3. Open the viewer at <http://localhost:5173>. The Evidence Provenance graph loads automatically.
4. Try the second example by using the graph selector, opening `http://localhost:5173/?graph=action-provenance-finance-agent.json`, or importing a local graph JSON file.
5. Validate the example data (optional, confirms your environment is set up correctly):
   powershell
   node scripts\validate.mjs
   node scripts\validate.mjs action-provenance-finance-agent.json
   
6. Replace the example graph with your own data. See [Building your own graph](building-your-own-graph) below.
7. (Optional) Generate an investigation report from the included example:
   powershell
   node scripts\render-investigation.mjs investigation\case-example-finance-agent.json
   
   This writes a Markdown and an HTML report next to the input file. See [Building your own investigation report](building-your-own-investigation-report) below.
8. (Optional) Publish the viewer so others can see it without cloning the repo. See [Publishing to GitHub Pages](publishing-to-github-pages) below.

 React PWA features

- Stage-aware React Flow graph with zoom, pan, minimap, relationship highlighting, and node inspection
- Evidence and Action Provenance modes using the existing JSON schema
- Search across IDs, labels, descriptions, evidence, types, and stages
- Node-type filters and evidence-strength visual encoding
- Local graph import, validation, persistence, and export
- Installable PWA with generated service worker and offline asset cache
- Responsive desktop, tablet, and mobile layouts
- No API, backend, telemetry, or cloud upload path

Build and preview the production PWA:

powershell
npm run build
npm run preview


The build writes to `dist/` and copies the graph JSON/schema, investigation artifacts, and draft detection files needed by the published static site.

 Telemetry table catalog

The Telemetry tables view catalogs 37 sources across:

- Application Insights
- Microsoft 365
- OpenAI connector
- Defender XDR
- Microsoft Sentinel
- Microsoft Entra
- Agent 365 data lake
- Azure platform

Each row documents product, purpose, requirement level, data tier, cost model, expected freshness, sensitivity, and key fields. The catalog includes the Application Insights tables shown by the workbook as well as Defender, Sentinel, Agent ID, and data-lake sources.

Use Import health snapshot to add local volume, cost, and freshness observations. The JSON format is:

json
[
  {
    "table": "AppRequests",
    "events": 12500,
    "gigabytes": 0.42,
    "lastSeen": "2026-10-07T08:00:00Z"
  }
]


The PWA stores this snapshot in browser storage. Select Template in the table view to download a complete 37-table starter file.

 Ready-to-import examples

| Feature | Example file | Demonstrates |
| --- | --- | --- |
| Graph JSON import | [`examples/imports/mcp-data-exfiltration-provenance.json`](./examples/imports/mcp-data-exfiltration-provenance.json) | Indirect prompt injection → unapproved MCP server → `export_records` tool → confidential SharePoint data → external endpoint → correlated detection and containment |
| Health snapshot import | [`examples/imports/table-health-snapshot.json`](./examples/imports/table-health-snapshot.json) | Active, delayed, stale, and unavailable telemetry across Application Insights, Microsoft 365, Defender, Sentinel, Entra, and Agent 365 data-lake tables |

To demonstrate graph import:

1. Download `mcp-data-exfiltration-provenance.json`.
2. Open Graph explorer.
3. Select Import JSON and choose the file.
4. Search for `export_records`, select the tool node, and follow its exact and correlated relationships through telemetry, detection, finding, and response.
5. Select Export to confirm that the locally imported graph can be downloaded again.

To demonstrate table-health import:

1. Download `table-health-snapshot.json`.
2. Open Telemetry tables.
3. Select Import health snapshot and choose the file.
4. Review event counts, GB volume, and the calculated Active/Delayed/Stale/No snapshot states.
5. Filter to Agent 365 data lake or search for `AADAgentRiskEvents` to demonstrate preview and unavailable-source handling.

The examples are synthetic and use reserved or fictitious identifiers. They do not contain tenant data and do not call any external endpoint.

 Detections (example queries — untested)

[`detections/`](./detections) contains draft KQL queries against Microsoft Sentinel / Microsoft Defender Advanced Hunting tables (`CloudAppEvents`, `AlertEvidence`, `AgentsInfo`, `BehaviorInfo`) and the Microsoft Entra Agent ID identity model. None of these queries have been run against a live tenant. They're included to show what a detection built from this schema could look like, and as a starting point if you happen to use these same Microsoft products — not as validated, ready-to-deploy rules.

| File | What it illustrates | Status |
| --- | --- | --- |
| [`CAND-001.kql`](./detections/CAND-001.kql) | A correlation joining a completed AI tool run to later alert evidence, by account + time window | Draft — untested, has unfilled placeholders |
| [`CAND-001-sentinel.kql`](./detections/CAND-001-sentinel.kql) | The same query adapted for Microsoft Sentinel's Log Analytics field names | Draft — untested |
| [`CAND-002-guardrail-enriched.kql`](./detections/CAND-002-guardrail-enriched.kql) | A stronger version correlating agent guardrail posture with classified behaviors instead of raw alerts | Draft — untested, depends on an unverified join-key assumption (see file comments) |
| [`workspace-preflight.kql`](./detections/workspace-preflight.kql) | Read-only, count-only queries to check whether the tables/fields the detections assume actually exist and are populated | Safe to run first — returns aggregates only, no sensitive rows |
| [`agent-observability-preflight.kql`](./detections/agent-observability-preflight.kql) | Same idea, for the newer agent-identity/guardrail tables (`AgentsInfo`, `BehaviorInfo`, Entra Agent ID tables) | Safe to run first — returns aggregates only |

If you want to adapt any of these for real use:

1. Run the matching `-preflight.kql` file first. It only returns row counts and column-presence checks, not prompt text, account identifiers, or alert content.
2. Confirm every placeholder value (`CorrelationWindow`, `SuspiciousPromptTerms`, `RequiredAlertCategories`, etc.) against your own environment — every default is either empty or a guess.
3. Replay the query over historical data in count-only mode before creating any alert rule from it.
4. Treat every comment in the query file marked "PLACEHOLDER" or "unverified" as a blocking item, not a suggestion.

The queries assume familiarity with Kusto Query Language (KQL) and access to a Microsoft Sentinel workspace or Microsoft Defender Advanced Hunting. Both are optional — the graph viewer and investigation reports work entirely without them.

 Building your own investigation report

The interactive graph models detection logic provenance — how a rule was built, what it assumes, and where its gaps are. That's a different artifact from a per-incident investigation report (a specific agent, a specific conversation, specific files touched, a confidence-scored evidence chain, blast radius, and a recommendation). This repo includes a second, separate template for that:

| File | Purpose |
| --- | --- |
| [`investigation/case-schema.json`](./investigation/case-schema.json) | JSON Schema contract for one incident: header fields, an ordered evidence chain (`steps`), an evidence table, anomalies, blast radius, and a recommendation |
| [`investigation/case-template.json`](./investigation/case-template.json) | A blank starter — duplicate this for each new incident |
| [`investigation/case-example-finance-agent.json`](./investigation/case-example-finance-agent.json) | An example incident, authored as a walkthrough of the schema |
| [`scripts/render-investigation.mjs`](./scripts/render-investigation.mjs) | Renders any case JSON into a Markdown report and an HTML report |
| [`scripts/validate-case.mjs`](./scripts/validate-case.mjs) | No-dependency Node validator for case files (mirrors `scripts/validate.mjs`) |
| [`investigation/investigation-report.css`](./investigation/investigation-report.css) | Table/link styling used by the generated HTML report |

 Using `case-schema.json`

1. Author a new incident: copy [`investigation/case-template.json`](./investigation/case-template.json) to a new file, for example `investigation/case-2026-09-30-finance-agent.json`, and replace every `REPLACE:` placeholder.
2. Keep the schema reference: leave `"$schema": "./case-schema.json"` at the top. In VS Code this gives you inline autocomplete and red squiggles for invalid fields (wrong `risk`/`evidenceType` enum values, missing required fields) as you type — no extra setup needed, it's the same mechanism already active on `graph-data.json`.
3. Validate before rendering:
   powershell
   node scripts\validate-case.mjs investigation\case-2026-09-30-finance-agent.json
   
   This checks required fields, the `risk`/`evidenceType`/`priority` enums, and array shapes without needing Python or any package install.
4. Render it:
   powershell
   node scripts\render-investigation.mjs investigation\case-2026-09-30-finance-agent.json
   
   This writes `<name>.md` and `<name>.html` next to the input file: header fields, an auto-generated "What happened" flow diagram (built from `steps`), an evidence table, anomaly findings, a blast-radius tree, an analyst recommendation, and an evidence-to-telemetry map that names the KQL table each evidence row would come from (`AppDependencies`, `CloudAppEvents`, and so on) — so the narrative stays traceable back to a query instead of being a one-off write-up.

Evidence-type convention (`steps[].evidenceType` and `evidenceTable[].evidence`; also used to interpret the graph's `conditional` flag):

| Evidence type | Meaning | Typical source |
| --- | --- | --- |
| `exact` | Same trace: a shared `operation_Id`/`operation_ParentId` (or equivalent span-parent link) ties two records together | OpenTelemetry GenAI spans (e.g. Application Insights `AppDependencies`) |
| `correlated` | No shared span ID; joined by identity + a bounded time window | Sentinel/Defender tables such as `CloudAppEvents`, `BehaviorInfo` |
| `audit` | A separate, authoritative log record of the actual effect (a file changed, a permission changed) | Audit logs, `AlertEvidence` |
| `inferred` | A heuristic or pattern match with no direct telemetry confirmation | Prompt-term matching, anomaly scoring |

If you're building a case from real telemetry rather than by hand: pull the span chain for a conversation/session identifier from your agent-execution logs (`exact` rows), then add the `correlated`/`audit` rows from your security telemetry for the same account and time window, and fill those into the case file before rendering.

 Using `investigation-report.css`

`render-investigation.mjs` already wires this up for you: the generated `<name>.html` contains `<link rel="stylesheet" href="investigation-report.css">`, so as long as the two files stay in the same folder (`investigation/`), opening the HTML file directly (`file://...` or served over HTTP) picks up the styling automatically. No build step is required.

Other places you can reuse it:

- A hand-authored HTML report: copy the same `<link rel="stylesheet" href="investigation-report.css">` tag into any other HTML file in the same folder.
- A published report: if you publish this repo to GitHub Pages (see below), the CSS and HTML are served together automatically, so a link like `https://<you>.github.io/<repo>/investigation/case-example-finance-agent.html` renders styled, no extra step needed.
- Email, Teams, Confluence, or other systems that strip `<style>` blocks: these need the rules inlined onto each element instead of linked. Run an inliner over the generated HTML, for example:
  powershell
  npx --yes juice investigation\case-example-finance-agent.html investigation\case-example-finance-agent.inlined.html
  
  `juice` merges `investigation-report.css` into `style="..."` attributes on each element, producing a copy safe to paste into systems that don't support external or `<style>`-block CSS.
- Azure Workbooks do not accept custom CSS in a text step. A workbook text step's `"style"` JSON property is a fixed enum (`plain`, `info`, `error`, `success`, `warning`, `upsell`) that maps to portal-standard formatting, not a free-form CSS slot. To surface this report from within a Sentinel/Azure Monitor workbook, use a workbook Link step (or an external-link action) pointing at the published HTML/GitHub Pages URL instead.

 Publishing to GitHub Pages

Use a public GitHub template repository deployed with GitHub Pages through GitHub Actions. This is the best fit because:

1. GitHub Pages hosts the static React PWA build at no additional infrastructure cost.
2. A template repository lets others select Use this template, replace `graph-data.json`, and publish their own graph without carrying fork history.
3. The included workflow installs locked dependencies, runs tests, validates the graph model, builds the PWA, and publishes `dist/` before every deployment.
4. Pull requests provide reviewable provenance changes: node, edge, evidence, and confidence edits remain visible as JSON diffs.
5. Static hosting exposes no server-side secrets or runtime to maintain.

 Publish

1. Create an empty GitHub repository and choose `main` as its default branch.
2. Initialize this folder and push it:

   powershell
   git init
   git add .
   git commit -m "Add Agentic Security Provenance Graph"
   git branch -M main
   git remote add origin https://github.com/OWNER/REPOSITORY.git
   git push -u origin main
   

3. In the repository, open Settings → Pages.
4. Under Build and deployment, set Source to GitHub Actions.
5. The included `Validate and deploy GitHub Pages` workflow publishes the site. Its URL appears in the workflow deployment summary.
6. In Settings → General, enable Template repository so others can reuse it cleanly.
7. Add an appropriate license before inviting external reuse. MIT is common for permissive reuse, but the repository owner should choose the license.

For internal or sensitive graph data, use a private repository and confirm that the organization's GitHub plan and Pages policy permit private Pages. Never publish prompt content, account identifiers, IP addresses, alert details, or tenant telemetry without sanitizing them first.

 Building your own graph

1. Copy this repository (use Use this template if you enabled it, or just fork/clone it).
2. Replace the metadata, stages, nodes, and edges in [`graph-data.json`](./graph-data.json) — or create a new file entirely and load it via `?graph=yourfile.json`.
3. Preserve the contract defined by [`graph-schema.json`](./graph-schema.json).
4. Run `node scripts\validate.mjs yourfile.json` after every change.
5. Preview locally and review every `contextual`/`conditional` relation before trusting it.
6. Push to `main`; if you've enabled GitHub Pages (see above), the workflow validates and deploys automatically.

The viewer automatically creates filters for new node types already allowed by the schema and lays out any number of declared stages. To introduce a brand-new node type, add it to the schema's `node.type` enum and give it a color in `TYPE_COLORS` in [`app.js`](./app.js). To introduce a new `evidenceType`, do the same in `EVIDENCE_COLORS`/`EVIDENCE_LABELS`.

`graph-data.json`/`graph-schema.json` model detection-logic or action provenance (reusable across investigations). `investigation/case-schema.json` models a single incident (one case per file, never reused across incidents) — keep the two contracts separate rather than merging incident specifics into a provenance graph.

 Agent 365 Permission Intelligence

A third, independent artifact alongside the provenance graph and the investigation report: instead of why something looked suspicious or what happened in one incident, [`access-graph/`](./access-graph) models an evidence-backed identity and permission graph. Configured authorization, observed activity, deterministic/bounded/inferred reachability, lifecycle, and controls remain separate edge classes. Its live-first, eleven-view CISO/IAM workbook implements the complete 16-item Permission Intelligence proposal with per-agent detail and live tiles, bars, pies, and timelines for utilization, provenance, drift, escalation/reach, hygiene, concentration, confidence, change impact, and Agent Permission 360.

It's built as three phases plus a workbook, each with its own file(s):

| Phase | What it is |
| --- | --- |
| 1. Canonical access model | A JSON Schema contract for identities, blueprints, entitlements, boundaries, observed runtime telemetry, and business dependencies — every record carries evidence, confidence, and freshness |
| 2. Deterministic evaluator | A no-dependency Node script that resolves effective access, computes blueprint-baseline drift, and simulates blast radius for proposed permission/agent changes |
| 3. KQL adapters | Draft queries that populate Phase 1 from Microsoft Graph activity logs and Entra sign-in/risk logs |
| The workbook | An importable Azure Monitor Workbook rendering all of the above, with a governed (Logic App-based) remediation action rather than a direct in-browser Graph write |

See [`access-graph/README.md`](./access-graph/README.md) for the full design, usage commands, and its own project-status warning.


 Provenance conventions

- Use an edge without `conditional` only when the source directly observes or explicitly asserts the relationship.
- Set `"conditional": true` for inferred, hypothesized, or match-dependent relationships.
- Choose `evidenceType` honestly: `exact` requires a shared trace/session/native identifier, not just a plausible-sounding join. When in doubt, use `correlated` or `contextual` instead of `exact`.
- Put source-specific facts in `evidence`; do not place secrets or raw tenant telemetry in public graphs.
- Use `confidence` to express evidence quality (how well-documented a claim is), not severity or business impact.
- Represent contradictions as `finding` nodes with `evidenceType: "conflict"` rather than silently resolving them.
- Treat identity-and-time correlation as an investigation hypothesis, not proof, unless a shared trace/session identifier is available.

 About the example graph data

[`graph-data.json`](./graph-data.json) models a fictional/illustrative detection scenario (an AI prompt-injection technique referred to as "PuzzleMask" in the example) end-to-end, including a deliberately-preserved inconsistency: the example's own summary metadata says "ready to deploy" while its detection query has unfilled placeholders and is explicitly not deploy-ready. This is intentional — it demonstrates how the graph schema can represent a known contradiction as a first-class `finding` node (`evidenceType: "conflict"`) instead of silently picking a side. See [`provenance-graph.md`](./provenance-graph.md) for the full narrative walkthrough of this example, including a second Mermaid diagram covering the two graph modes.

If you build your own graph from a real detection, decide your own `metadata.deploymentStatus` based on your own tooling and evidence — don't copy this example's status.
