# CISO Command Center

A protected Microsoft Fabric App for an English-language, executive view of
security posture and security operations. It combines **seven pages and 51 KPI,
chart, map, and table regions** with Microsoft sign-in and verified source data.

> **Publication status:** This README uses generic descriptions and placeholders.
> The rest of this checkout has not been sanitized for public distribution.
> Complete the [publication checklist](#publishing-to-your-repository-without-confidential-information)
> before uploading any project files, including to a private repository.

CISO Command Center: A Business-Aware CISO Dashboard with Sentinel and Fabric App https://youtu.be/XqVlsNTAcaQ

## CISO capabilities and business benefits

| Page | Capabilities | Benefit |
| --- | --- | --- |
| Executive Summary | Custom posture index, incident closure rate, total incidents, open high-severity incidents, time to close, triage queue, risky sign-ins, incident trends and classification | Gives leaders a consistent overview of operational posture, backlog, and response effectiveness |
| Top Risks & Business Impact | Priority alerts, week-over-week risk trend, targeted entities, severity exposure signals, privileged role changes | Helps prioritize investigation and discuss potential exposure; does not calculate financial loss |
| Threat & Response | Time to first modification, true-positive rate, closure time by severity, opened versus closed incidents, oldest backlog, analyst workload, detection sources, noisy rules | Helps identify response bottlenecks and opportunities for detection tuning |
| Identity & Access | Sign-in volume and failures, successful sign-ins requiring MFA, sign-in risk, Conditional Access outcomes, geographic distribution, identity/application changes, UEBA signals | Highlights identity threats and access-control signals |
| Coverage & Health | Event volume, source freshness, detection activity, incident sources, top noisy alert rules | Helps identify collection gaps, stale sources, and uneven detection activity |
| MITRE ATT&CK | Tactic distribution, tactic trends, severity over time, Defender XDR technique counts | Organizes observed detections around a common threat framework |
| Email & Collaboration | Inbound messages, detected threats, delivery outcomes, threat types, trends, possible campaigns, malicious sender domains, targeted mailboxes | Supports visibility into email threats and potential campaign concentration |

### User experience

- Consistent custom React interface with light/dark themes and responsive layouts.
- Sidebar navigation and title search within the selected page.
- 7-, 30-, and 90-day views using the same approved KPI definitions.
- KPI cards, time/category charts, geographic sign-in points, and detailed grids.
- Last successful refresh and data-window timestamps, plus loading, permission,
  integrity, failed-refresh, and overdue-data states.
- A **Refresh** button to reload published metrics, and one-minute polling after
  successful reads. Neither operation starts a source-data refresh notebook.
- Protected hosting and delegated queries: readers use their own authorized identity.

### What these metrics do not claim

- The operational posture index is **custom**, not Microsoft Secure Score, a
  compliance certification, or a measure of total business risk.
- The MFA percentage measures successful sign-ins requiring MFA, **not MFA enrollment**.
- Time to first modification is not necessarily time to acknowledge or remediate.
- MITRE counts describe observed detections, not proof of complete technique coverage.
- Some queries retain fixed comparison windows or measure latest-source freshness;
  not every calculation changes with the selected 7/30/90-day range.
- CloudAppEvents-only use cases and the two custom findings sources are excluded.
  There is no Data & AI Risk page in this version.
- This is a read-only analytics app. Incident editing, remediation actions, write-back,
  file uploads, AI chat, and a packaged Teams tab are **not implemented**.

## Fabric App versus a live Real-Time Dashboard

Here, "live dashboard" means a **Fabric Real-Time Dashboard**, not a Power BI app.
Both options can provide interactive analytics and controlled access; neither
automatically solves source permissions, licensing, slow queries, or data quality.

| Area | This CISO Fabric App | Native Real-Time Dashboard |
| --- | --- | --- |
| Visual design | Custom React layout, branding, navigation, status panels, and application behavior | Built-in tile layouts and supported visuals; importing JSON does not apply arbitrary HTML/CSS |
| Main audience | Executives and readers who need a curated, consistent CISO experience | Analysts and operators who need direct KQL-based exploration and monitoring |
| Interaction | Custom page navigation, range selection, title search, themes, and refresh UX | Native pages, parameters, tile interactions, and dashboard editing without maintaining a frontend |
| Data path | KQL notebook -> Delta metrics -> Direct Lake model -> delegated connector | Queries connected data sources, including KQL databases |
| Freshness | Scheduled snapshots; designed for a 15-minute notebook cadence, plus ingestion and query latency | Live refresh can rerun queries at a configured interval; actual freshness still depends on ingestion, query time, and caching |
| Source-query workload | Expensive source calculations run per refresh batch rather than for every reader interaction; semantic-model reads still consume resources | Refreshes execute dashboard queries; source optimization and caching remain important |
| Data consistency | App-specific completion checks reject partial, mixed, or malformed KPI batches | Built-in query/visual behavior; this app's cross-tile packet-validation contract is custom |
| Delivery and maintenance | Requires code, dependency management, tests, deployment, and maintenance of notebook/model dependencies | Faster to author and maintain for standard visualization needs; supports dashboard file import/export |
| Future workflows | Fabric Apps can support APIs, server functions, app-owned data, and storage, if separately enabled and implemented | Primarily an analytics and monitoring surface rather than a general-purpose custom application |
| Sharing | App permission **and** delegated model/data permissions; share its protected link | Native dashboard sharing with the required source access |
| Teams | Share a link or Website bookmark; a custom embedded Teams tab is separate work | Use the supported dashboard sharing experience; do not assume every Fabric item embeds in the Teams Power BI tab |

**Choose the app** for a tailored executive experience, reusable code, and controlled
snapshot validation. **Choose the Real-Time Dashboard** for rapid KQL exploration,
native dashboard authoring, and frequent operational monitoring. They can coexist:
the app does not replace the operational dashboard or make its underlying queries faster.

The current app is **not a streaming dashboard**. One-minute browser polling does
not make a 15-minute metrics snapshot one minute fresh.

## Architecture and data guarantees

```text
Authorized KQL source / mirrored external tables
    -> Fabric refresh notebook (10 source-group queries)
    -> Metrics Lakehouse (Delta table)
    -> Direct Lake semantic model
    -> Delegated semantic-model connector
    -> Protected CISO Fabric App
```

The refresh covers **153 tile/period combinations**: 51 tiles times three periods.
It uses two query workers, a three-minute per-group timeout, and a ten-minute query
budget. Larger source datasets still require performance validation.

Successful results, tile-completion records, and refresh metadata are appended
together in one Delta transaction. Query failures publish failure metadata, not
partial KPI results. Readers retain the last complete successful batch and choose
the newest batch by its time anchor rather than append order.

Empty results have completion records without invented rows. The frontend rejects
missing or duplicate completions, invalid JSON, unexpected tiles, mixed batches or
periods, and truncated packet sets before displaying metrics.

App-owned database, storage, and functions services are disabled. The notebook and
metrics Lakehouse are separate Fabric items, not data bundled into the frontend.

## Deployment requirements

| Requirement | What to prepare |
| --- | --- |
| Fabric availability | Confirm Fabric Apps availability in the target region and tenant; the tenant administrator must enable the workload |
| Capacity | This end-to-end architecture needs supported Fabric capacity or a suitable trial for its KQL, notebook, Lakehouse, and Direct Lake dependencies |
| Licensing | Check [Fabric Apps licensing](https://learn.microsoft.com/fabric/apps/licensing) and Power BI semantic-model licensing separately for developers and readers |
| Deployment identity | An approved account able to create/update the required items; source-query and Lakehouse-write rights for the notebook execution identity |
| Reader identity | App Run and interact, semantic-model Read + Build, and required metrics data access |
| Local tools | Node.js 24, npm, and Git; Python for the refresh-safety unit tests |
| Packages | Access to the feed hosting the pinned packages; preserve compatible versions and the lockfile |
| Notebook runtime | A published Fabric Environment containing the dependency in [metrics/environment.yml](metrics/environment.yml) |
| Source data | Authorized KQL external tables with the columns and types required by the retained query definitions |
| Operations | Ownership of refresh scheduling, monitoring, capacity usage, permission reviews, and schedule renewal |

Fabric Apps also offers a Power BI Pro creation option, but that option alone does
not provision the KQL/notebook/Lakehouse architecture described here. Do not assume
every reader needs Pro solely for the app item, or that app access waives the
semantic model's licensing requirements.

**Dependency portability:** the current lockfile references an organization package
feed. A public clone is not guaranteed to restore packages. Before distribution,
confirm access and redistribution terms, remove confidential feed references, and
regenerate the lockfile using an approved accessible feed with compatible versions.
Do not commit feed credentials or silently replace pinned packages with `latest`.

### Required source tables

The current query plan uses:

```text
SecurityIncident
SecurityAlert
SigninLogs
AuditLogs
BehaviorAnalytics
AlertInfo
EmailEvents
DeviceProcessEvents
```

The definitions use `external_table(...)`. Having a similarly named table only in
Log Analytics is not sufficient: verify the corresponding mirror/external table
in the selected KQL database. Review the projected source columns in
[scripts/build-ciso-query.mjs](scripts/build-ciso-query.mjs) and the companion
dashboard queries. Source collection/mirroring is a prerequisite, not configured
by the app deployment.

## Project layout

Preserve this relative layout when distributing the full project:

```text
<repository-root>/
  CISO-Command-Center.fabric.json     # Reviewed query/template definition
  fabric-app/
    README.md
    package.json
    package-lock.json
    rayfin/
    metrics/
    scripts/
    packages/
```

The generator and notebook controller read
[the companion dashboard definition](../CISO-Command-Center.fabric.json) from the
parent folder. Publishing only the application subfolder without it breaks query
generation and notebook preparation.

| Path | Purpose |
| --- | --- |
| [packages/frontend](packages/frontend) | React/Vite UI, authentication, query hooks, and visuals |
| [packages/frontend/src/queries/metrics](packages/frontend/src/queries/metrics) | Period-specific DAX queries and visual specifications |
| [packages/data](packages/data) | Base runtime package; app-owned data service is disabled |
| [packages/shared](packages/shared) | Shared contracts |
| [rayfin/rayfin.yml](rayfin/rayfin.yml) | Protected hosting, authentication, and connector declaration |
| [metrics/refresh.py](metrics/refresh.py) | Complete-batch query execution and Delta publication |
| [metrics/preflight.py](metrics/preflight.py) | Source authentication and SDK preflight |
| [metrics/notebook-control.mjs](metrics/notebook-control.mjs) | Environment/notebook orchestration using local deployment state |
| [scripts/build-ciso-query.mjs](scripts/build-ciso-query.mjs) | Query plan and frontend metadata generation |

## Step-by-step deployment to Fabric

Run local commands from **the application folder containing this README**.
Replace all placeholders with your own approved values locally. These are setup
instructions, not permission to overwrite an existing deployment.

### 1. Prepare a clean, correctly targeted local copy

1. Complete the publication checklist before cloning or distributing a public copy.
2. Preserve the parent dashboard definition and application-folder layout above.
3. Do not copy another environment's runtime variables or deployment registry.
   They can target an existing app unexpectedly.
4. Configure your KQL endpoint/database in [metrics/refresh.py](metrics/refresh.py),
   [metrics/preflight.py](metrics/preflight.py), and
   [metrics/diagnostics.py](metrics/diagnostics.py) if you use diagnostics.
5. Set the expected tenant guard in
   [metrics/notebook-control.mjs](metrics/notebook-control.mjs) to your approved
   tenant. Preserve the guard and API-origin validation; do not disable them.

These scripts currently contain deployment-specific settings. They do **not**
automatically read arbitrary environment variables. For a public release,
externalize such settings into ignored local configuration or provide explicit
placeholders and document their substitution. Review local configuration changes
again before every commit.

### 2. Install dependencies and sign in

After configuring access to the approved package feed:

```powershell
node --version
npm ci
npx rayfin login
npx rayfin login status
```

Select the intended tenant/account. Use protected credential storage; never paste
tokens into source files, command arguments, or the README.

Set a local workspace variable for the later connector and deployment commands:

```powershell
$workspaceId = "<WORKSPACE_ID>"
```

### 3. Verify source availability

In the target KQL database, check each required external table and its schema.
Run a small bounded aggregate before attempting the full refresh. A missing table,
access failure, or partial query error is a blocker, not a zero-valued KPI.

Retain the approved 51-tile query contract. Changes to tiles require corresponding
generator, refresh-plan, frontend metadata, and test updates.

### 4. Create the metrics Lakehouse and published Environment

In the approved Fabric workspace:

1. Select **New item -> Lakehouse**. Use `CISO_Metrics` as the local project name.
   The current refresh worker uses this name in its Spark table references.
2. Select **New item -> Environment**. Use `CISO_Metrics_Runtime` as the project name.
3. Add the pinned `azure-kusto-data` dependency from
   [metrics/environment.yml](metrics/environment.yml), then **Publish**.
4. Wait for successful environment publication before running the notebook.
5. Record your workspace, Lakehouse, and Environment IDs in the ignored local
   file `metrics/deployment.json`:

   ```json
   {
     "workspaceId": "<WORKSPACE_ID>",
     "lakehouseId": "<METRICS_LAKEHOUSE_ID>",
     "lakehouseName": "CISO_Metrics",
     "environmentId": "<PUBLISHED_ENVIRONMENT_ID>"
   }
   ```

These names are suggested project resource names, not identifiers for an existing
deployment. If you rename them, update every dependent Spark reference and the
Environment configuration emitted by the controller.

### 5. Create and run the source preflight notebook

For a new notebook only:

```powershell
node metrics\notebook-control.mjs create-preflight
```

The controller records the created notebook ID locally. If creation returns a
pending operation, respect its retry guidance and use `resolve-create`; do not
create a duplicate notebook.

```powershell
node metrics\notebook-control.mjs resolve-create
```

Run `resolve-create` only when creation is pending. For an existing approved
notebook, use `update-preflight` instead of creating another one.

```powershell
node metrics\notebook-control.mjs run
node metrics\notebook-control.mjs status
```

Wait until the recorded retry time before checking status. In Fabric, inspect the
notebook run and exit value: the preflight must report verified source access.
Do not publish notebook outputs or source counts. SDK/import, authentication,
tenant, or query errors must be resolved before continuing.

### 6. Publish and verify a complete metrics batch

```powershell
node metrics\notebook-control.mjs update-refresh
node metrics\notebook-control.mjs run
node metrics\notebook-control.mjs status
```

The controller embeds the ten source-group query plan, attaches the metrics
Lakehouse and published Environment, and updates the notebook definition.
Respect any pending update/run retry interval.

Verify in Fabric that:

- The full run succeeds, not just job submission.
- Its exit summary reports ten queries and **153 tile/period combinations**.
- The persisted Delta table is **`cisometricpackets`**.
- Results, 153 completion records, and successful refresh metadata form a complete
  batch. Result-row counts vary with your data; do not compare them to demo values.
- The worker's persisted packet-count check succeeds.

Do not deploy a monolithic combined query as the refresh worker merely because a
diagnostic query returns some rows. Partial results and timeout warnings are failures.

### 7. Create the Direct Lake semantic model

1. Open the metrics Lakehouse in Fabric.
2. Select **New semantic model**.
3. Select only `cisometricpackets`, choose a model name, and confirm creation.
4. Keep the semantic-model table name `cisometricpackets` for the existing DAX.
5. Verify these ten application columns:

   ```text
   BatchId, AsOf, Kind, TileId, PeriodDays, RowIndex,
   RowJson, QueriedAt, FinishedAt, Status
   ```

No custom model measures are required; KPI query results are stored in `RowJson`.
Use the native model-creation workflow here rather than assuming the controller's
optional REST model-creation path works in every environment.

### 8. Register and validate the delegated connector

Record the model's actual ID locally, then run:

```powershell
$semanticModelId = "<SEMANTIC_MODEL_ID>"
npx rayfin connector add --type fabric-semanticmodel --name cisometrics `
  --workspace-id $workspaceId --item-id $semanticModelId `
  --auth delegated --operations executeQuery
npx rayfin connector inspect --name cisometrics
```

If `cisometrics` already exists, review and approve the CLI's re-add prompt for the
intended model. Keep the alias unchanged because the frontend uses it. Let the CLI
maintain generated connector wiring; check both authentication and operation scope.
The table listing must include `cisometricpackets`.

Validate the full 7/30/90-day queries in
[the metrics query folder](packages/frontend/src/queries/metrics). The following
PowerShell example sends each complete query through the connector, saving private
input/output files only in the CLI's ignored scratch directory:

```powershell
New-Item -ItemType Directory -Force -Path rayfin\.temp | Out-Null
foreach ($days in 7, 30, 90) {
  $query = Get-Content -Raw "packages\frontend\src\queries\metrics\metrics-$days.dax"
  @{ query = $query } | ConvertTo-Json |
    Set-Content -Encoding utf8 "rayfin\.temp\metrics-$days.input.json"
  npx rayfin connector invoke cisometrics executeQuery `
    --file "rayfin\.temp\metrics-$days.input.json" `
    --output-file "rayfin\.temp\metrics-$days.output.json"
  if ($LASTEXITCODE -ne 0) { throw "Metrics query failed for $days days." }
}
```

Use PowerShell 7 for UTF-8 JSON without a byte-order mark. Complete the approved
interactive Power BI query consent if prompted; do not broaden management
permissions to troubleshoot a read query. Inspect the **full output files**, not
the CLI's preview. A capped inspection sample does not prove batch completeness.
The app's packet parser is the final integrity gate.

### 9. Validate the app and protected configuration

Run the checks serially:

```powershell
npm run typecheck
npm run build
npm run lint
npm test
npm run validate:visual
node --test scripts\build-ciso-query.test.mjs
python -m unittest discover -s metrics -p test_refresh.py
```

Stop on a failed gate. Build does not replace type-check, and static visual
validation does not prove meaningful chart rendering.

Review [rayfin/rayfin.yml](rayfin/rayfin.yml):

- Authentication and Fabric authentication are enabled.
- Password authentication is disabled.
- Static hosting uses `assetAccess: protected`.
- The connector uses delegated authentication and only `executeQuery`.
- Redirect URIs contain only approved local URLs and your own hosting URL.

For frontend-only development, `npm run dev:frontend` still needs valid runtime
configuration. `npm run dev` can provision/update remote services; it is not a
no-impact layout preview.

### 10. Preview and deploy to the explicit workspace

```powershell
npx rayfin up -n --workspace-id $workspaceId --json
```

Review the resolved workspace name/ID and planned changes. A dry run does not build
or deploy. Proceed only after the workspace owner approves the target and operation:

```powershell
npx rayfin up --workspace-id $workspaceId --item-name "CISO Command Center" --json
```

Review any same-name item before approving reuse; do not add force/automatic
approval flags to bypass that decision. Check the connector's deployment result,
not only overall success. A documented `non-graphql-connector` generation skip
for this semantic-model connector is not itself a failure; missing or failed
required connector deployment is a blocker.

Use the actual hosting and Fabric management links emitted by the CLI. Keep those
links, runtime environment files, and deployment registry out of public Git.
Confirm the allowed redirect URI matches your new host; revalidate/deploy any
required auth configuration update rather than reusing another deployment's URL.

### 11. Grant reader access and validate as a reader

For each approved reader:

1. **Fabric App -> Share / Manage permissions:** grant **Run and interact**
   (Read + Execute), without Edit or Reshare.
2. **Semantic model -> Manage permissions -> Direct access:** grant **Read + Build**.
   Build permits querying/reusing model data; it does not give model Write access.
3. **Metrics Lakehouse -> Manage OneLake security:** where supported, create a
   **Read** role with **Selected data -> Tables -> cisometricpackets**, then add the
   reader. Check existing roles for unintended broader access.
4. Verify any required item-level metadata access and the model's source identity/
   security mode. Lakehouse metadata Read alone is not a guarantee of table-data access.
5. Check the reader's Power BI dependency license. Do not grant workspace Admin,
   Member, or broad source-data access as a shortcut.
6. Have the reader sign back in after propagation and open the protected app.

Test signed-out protection, all seven pages, all three periods, charts with
meaningful marks, maps/grids, refresh, and error states. Test Fabric-hosted use and
the standalone link separately. Owner-side success does not prove reader access.
For a reader-only "Cannot find table" error, verify model Build and source-data
rights before recreating a model that works for its owner.

### 12. Schedule and operate the refresh

After measuring **full notebook duration including startup**, configure its Fabric
schedule for a 15-minute interval in UTC and an explicit end date, for example
90 days after activation. Ensure the complete run fits comfortably in the interval.

Verify a scheduled run under the actual execution identity produces a complete
batch and becomes visible through the model/app. Renew the schedule before expiry,
monitor failures and capacity costs, and manage Delta history/retention through an
approved policy.

The current UI describes a 15-minute schedule and marks snapshots older than
30 minutes overdue. If you intentionally change cadence, update those descriptions
and thresholds together. Browser Refresh reloads metrics; it does not repair a
failed or expired notebook schedule.

## Sharing in Teams

Share the approved protected app link in a Teams message or pin it as a Website
bookmark. Current Teams Website tabs open in the browser; this is **link sharing**,
not a packaged in-Teams dashboard.

Fabric items cannot be embedded through the Teams Power BI tab. A custom Teams tab
would require separate packaging, SSO, framing validation, and tenant approval.
Teams sharing does not grant Fabric, model, or OneLake permissions.

Never enable anonymous hosting or Power BI **Publish to web** for security data.

## Publishing to your repository without confidential information

**Scope:** the steps below are publication requirements, not a statement that the
whole checkout or any existing archive has passed a confidentiality review.
Configuration identifiers are not passwords, but can still disclose environment
details. Secret scanners alone will not find all confidential information.

### 1. Prepare an explicit publication copy

Use a clean export of reviewed source and templates, preserving the relative
layout above. Do not copy the working directory wholesale or reuse an old ZIP.
Exclude runtime state, dependencies, outputs, logs, caches, screenshots, and real
data. A private repository is not permission to upload confidential material.

### 2. Sanitize the files that need configuration

| Area | Publication requirement |
| --- | --- |
| [rayfin/rayfin.yml](rayfin/rayfin.yml) | Replace actual workspace/model IDs and hosted redirect URLs with documented local configuration or placeholders; preserve protected auth defaults |
| Metrics Python scripts | Remove actual KQL endpoints/database references and any environment-specific paths; retain generic query logic and explicit configuration instructions |
| [metrics/notebook-control.mjs](metrics/notebook-control.mjs) | Externalize or replace the actual expected-tenant setting; retain tenant/origin guards and explain local setup |
| `metrics/deployment.json` | Exclude actual item IDs, job/operation URLs, schedules, timestamps, and batch summaries; supply only a reviewed placeholder example |
| Companion dashboard JSON | Review data-source definitions, workspace/item references, query literals, URLs, identities, and markdown; preserve the template contract |
| Other guides and HTML previews | Remove environment URLs, accounts, filesystem paths, execution history, customer context, and real metric values; label synthetic demos clearly |
| Notebook exports | Clear all outputs and execution metadata containing data/identities; inspect attachments and encoded/base64 content as well as visible cells |
| Package manifests and lockfile | Remove private/internal links and confidential feed references; verify package access and regenerate a compatible lockfile through the package manager |
| Archives and release assets | Rebuild only from the reviewed publication copy; inspect their contents independently |

Do not indiscriminately replace every GUID: template tile/page/query IDs are used
by the generator and tests. Distinguish those stable logical IDs from actual tenant,
workspace, item, user, and deployment identifiers.

Keep representative examples synthetic. Incident titles, email subjects, sender
domains, user names, IP addresses, coordinates, entity names, KPI snapshots, and
security query literals can contain customer information even without secrets.

### 3. Exclude local state before staging

Review [.gitignore](.gitignore) and add missing project-specific exclusions to the
publication copy. In particular, the current ignore file does not explicitly
exclude the metrics deployment state. An application-folder example is:

```gitignore
.env*
!.env.example
metrics/deployment.json
rayfin/.env*
rayfin/.deployments.json
rayfin/.temp/
rayfin.config.json
.schema/
.fabric-app-semantic-model-tools-*/
node_modules/
dist/
coverage/
*.log
*.tsbuildinfo
*.zip
```

Review nested environment files and parent-folder archives too; ignore rules are
path-scoped. Any allowed example file must contain placeholders only. Ignore rules
do not remove already tracked files or their earlier Git history.

### 4. Review licensing and attribution

Include the upstream notices and license files required for code you distribute.
Confirm you are authorized to publish the app, template queries, and bundled assets.
A `license` field in a package manifest is not a substitute for this review.
Do not redistribute private package contents or dependencies from `node_modules`.

### 5. Scan content, history, and the actual staged files

Before any push:

- Search for your own deployment IDs, tenant domains, accounts, hostnames, local
  paths, internal repository/feed links, and known confidential query literals.
- Run an approved secret scanner for credentials, tokens, keys, certificates, and
  connection strings. Inspect notebook outputs, binary assets, and archives separately.
- Review Git history, branches, tags, and release assets if reusing a repository.
  Removing a value from the current file does not remove earlier committed versions.
- If a secret was exposed, revoke/rotate it and follow the approved incident and
  history-cleanup process; do not rely only on deleting the visible value.

Stage reviewed files explicitly rather than `git add .`. For example, from the
repository root, stage this reviewed document with:

```powershell
git add -- fabric-app/README.md
git --no-pager diff --cached --stat
git --no-pager diff --cached
git status --short
```

Repeat the review for every source/template file you intend to publish. Do not
attach live query results or deployment logs to commits, pull requests, or issues.

### 6. Verify portability, then publish

From a fresh clone/export without your private environment state:

1. Confirm `npm ci` restores from the approved documented feed.
2. Run the validation commands from deployment step 9.
3. Check the placeholder configuration instructions and required companion file.
4. Confirm no private data is needed merely to build or run unit tests.
5. Have an authorized reviewer approve the final staged content and distribution.
6. Choose repository visibility, enable available secret scanning/push protection,
   commit the reviewed files, and push only to the intended repository.

Public source code does not make the deployed app or its data public. Readers must
still authenticate and have the appropriate Fabric, model, and data permissions.

## References

- [Microsoft Fabric Apps overview and tenant setup](https://learn.microsoft.com/fabric/apps/overview)
- [Fabric Apps licensing](https://learn.microsoft.com/fabric/apps/licensing)
- [Create and customize a Real-Time Dashboard](https://learn.microsoft.com/fabric/real-time-intelligence/dashboard-real-time-create)
- [Share a Fabric App and related items](https://learn.microsoft.com/fabric/apps/share-app)
- [Direct Lake](https://learn.microsoft.com/fabric/fundamentals/direct-lake-overview)
- [Semantic-model Build permission](https://learn.microsoft.com/power-bi/connect-data/service-datasets-build-permissions)
- [Create and manage OneLake security roles](https://learn.microsoft.com/fabric/onelake/security/create-manage-roles)
- [Teams limitations for Fabric items](https://learn.microsoft.com/power-bi/collaborate-share/office-integration/service-collaborate-microsoft-teams#known-issues-and-limitations)
