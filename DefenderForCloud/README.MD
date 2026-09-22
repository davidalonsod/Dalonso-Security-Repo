# 🛡️ Microsoft Defender for Cloud — CIEM Risk & Least Privilege Dashboard

Are Your Cloud Permissions Over-Privileged? Multi-Cloud CIEM Explained with Defender for Cloud https://youtu.be/sDRjvGuBV0s 

An **Azure-hosted multi-cloud Workbook** that turns Microsoft Defender for Cloud's CIEM view
into a **Cloud Infrastructure Entitlement Management operations console**. It combines
Defender CIEM findings for Azure, AWS and GCP, multi-cloud Defender CSPM attack paths, Azure
RBAC via Azure Resource Graph, and optional Azure Activity / Microsoft Entra audit logs. No
third-party product is required for the implemented views.

- **File to import:** `Defender-CIEM-RiskLeastPrivilege-Workbook.json`
- **Generator (source of truth):** `Build-CIEMWorkbook.ps1`
- **Type:** Azure Monitor / Microsoft Sentinel workbook (`Notebook/1.0`)
- **Tabs:** 11 · **Query tiles:** 74 (61 Azure Resource Graph + 13 Log Analytics) · **Data source:** Azure Resource Graph (`securityresources`, `authorizationresources`, `resources`, `resourcecontainers`) + Log Analytics (`AzureActivity`, `AuditLogs`, and optional attack-path history)
- **Attack-path history (optional):** `Snapshot-AttackPaths.ps1` feeds first-seen / resolved / history into `CIEM_AttackPaths_CL`

> It reframes CIEM around four questions instead of a provider-by-provider inventory:
> **Where is the greatest identity risk? · Which identities create attack paths? · What
> permissions are unused? · What should we remediate first?**

---

## Repository contents

| File | Purpose |
|---|---|
| `Defender-CIEM-RiskLeastPrivilege-Workbook.json` | The importable Azure Workbook (paste into Advanced Editor). |
| `Build-CIEMWorkbook.ps1` | Deterministic generator / source of truth — edit and re-run to rebuild the JSON. |
| `Snapshot-AttackPaths.ps1` | Manual/local attack-path snapshot (`Az.Accounts` + `Az.ResourceGraph`). |
| `Deploy-AttackPathSnapshot.ps1` | One-command stand-up of the attack-path history pipeline (infra + runbook + schedule + roles). |
| `infra/attackpath-snapshot.bicep` | DCE · `CIEM_AttackPaths_CL` table · DCR · Automation account + managed identity · DCR role. |
| `infra/runbook/Snapshot-AttackPaths.Runbook.ps1` | Zero-module PowerShell 7.2 Automation runbook (managed-identity, REST). |
| `README.md` | This document. |

---

## Why this instead of the built-in CIEM page

The built-in Defender for Cloud CIEM view lists over-provisioned and unused identity
*recommendations*. This workbook adds the operational layer on top:

| Built-in CIEM | This workbook |
|---|---|
| Recommendation counts per cloud | **Risk-ranked identities** with a transparent 0–100 score |
| Human + non-human mixed together | Dedicated **Non-Human Identities** tab (SP / MI / AI) |
| No prioritization | **CIEM Risk Score** for triage ordering (queue) |
| No unified remediation queue | **Evidence-aware least-privilege queue** with review guidance and portal links; approval/closure tracking remains external |
| No privilege lineage | **Privilege & Entitlement** tab from Azure RBAC |
| No program view | **Governance** tab: per-subscription posture, severity, bands |
| Provider evidence differences are easy to miss | Explicit `UsageEvidenceStatus` and cloud/connector coverage |
| Attack-path list hides graph context | Azure/AWS/GCP provider, account/project, entry/target, identities/resources and optional history |

---

## The 11 tabs

| Tab | Answers | Primary source |
|---|---|---|
| 📊 **Overview** | Exposure KPIs, executive risk statement, cloud/connector coverage, AWS/GCP connector readiness and inventory, evidence gaps, identity classes, secure score, privilege concentration, top risk | CIEM assessments + ARG/RBAC/resources |
| 🧭 **Identity Risk** | Ranked queue with cloud, raw/normalized identity type, `UsageEvidenceStatus`, counts and Defender link | CIEM assessments |
| 👑 **Privilege** | Azure role/scope/principal analytics, crown-jewel access, **escalation primitives**, review command, **blast radius** | Azure RBAC |
| ⏱️ **PIM Changes** | Current Azure privileged posture; selected-workspace readiness; ARM role/schedule/policy changes; PIM workflow, approval, actor and failure views | ARG + `AzureActivity` + Entra `AuditLogs` |
| 🔗 **Effective Permissions** | Identity selector; published granted-but-unused actions and provider breakdown; cloud-aware filtering | CIEM assessments |
| ✂️ **Least Privilege** | Evidence-aware rightsizing KPIs, utilization/evidence bands, provider-validation buckets and remediation queue | CIEM assessments |
| 🤖 **Non-Human** | Service principals, managed/AI identities, risk queue, attached managed-identity workloads with broad privilege | CIEM + Azure RBAC/resources |
| 💎 **Critical Assets** | Azure crown-jewel resource inventory plus direct and inherited broad privileged reach | Azure RBAC + resources |
| 🕸️ **Attack Paths** | Source health; Azure/AWS/GCP cloud/account coverage; graph entry/target and participating identities/resources; risk/category/toxic combinations; optional active/resolved history | Defender CSPM ARG `graphComponent` + optional `CIEM_AttackPaths_CL` |
| 🗄️ **Resource Access** | Filtered Azure assignment summary, scope/principal distributions and top scopes | Azure RBAC |
| 📋 **Governance** | Current finding lifecycle, subscription posture, severity and calculated risk bands; ownership/SLA extension guidance | CIEM assessments |

**Implemented capability layers:** ARG provides provider-normalized CIEM findings, Azure RBAC
lineage/escalation/blast radius, workload attachment context, secure score, and multi-cloud
attack-path graphs. Log Analytics optionally provides Azure RBAC/PIM change history and
snapshot-backed attack-path history. The workbook provides review guidance, not an approval,
ticketing, rollback, or verified-closure system.

### Capability status at a glance

| Capability | Cloud scope | Status / evidence source |
|---|---|---|
| Inactive and overprovisioned identity findings | Azure / AWS / GCP | Implemented from Defender CIEM assessments; provider identity types normalized and raw type retained. |
| Permission-utilization detail | Azure; provider-dependent elsewhere | Implemented when `UsageEvidenceStatus=Available`; AWS/GCP route to provider validation when Defender does not publish action detail. |
| Entitlement lineage, privileged roles and resource reverse lookup | Azure | Implemented from Azure RBAC; group-member expansion, PIM eligibility inventory and full net-effective graph remain external. |
| PIM/RBAC change monitoring | Azure resources / Entra workflow | Optional Log Analytics layer; `AzureActivity` and `AuditLogs` are evaluated independently with readiness status. |
| Human, workload and AI identity views | CIEM multi-cloud + Azure workload attachment | Implemented for CIEM findings; attached workload-to-managed-identity mapping is Azure-specific. |
| Critical-resource reach | Azure | Implemented as resource-type/RBAC approximation; business criticality, sensitivity and ownership enrichment remain external. |
| Current attack paths and graph entities | Azure / AWS / GCP / cross-cloud | Implemented from Defender CSPM ARG `graphComponent`, including provider/account, entry/target, identities/resources and source health. |
| Attack-path first-seen/resolved/trends | Azure / AWS / GCP / cross-cloud | Optional snapshot pipeline to `CIEM_AttackPaths_CL`, including zero-path heartbeat handling. |
| Remediation operations | All findings | Review guidance and deep links only; approval, ticketing, rollback, exception and verified closure are not implemented. |
| CIEM backlog/history trends | All | Not implemented; current CIEM assessments are current state. Snapshot to a custom table for backlog age and closure rate. |

> **Tenant-bound scope:** Azure Workbooks and Azure Resource Graph query one Microsoft Entra tenant
> context at a time. `Subscription = All` means all subscriptions visible in the current Azure
> portal directory, not subscriptions across every tenant associated with the user. If AWS/GCP
> connectors are hosted in another tenant, switch directory and open/import the workbook there.

---

## Global filters (pill bar, applied where the source supports them)

| Filter | Effect |
|---|---|
| **Subscription** | Multi-select; scopes every tile (via `crossComponentResources`). Defaults to all. |
| **Time Range** | Applies to Log Analytics PIM/history panels. ARG CIEM/RBAC panels are current state and have no historical timestamp. |
| **Cloud** | All / Azure / AWS / GCP. Applies to provider-normalized CIEM and attack-path panels; Azure RBAC tabs remain Azure-only. |
| **Identity type** | All / User / Group / Service principal / Managed identity. |
| **Risk level** | Filters the Identity Risk grid by computed band. |
| **State** | Unhealthy (default) / Healthy / All (recommendation status). |
| **Privilege** | All / Privileged only / Owner only (applied to RBAC tiles). |
| **Identity** | Free-text identity-name filter (drives the Effective Permissions tab). |
| **Workspace (PIM / history)** | ARG-backed picker listing accessible Log Analytics workspaces in the selected subscriptions. Prefer the workspace holding `AzureActivity`, `AuditLogs`, and optionally `CIEM_AttackPaths_CL`; `LAWSentinel` is selected by default when available. |
| **Show history** | Off (default) / On — reveals the snapshot-backed first-seen / resolved / history tiles on Attack Paths. |
| **Resource filter** | Free-text scope fragment for the Resource Access tab. |

---

## CIEM Risk Score (transparent, in the open)

> ⚠️ **This is a workbook-calculated score, not an official Microsoft Defender for Cloud
> metric.** It exists purely to order CIEM findings for triage. The formula is visible in the
> *Least Privilege* tab and reproduced here so anyone can audit it.

Built only from fields Defender for Cloud CIEM actually exposes in `additionalData`
(`usedCount`, `unusedCount`, `ResourceType`, `ai_identity`) plus assessment `metadata`:

> Since August 6, 2026, Defender no longer publishes unused-action details for AWS/GCP.
> The workbook marks those records as `UsageEvidenceStatus = ProviderValidationRequired`;
> their score has no utilization-gap points, so treat it as a lower bound rather than as
> evidence of low risk. Other states are `Available`, `MissingTelemetry`, and `NotApplicable`.

| Factor | Points | Basis |
|---|---|---|
| Permission-utilization gap | ≤ 40 | `unusedCount / (usedCount + unusedCount)` → 95%+ = 40, 75%+ = 30, 50%+ = 20, >0 = 10 |
| Identity type | ≤ 15 | Service principal 15 · Managed identity / application 12 · User 8 · other 5 |
| Inactivity | 20 | Identity flagged by the *inactive identities* CIEM finding |
| Severity | ≤ 15 | Assessment `metadata.severity` (High 15 · Medium 10 · Low 5) |
| AI identity | 10 | `additionalData.ai_identity == true` |

**Bands:** Critical ≥ 80 · High ≥ 60 · Medium ≥ 35 · Low < 35.

---

## Data sources and capability boundaries

| ARG table | Used by | Notes |
|---|---|---|
| `securityresources` — `microsoft.security/assessments` | Overview, Identity Risk, Least Privilege, Non-Human, Governance | The over-provisioned + inactive CIEM finding families across Azure, AWS, and GCP. Requires **Defender for Cloud CIEM / Permissions Management** enabled. |
| `securityresources` — `microsoft.security/attackpaths` | Attack Paths | Native multi-cloud paths across Azure, AWS and GCP. Requires **Defender CSPM**, provider connector coverage, agentless scanning where applicable, and Security Reader/Reader access. |
| `securityresources` — `microsoft.security/securescores` | Overview | Defender secure score per subscription. |
| `authorizationresources` — `roleassignments` / `roledefinitions` | Privilege, Escalation, Blast radius, Resource Access | Azure RBAC; always available. |
| `resources` (attached managed identities) | Non-Human (over-privileged workloads), Critical Assets | MI-to-workload mapping + crown-jewel inventory. |
| `resourcecontainers` — `subscriptions` | Overview, Governance | Subscription display names. |
| `AzureActivity` (Log Analytics) | PIM Changes | ARM role assignment, schedule-request, and role-management-policy operations. |
| `AuditLogs` (Log Analytics) | PIM Changes | PIM activation, eligibility, approval, assignment, policy, and alert-setting workflow. |

**Minimum viable deployment:** Defender for Cloud with **CIEM (Permissions Management)**
enabled so the identity assessments populate. RBAC tabs work with no extra setup.

### AWS / GCP visibility troubleshooting

The built-in Defender recommendations page can span cloud environments, while workbook ARG
queries are scoped through the **Subscription** parameter. AWS/GCP assessment resources are
stored under the Azure subscription associated with each Defender for Cloud connector.

1. Set **Cloud = All** and include the connector-hosting Azure subscription in
   **Subscription**. Check **CIEM source coverage by cloud and connector subscription** on
   Overview, then inspect **Defender multicloud connector readiness** and **Visible Defender
   for Cloud connectors**.
2. If the AWS/GCP connector subscription belongs to another Microsoft Entra tenant, switch
   the Azure portal directory first. A workbook in the current directory can't query ARG in
   another tenant merely because that subscription appears in an account list.
3. Under **Defender for Cloud → Environment settings**, verify Defender CSPM and
   **Permissions Management (CIEM)** are enabled for the AWS account or GCP project.
4. Enable AWS CloudTrail ingestion for stronger AWS identity evaluation and GCP Cloud
   Logging ingestion for GCP CIEM evaluation. Allow a few hours after configuration.
5. Confirm that your Azure identity has Reader access to the connector-hosting subscription;
   Resource Graph only returns assessment rows the current identity can read.

AWS IAM users/roles/groups and GCP users/groups/service accounts are normalized into the
workbook's User, Group, and Service principal filter categories. The original provider type
remains visible as `IdentityTypeRaw`.

### PIM Changes telemetry

The tab works in layers: its current active privileged-access KPI comes from Resource Graph
with no workspace dependency. Historical panels use whichever source is present in the
selected workspace: `AzureActivity` supplies ARM changes, while `AuditLogs` supplies PIM
workflow/approval detail. Full coverage requires both.

1. On every monitored subscription, create an Activity Log diagnostic setting that sends
   **Administrative** events to the workspace (`AzureActivity`).
2. In Microsoft Entra diagnostic settings, send **AuditLogs** to the same workspace.
3. Select that workspace in **Workspace (PIM / history)** and choose the desired **Time Range**.

The **Selected workspace data readiness** grid reports the two sources independently. During
validation on **2026-09-22**, `LAWSentinel` had 24 Azure authorization events in 90 days but
no PIM service events in `AuditLogs`; the latter must be routed from Microsoft Entra diagnostic
settings. A workspace can contain `AzureActivity` without containing Entra PIM workflow data.

The tab treats successful broad Owner/UAA/RBAC Administrator/Contributor writes as review
candidates and exposes caller type, object ID, application ID, IP, principal, scope, and
correlation ID. A direct `roleAssignments/write` event is not by itself proof that PIM was
bypassed because an activation can materialize a temporary active assignment. Confirm origin
from the adjacent PIM lifecycle events and caller metadata.

---

## Import / deploy

**Portal (fastest)**

1. **Microsoft Sentinel → Workbooks** (or **Azure Monitor → Workbooks**) → **Add workbook → Edit → `</>` Advanced Editor**.
2. Paste the contents of `Defender-CIEM-RiskLeastPrivilege-Workbook.json` → **Apply**.
3. **Done Editing → Save**, name it *Defender for Cloud — CIEM Risk & Least Privilege*, pick a resource group / location.
4. Select your **Subscription**(s) and start on **📊 Overview**.

**Regenerate from source**

```powershell
pwsh -File .\Build-CIEMWorkbook.ps1
```

Edit `Build-CIEMWorkbook.ps1` (parameters, tiles, KQL, the score model) and re-run to rebuild the JSON deterministically.

---

## Validation status

- **Structure:** 11 tabs / 11 groups parity, 74 query tiles (61 Azure Resource Graph + 13 Log Analytics), all ARG tiles cross-subscription-scoped, no empty groups. ✔
- **RBAC posture:** built-in role GUID classification validated live — 26 privileged assignments across 15 identities, including 14 Owner assignments, 17 broad-scope grants and 14 non-human privileged identities. ✔
- **PIM changes:** AzureActivity and AuditLogs normalization compiled against live schemas; role/principal/scope/caller extraction was validated against real assignment writes, including a broad Owner grant. ✔
- **CIEM extraction:** provider-neutral title matching and type normalization compile live. The accessible subscriptions currently return 20 Azure overprovisioned and 17 Azure inactive findings; no AWS/GCP assessment rows are currently visible to this identity. ✔
- **Attack paths:** all 12 current-state ARG tiles compile through the Resource Graph REST API. Microsoft documents Azure/AWS/GCP support and AWS chains such as public EC2 → IAM role escalation → S3. The accessible subscriptions currently return **zero** `microsoft.security/attackpaths` rows, so AWS field extraction is schema-validated but cannot be behavior-validated against a live AWS path in this tenant. ✔
- **Current multicloud scope (2026-09-22):** in tenant `c65d…`, the selected subscription exposes one GitHub connector, zero AWS connectors and zero GCP connectors; exact workbook queries therefore return valid zero-valued AWS/GCP KPIs. Other accessible subscriptions are listed under tenant `0527…`, but this session has no token for that tenant, so its connector state couldn't be queried. ✔
- KQL uses ARG-portable functions including `extract`, `matches regex`, `iff`, `round`, `toreal`, `dcountif`, `sumif`, `coalesce`, `case`, `parse_json`, `array_length`, `substring`, `mv-expand`, `make_set`, and `strcat_array`. Built-in privileged roles are classified by GUID before the deduplicated role-definition join. ✔

---

## Attack-path history — first seen, resolved & solved paths

**Why a snapshot is required:** Defender for Cloud attack paths in Azure Resource Graph
(`microsoft.security/attackpaths`) are **current-state only** — the schema has *no timestamp*
and *no record of resolved paths* (fields are `displayName`, `riskLevel`, `potentialImpact`,
`riskCategories`, `attackPathType`, `AttackPathID`, and a `graphComponent` entity graph). Once
a path is remediated it simply disappears. So *first seen*, *resolved date*, and a
*solved-paths history* can only come from periodically snapshotting the active set.

**How it works**

1. Schedule `Snapshot-AttackPaths.ps1` (Azure Automation runbook or timer Function, e.g. daily).
   Each run appends one row per active attack path plus a snapshot heartbeat to
   `CIEM_AttackPaths_CL`, stamped with `TimeGenerated`. The heartbeat lets a zero-path run
   resolve paths that existed in the preceding snapshot.
2. In the workbook, pick your **Workspace (PIM / history)** and set **Show history = On**.
3. The Attack Paths tab then derives, per `AttackPathId`:
   - **First seen** = `min(TimeGenerated)`
   - **Resolved** = `max(TimeGenerated)` for paths absent from the latest snapshot (with duration)
   - **Active list** with age, a **Resolved list** with duration, and an **active/new/resolved trend**.

### One-command setup (recommended)

Stands up the whole pipeline — custom table, DCE, DCR, an Automation account with a
managed identity, the runbook, a daily schedule, and the required roles:

```powershell
Connect-AzAccount
.\Deploy-AttackPathSnapshot.ps1 -ResourceGroup rg-sentinel `
    -WorkspaceName law-sentinel-prod -Location eastus `
    -ReaderScopeSubscriptionIds '<subA>','<subB>' -RunNow
```

What it deploys (files under `infra/`):

| File | Provisions |
|---|---|
| `infra/attackpath-snapshot.bicep` | `CIEM_AttackPaths_CL` table · DCE · DCR (stream `Custom-CIEM_AttackPaths_CL`) · Automation account + system-assigned identity · Automation variables · **Monitoring Metrics Publisher** on the DCR |
| `infra/runbook/Snapshot-AttackPaths.Runbook.ps1` | Zero-module PS7.2 runbook (authenticates via the Automation managed identity, reads attack paths from ARG, ingests via the Logs Ingestion API) |
| `Deploy-AttackPathSnapshot.ps1` | Deploys the Bicep, imports/publishes the runbook, creates the daily schedule, and grants the identity **Reader** on the target subscriptions |

The history schema preserves `Cloud`, `ProviderSet`, AWS account / GCP project / Azure
subscription, entry-point and target entity IDs, node/connection counts, and bounded raw
entity/connection JSON. Re-run `Deploy-AttackPathSnapshot.ps1` after upgrading an existing
deployment so the custom table and DCR receive the added columns before the new runbook runs.

Prereqs: `Az.Accounts` + `Az.Resources` + `Az.Automation`, Owner/UAA on the resource group,
and **Defender CSPM** enabled (so attack paths exist). The runbook itself needs **no** modules
imported into Automation.

**Manual / local option:** `Snapshot-AttackPaths.ps1` (repo root) runs the same snapshot
interactively with `Az.Accounts` + `Az.ResourceGraph` against a table + DCR you create yourself
(steps in that script's header).

> The current-state Attack Paths tiles (source health, cloud/account coverage, risk/category,
> graph entities, entry/target and lists) work from ARG with no setup; the history tiles stay
> hidden until **Show history = On**. An empty source-health result means no current path rows
> were returned for the selected connector-hosting subscriptions, not that AWS/GCP are unsupported.

---

## Honest limitations (and how to close them)

This workbook deliberately does **not** overstate what Azure exposes as queryable data:

| Gap | Why | How to close it (advanced build) |
|---|---|---|
| **Credential age / expiry / owner** for non-human identities | Not in CIEM assessment data | Add Microsoft Entra: app credential inventory via Graph + `AADServicePrincipalSignInLogs`. |
| **Full net-effective-permission graph** | Not exposed as ARG data | Use **Defender for Cloud → Cloud Security Explorer**; the Attack Paths tab surfaces Defender CSPM paths and links out for deep traversal. |
| **Historical trends** | ARG reflects *current* state only | Snapshot CIEM state to Log Analytics on a schedule (Logic App / Function running the ARG query → custom table), then chart from there. |
| **Business ownership / SLA / crown-jewel tags** | Org-specific | Add a custom Log Analytics table or JSON source keyed on identity / subscription (see schema below). |
| **MFA / Conditional Access gap + dormant credentials** | Entra sign-in data is not in ARG | Add Log Analytics / Sentinel (`SigninLogs`, `AADServicePrincipalSignInLogs`) and join privileged identities to MFA/CA state + last activity. |
| **PIM standing vs eligible inventory** | PIM eligibility/schedule instances are not exposed in `authorizationresources` (only role definitions + assignments); the PIM Changes tab monitors changes but cannot reconstruct authoritative current eligibility | For Azure resource roles, collect ARM `Microsoft.Authorization/roleAssignmentScheduleInstances` and `roleEligibilityScheduleInstances` (`api-version=2020-10-01`). Microsoft Graph `/roleManagement/directory` is for Entra directory roles. |
| **Granted-vs-used from activity** | The PIM Changes tab monitors authorization changes, not every resource action performed under a grant | Correlate activation windows with broader `AzureActivity` operations over 30/90 days. |
| **AWS/GCP unused-action detail** | Defender stopped publishing these action lists on August 6, 2026 | Use AWS IAM last-accessed information or GCP Policy Intelligence and IAM role recommendations. |
| **Attack-path provider field stability** | Provider/account context is nested in `graphComponent` entities and can evolve by entity type | The workbook derives provider/account from structured graph JSON, preserves raw entity JSON, and labels cross-cloud paths through `ProviderSet`; validate new entity types as they appear. |

### Normalized schema for custom enrichment

To light up ownership, criticality and remediation SLAs, add a source with these columns and
join on `IdentityId` / `AccountOrSubscriptionId`:

```
IdentityId · IdentityName · IdentityType · HumanOrNonHuman · IdentityOwner
BusinessUnit · ApplicationName · AccountOrSubscriptionId · ResourceCriticality
RemediationOwner · RemediationDueDate · RiskAcceptanceExpiry · CIEMRiskScore
```

---

## MVP vs advanced

- **Implemented now:** provider-normalized CIEM findings · Azure RBAC/PIM posture and changes · multi-cloud Defender attack-path graph context · evidence-state handling · source-readiness panels · optional attack-path history · Defender deep links.
- **Advanced extensions:** CIEM finding snapshots and backlog-age trends · Entra/AWS/GCP credential inventory · provider-native entitlement/usage exports · ownership/criticality/exception mappings · ITSM approval, rollback and verified closure.
