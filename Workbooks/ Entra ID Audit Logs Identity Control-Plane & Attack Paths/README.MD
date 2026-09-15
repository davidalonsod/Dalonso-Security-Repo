# 🛡️ Entra ID AuditLogs — Identity Control-Plane & Attack Detection Workbook

A single Microsoft Sentinel / Azure Monitor workbook that turns the Microsoft Entra ID **`AuditLogs`** table into an identity **control-plane defense console** — serving SOC analysts, CISOs, and security architects from one surface.

> Don't just show `AuditLogs`. Turn individual audit events into **security stories**: *Actor → Target → Privilege → Application → Related change → Risk → MITRE → Investigation.*

- **File:** `EntraID-AuditLogs-ControlPlane-Workbook.json`
- **Type:** Azure Monitor / Microsoft Sentinel workbook (Gallery Template JSON, `Notebook/1.0`)
- **Tabs:** 12 · **Query tiles:** 54 · **Parameters:** 11
- **Backbone:** `AuditLogs`, enriched with `IdentityInfo`, `SigninLogs` / `AADUserRiskEvents`, and `SecurityAlert`

---

## Why this workbook

Most identity dashboards report *how many* administrative events occurred. That number is useless to a CISO, un-triageable for a SOC analyst, and un-actionable for an architect.

This workbook answers the questions that matter instead:

> **Who** changed the control plane, **what** changed, **how consequential** was it, does it form part of an **attack path**, and is the organization actually **in control** of Entra?

`AuditLogs` is the record of every traceable change to users, groups, roles, applications, service principals, policies, and tenant configuration — the **control plane** of your identity estate. This workbook converts those raw events into ranked, enriched, investigable stories.

---

## Key capabilities

- **Persona-aware** — one surface for the SOC (triage queue, attack chains, investigation), the CISO (security KPIs, top risks, break-glass), and the architect (privilege hygiene, permissions, governance).
- **Transparent risk scoring** — additive, reason-bearing scores for queue ordering, never an opaque "risk number." Every row shows *why* it scored.
- **Identity enrichment** — joins `IdentityInfo` to know whether an actor is privileged, high-value, or a guest, and cross-references `SigninLogs` / risk events and `SecurityAlert`.
- **Control-plane degradation detection** — parses Conditional Access old/new JSON into human-readable flags: *CA disabled*, *report-only*, *MFA control removed*, *user/location exclusion added*, *security defaults disabled*.
- **Multi-stage attack chains** — stitches auth-change → app/SP create → consent/permission → credential → privilege → control-change into a single per-actor sequence.
- **Break-glass monitor** — flags **any** action by emergency-access accounts, bypassing every other filter.
- **Permission risk catalogue** — separates delegated vs application permissions and rates each grant Low → Critical.
- **Tier-0 aware** — names the crown-jewel roles explicitly, including the often-forgotten **Hybrid Identity Administrator** and **Domain Name Administrator**.
- **Drift-resistant** — an operation-discovery page instead of assuming Microsoft's activity names, plus an enrichment-availability check so empty tiles are never mistaken for "no activity."
- **Portable** — the workspace is a parameter; import into any tenant with no edits.

---

## Tabs

| # | Tab | Primary audience | Answers |
|---|---|---|---|
| 1 | 📊 Overview | CISO | Posture, security KPIs, top risks, break-glass activity |
| 2 | 🚨 SOC Queue | SOC | What to investigate first (scored, reason-bearing queue) |
| 3 | 👑 Privilege & PIM | SOC / Architect | Role assignments, self-assignment, outside-PIM, SP-initiated |
| 4 | 🧩 Apps & SP | SOC / Architect | App/SP creation, credentials, consent, lifecycle paths |
| 5 | 🎟️ Permissions | Architect / SOC | Delegated vs application permissions, Low→Critical risk |
| 6 | 🔐 Auth & CA | CISO / SOC / Architect | CA & security-control degradation, federation, domain, tenant drift |
| 7 | 👥 Users & Groups | SOC / Architect | User lifecycle, SSPR vs admin resets, user→group→privilege |
| 8 | 🧭 Attack Paths | SOC / Hunter | Correlated multi-stage sequences (MITRE ATT&CK) |
| 9 | 🔎 Investigation | Investigator | Entity timeline, old/new values, correlation pivots |
| 10 | 📋 Governance | Architect / CISO | Privileged-identity, application, and control governance |
| 11 | 🎯 MITRE | Detection engineering | Technique-centric coverage + use-case → hunt/rule map |
| 12 | ⚙️ Readiness | Workbook owner | Data health, operation discovery, enrichment availability |

---

## Global parameters

Every tile shares one pill bar:

| Parameter | Purpose |
|---|---|
| Workspace | Target Log Analytics / Sentinel workspace (portable) |
| Time Range | Global window applied to every tile |
| Queue Priority | Minimum severity band for the SOC queue |
| Result | Keep only `success` or `failure` records |
| Category (Include) | Scope to `RoleManagement`, `ApplicationManagement`, `Policy`, … |
| Logged By Service (Include) | Scope to `Core Directory`, `PIM`, `Conditional Access`, … |
| Excluded Actors | Drop noisy sync / automation accounts from every tile |
| Actor / Target (global) | Free-text filter on actor or first target |
| Application / object (global) | Free-text filter on the first target display name |
| Actor IP (global) | Prefix match on the initiating actor IP |
| Break-glass accounts | Emergency-access UPNs for the Overview monitor |

---

## Data sources & prerequisites

`AuditLogs` is required; everything else enriches specific tiles and degrades gracefully (`union isfuzzy` + presence checks) when absent.

| Table | Required by | Notes |
|---|---|---|
| `AuditLogs` | All tabs | Primary control-plane source. Populated by the Microsoft Entra ID data connector. |
| `IdentityInfo` | Overview Top Risks, Governance | Actor privilege / risk / blast-radius enrichment (UEBA). |
| `SigninLogs` | Attack Paths | Risky sign-in → MFA-change correlation. |
| `AADUserRiskEvents` | Attack Paths | Identity Protection risk detections. |
| `SecurityAlert` | Readiness / correlation | "Already detected?" context. |
| `AADServicePrincipalSignInLogs`, `AADNonInteractiveUserSignInLogs`, `AADManagedIdentitySignInLogs`, `AADRiskyUsers`, `MicrosoftGraphActivityLogs`, `AzureActivity`, `AADProvisioningLogs` | Readiness availability | Optional deeper-investigation pivots. |

Minimum viable deployment: the **Microsoft Entra ID** connector streaming `AuditLogs`. Add `IdentityInfo` (UEBA) and `SigninLogs` to unlock the Top Risks, Governance, and Attack-Paths enrichment.

---

## Deploy / import

**Portal (fastest)**

1. In **Microsoft Sentinel → Workbooks** (or Azure Monitor → Workbooks), select **Add workbook → Edit → `</>` Advanced Editor**.
2. Paste the contents of `EntraID-AuditLogs-ControlPlane-Workbook.json` and **Apply**.
3. **Done Editing → Save**, name it *Entra ID AuditLogs — Identity Control-Plane*, and pick your resource group / workspace.
4. Select your **Workspace** and **Time Range**, and populate **Break-glass accounts** with your emergency-access UPNs.
5. Start on **⚙️ Readiness** to confirm `AuditLogs` and the enrichment tables are flowing, then work outward.

**Regenerate from source (optional)**

The workbook JSON is generated deterministically:

```powershell
pwsh -File .\Build-AuditLogsWorkbook.ps1
```

Edit `Build-AuditLogsWorkbook.ps1` (parameters, tiles, KQL, scoring) and re-run to rebuild `EntraID-AuditLogs-ControlPlane-Workbook.json`.

---

## Risk-scoring model (in the open)

Two tiles rank events; both are additive and display their reasons.

**SOC queue** (fast ordering):

```text
base:  Critical 40 | High 30 | Medium 15 | Informational 5
  +20  initiator is a service principal
severity: >=50 Critical | >=30 High | >=15 Medium | else Info
```

**CISO Top Risks** (context-rich, `IdentityInfo`-enriched):

```text
operation:  Critical op 40 | High op 30 | else 10
+30  target is a named privileged (Tier-0) role
+25  self-assignment (actor is among the targets)
+20  target is an external (#EXT#) identity
+20  initiator is a service principal
+15  actor is high-risk in IdentityInfo
+10  action occurred off-hours (UTC < 6 or > 20)
severity: >=90 Critical | >=60 High | >=30 Medium | else Info
```

No single factor is treated as proof. The value is the **ordering plus the visible reasons**.

---

## MITRE ATT&CK coverage

The **MITRE** tab maps identity control-plane techniques to their data source and a confidence rating, including:

- **T1098 / T1098.001 / T1098.003** — Account Manipulation (roles, credentials) — high, from `AuditLogs`
- **T1556.009** — Conditional Access policy modification — high
- **T1484.002** — Domain trust / federation modification — high
- **T1671** — Cloud application integration (OAuth) — high
- **T1136.003** — Create cloud account — high
- **T1110.003** — Password spraying — high (via `SigninLogs`)
- **T1528 / T1550.001 / T1606.002** — token theft / PRT / SAML — low, marked as requiring Sign-in / Defender XDR corroboration

---

## What this workbook does not claim

- It does not prove **token replay, AiTM, password spray, or credential theft** — those require `SigninLogs`, Identity Protection, or Defender XDR.
- It does not prove a change was **unauthorized** — that is a human judgment against your change process.
- It does not prove **effective permission usage** — that needs `MicrosoftGraphActivityLogs` or app-governance data.
- Risk scores are **triage aids**, not probabilities of compromise.
- Heuristics depend on **operation names** that can drift — the Readiness discovery tile is the guardrail.

---

## Repository layout

```text
EntraID-AuditLogs-ControlPlane/
├── EntraID-AuditLogs-ControlPlane-Workbook.json   # importable workbook (paste into Advanced Editor)
├── Build-AuditLogsWorkbook.ps1                     # deterministic generator for the JSON
├── EntraID-AuditLogs-ControlPlane-Substack.md      # in-depth, section-by-section article
├── README.md                                       # this file
└── media/                                           # screenshots (add your own)
```

> Screenshots: add `media/*.png` and reference them here to give visitors a preview of the Overview, SOC Queue, and Attack Paths tabs.

---

## Notes

- **Read-only.** The workbook only queries telemetry; it never modifies identities, roles, or configuration.
- **Graceful degradation.** `union isfuzzy=true` and presence checks keep tiles rendering on tenants missing an optional table.
- **Portable.** The workspace is a parameter; no per-tenant edits required.
- **Companion content.** See the in-depth write-up in `EntraID-AuditLogs-ControlPlane-Substack.md`.

---

## License

Provided as-is for defensive security use. Add your preferred license (for example, MIT) before publishing.
