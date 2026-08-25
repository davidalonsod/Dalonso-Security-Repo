# 🛡️ CISO Security Posture Workbook (CISO KPIs)

The Sentinel Dashboard Every CISO Needs: Workbook Deep Dive (20+ KPIs) https://youtu.be/UCmmu87giEE

A board-ready Microsoft Sentinel **workbook** that turns raw security telemetry into a
CISO-grade posture narrative: a single risk score, top cross-domain risks, incident
response performance, identity / data-and-AI / email health, detection coverage, and
MITRE ATT&CK effectiveness — answering *"What are my biggest risks, how are they
trending, and what should I fix next — in under 5 minutes?"*

- **File:** `CISO_KPIs_Workbook.json`
- **Tabs:** 8 · **Query tiles:** 136 · **Parameters:** 4
- **Audience:** CISO · SOC Manager · Security Steering Committee
- **Type:** Azure Monitor / Microsoft Sentinel workbook (Gallery Template JSON)

> This is a **security-program view**, not a SOC operational dashboard. Every numeric
> tile is reproducible — select a panel → **Edit** → read the KQL. No client-side
> aggregation; all math runs in Kusto against your Sentinel workspace. Tiles compare
> the **current period** vs the **prior period of equal length** (▲ worse / ▼ better).

---

## Tabs

| Tab | Question it answers | Highlights |
|---|---|---|
| **1 · Executive Posture** | *Are we at risk? Are we improving?* | Composite posture score, incident KPIs vs prior window, risky users, sign-in failure, detection coverage, backlog, alert→incident conversion, attack-stage "killer KPI", auto-generated attention-required bullets. |
| **2 · Top Risks & Impact** | *Where should I worry right now?* | Business-language risk scenarios derived from incident/alert MITRE tactics, repeat-vs-new risks, assets at risk, user-risk concentration, control effectiveness, top risk-reduction actions. |
| **3 · Threat & MTTR** | *What is actually happening?* | Severity & classification trends, daily incident volume, MTTA/MTTR/TTC percentiles, reopened incidents, backlog aging, automation efficiency, detection source, noisy-rule ranking. |
| **4 · Identity & Access** | *How exposed are identities?* | Sign-in failures, Identity Protection (atRisk / confirmedCompromised), privileged exposure, workload-identity (service principal) risk, persistence/ATO signals, geography, identity control effectiveness, identity risk posture score. |
| **5 · Data & AI Risk** | *Is sensitive data / AI usage under control?* | **3-source AI hybrid** (SaaS `CloudAppEvents` + federated `SigninLogs`/`AADNonInteractiveUserSignInLogs` + endpoint `DeviceNetworkEvents`): sanctioned vs federated vs shadow AI, AI by category (LLM / Code / Image / MCP-Agent / Search), newly-seen AI apps vs 90-day baseline, risky-user × AI overlap, DLP outcome split, repeat violators, AI-agent posture. |
| **6 · Coverage, Health & Cost** | *How blind are we? Is the spend justified?* | Critical hosts not reporting, analytic-rule health (`SentinelHealth`), detection coverage %, ingestion volumes & anomalies, tier-migration candidates, license-benefit reference. |
| **🎯 MITRE Coverage** | *Are we stopping attacks before damage?* | Effective tactic & technique coverage from fired alerts, early-vs-late detection, attack-stage funnel, silent-tactic gaps. Adapted from the Sentinel MITRE Coverage Report. |
| **✉️ Email & Collab** | *What reached users; are defenses working?* | Inbound mail flow & verdicts, phishing/malware, ZAP remediation, Safe Links clicks, repeat clickers, top campaigns, attachment/URL telemetry (Defender for Office 365). |

---

## Key capabilities

- **Single posture score + trend** — one defensible number, current vs prior window,
  with the component KPIs that build it.
- **Business-language risk framing** — translates incident MITRE tactics into
  scenarios leaders understand (not raw alert names).
- **IR performance** — MTTA / MTTR / TTC percentiles vs targets, backlog aging,
  reopened incidents, automation rate, FP-weighted noisy rules.
- **Identity risk program** — human + workload identity, Identity Protection states,
  privileged exposure, early-vs-late compromise staging.
- **Data & AI governance** — 3-source shadow-AI/MCP/agent visibility, DLP outcomes,
  and AI-agent posture context.
- **Coverage & cost** — silent hosts, rule health, ingestion by tier, value-vs-spend.
- **MITRE effectiveness** — tactic/technique coverage grounded in what actually fired.
- **Auto-derived action layer** — window-over-window deltas surface only items
  breaching CISO thresholds (e.g., high-sev spike ≥ 25%, backlog ≥ 7d, risky users > 0,
  coverage < 90%).

---

## Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `Workspace` | Workspace picker | *(current)* | `crossComponentResources` for every query. |
| `Window` | Time range (Lookback) | `30d` | Global lookback; every tile compares this vs the prior equal-length period. |
| `SeverityFilter` | Multi-select | `High, Medium, Low, Informational` | Severity scope for incidents and alerts. |
| `selectedTab` | Hidden | `exec` | Drives the tab navigation row. |

---

## Data sources & connectors

All KPIs derive from **first-party Microsoft security telemetry** in the Sentinel
workspace. Tiles use graceful patterns so a missing table renders empty, not an error.

| Connector / product | Tables | Tabs |
|---|---|---|
| **Microsoft Sentinel** | `SecurityIncident`, `SecurityAlert`, `SentinelHealth`, `Usage`, `Operation`, `LAQueryLogs`, `Heartbeat` | 1, 2, 3, 6, 🎯 |
| **Microsoft Entra ID** | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `AADUserRiskEvents`, `AADServicePrincipalSignInLogs`, `AuditLogs` | 1, 4, 5 |
| **Microsoft Defender XDR** | `AlertInfo`, `IdentityInfo`, `DeviceInfo`, `BehaviorAnalytics`, `CloudAppEvents`, `DeviceNetworkEvents` | 1, 5 |
| **Defender for Office 365** | `EmailEvents`, `EmailPostDeliveryEvents`, `UrlClickEvents`, `EmailAttachmentInfo`, `EmailUrlInfo` | ✉️ |
| **Office 365 / Exchange** | `OfficeActivity` | 5 |
| **Advanced Hunting only** | `DataSecurityEvents`, `AIAgentsInfo` (not workspace tables — noted inline where referenced) | 5 |
| **Custom (optional)** | `Signinlogs_Anomalies_KQL_CL` (hourly anomaly KQL job) | 4 |

---

## Deploy / import

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `CISO_KPIs_Workbook.json` and **Apply**.
3. **Done Editing** → **Save**, name it *CISO Security Posture*, and pick your resource
   group / workspace.
4. Set **Workspace**, **Window**, and **Severity**, then present from the tabs.

> A print-optimized variant (`CISO_KPIs_Workbook_PrintEdition.json`) is available in
> this folder for board decks / PDF export.

---

## How to read the tiles

- **Current vs prior period** — ▲ increases in volume/severity are *worse*; ▼ decreases
  in MTTR/backlog are *better*. Target reference lines appear where applicable
  (e.g., MTTR 4h, phishing-in-mailbox ≤ 0.5%).
- **Color codes** — 🔴 high risk · 🟠 medium · 🟡 low · 🟢 mitigating/sanctioned · 🔵 informational.
- **Empty tile?** The required table likely isn't ingested in this workspace — check the
  data-sources table above.

---

## Notes

- **Read-only.** The workbook only queries logs; it changes nothing.
- **Reproducible math.** All aggregation is KQL — edit any tile to see and adapt
  thresholds.
- **AI-agent posture** (`AIAgentsInfo`) and some data-security signals live in Defender
  **Advanced Hunting**; those tiles annotate the requirement inline.

