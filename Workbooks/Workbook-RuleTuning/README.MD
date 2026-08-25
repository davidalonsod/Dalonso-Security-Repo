# 🛡️ Analytics Rule Tuning Workbook (Microsoft Sentinel)

Reduce noise with Sentinel Workbook Optimization Rules https://youtu.be/gCGjaFmPlEc

A single-pane Microsoft Sentinel **workbook** for **detection engineering**: find noisy
analytic rules, measure detection quality, reduce false positives, and **prove tuning
impact**. It turns `SecurityAlert` / `SecurityIncident` / `SentinelAudit` / `SentinelHealth`
into an actionable rule-tuning view with red/orange/green health signals.

- **File:** `Workbook-RuleTuning.json`
- **Layout:** single page · **7 sections** + SOC KPIs · **Query tiles:** 26 · **Parameters:** 3
- **Primary data sources:** `SecurityAlert`, `SecurityIncident` (+ `SentinelAudit`, `SentinelHealth`)
- **Type:** Azure Monitor / Microsoft Sentinel workbook (Gallery Template JSON)

---

## Why this workbook

Alert fatigue comes from a small number of noisy rules. This workbook ranks rules by
volume and **alert→incident conversion**, exposes false-positive rate and grouping
candidates, ties noise to the entities driving it, and records who changed what — so you
can tune with evidence and demonstrate the before/after impact to the SOC.

---

## Sections

| Section | What you get | Key signals |
|---|---|---|
| **SOC KPIs** | Headline numbers | Total alerts / incidents, avg noise %, active rules. |
| **1 · Rule health & noise** | Volume & conversion | Alerts/day with tuning hint, incidents per rule, alert→incident conversion, trend (alerts vs created vs closed), top 15 rules by volume, rules with no recent alerts. |
| **2 · False positives & grouping** | Detection quality | Noise ratio (with TP %), **FP rate (>30% flag)**, classification mix, alerts/incident (grouping candidates), MTTR P50/P90/P99, auto-closure %, hourly distribution. |
| **3 · Impacted entities** | Who/what drives noise | Top users / devices / IPs by alerts, entities triggering the selected rule (build exclusions), dynamic entity view. |
| **4 · Performance** | Execution health | Rules with failed/partial runs, slow KQL. |
| **5 · Fusion** | Correlation value | Fusion share, alerts by provider (Fusion vs scheduled vs others). |
| **6 · MITRE ATT&CK** | Coverage & gaps | Alerts by tactic, **zero-coverage tactics in red**. |
| **7 · Governance** | Change control | Who tuned/deployed which rule (`SentinelAudit`). |

---

## Key capabilities

- **Noise ranking** — alerts/day per rule with a tuning hint and top-volume leaderboard.
- **Detection-quality metrics** — alert→incident conversion, false-positive rate,
  classification mix, and TP %.
- **Alert-grouping guidance** — alerts-per-incident and cross-rule entity overlap to
  identify grouping / dedup candidates.
- **Response metrics** — triage and resolve times (P50/P90/P99) and approximate
  auto-closure rate.
- **Exclusion building** — pick a rule + entity type to list the exact entities to
  allowlist/exclude.
- **Execution health** — failed/partial rule runs and slow queries (`SentinelHealth`).
- **Fusion contribution** — how much value correlation adds vs scheduled rules.
- **MITRE coverage** — tactic coverage with **zero-coverage gaps highlighted**.
- **Governance** — an audit trail of rule tuning/deployment changes.

---

## Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `TimeRange` | Time picker | 30 days | Scopes every section. |
| `SelectedRule` | Dropdown | *(empty)* | Focus the entity/exclusion views on one rule. |
| `EntityType` | Dropdown | `account` | Pivot the impacted-entity and overlap views (account / host / IP, etc.). |

> **Tuning thresholds (adjust to your SOC):** target ~5 alerts/rule/day; flag rules
> >20/day for 3+ days; FP rate >30% over 14d = review; no alerts in 7d = validate data or
> lower threshold; higher alert→incident conversion is better (low % = noise).

---

## Data sources & prerequisites

| Table | Used by |
|---|---|
| `SecurityAlert` | Rule health/noise, FP/quality, entities, Fusion, MITRE (primary) |
| `SecurityIncident` | Conversion, classification mix, MTTR, auto-closure |
| `SentinelHealth` | Section 4 — failed/partial runs, slow KQL |
| `SentinelAudit` | Section 7 — rule change/governance trail |

**Prerequisites**
- Microsoft Sentinel enabled with analytic rules producing `SecurityAlert` /
  `SecurityIncident`.
- Enable **Sentinel health & audit** diagnostic logs so `SentinelHealth` and
  `SentinelAudit` are populated (Performance and Governance sections).

---

## Deploy / import

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `Workbook-RuleTuning.json` and **Apply**.
3. **Done Editing** → **Save**, name it *Analytics Rule Tuning*, and pick your resource
   group / workspace.
4. Set **Time range**, optionally pick a **Rule** and **Entity type**, then review
   sections top-to-bottom. Click a row → **Open in Logs** to drill down or export to CSV.

---

## Notes

- **Read-only.** The workbook surfaces tuning evidence; it doesn't modify rules. Apply
  changes in the analytics-rule editor, then use this workbook to prove the impact.
- **Colour legend:** red = needs action, orange = watch, green = healthy.
- **Graceful degradation.** Performance/Governance tiles render empty until
  `SentinelHealth` / `SentinelAudit` are enabled.
