# 🔄 Entra ID Non-Interactive Sign-In Security Workbook (V2 — IP Exclusion + Named Locations)

The Security Blind Spot: Non-Interactive Sign-ins. Monitoring and Threat Hunting. https://youtu.be/tJAQ-_jMUX8

A Microsoft Sentinel **workbook** for monitoring **Microsoft Entra ID (Azure AD)
non-interactive sign-ins** — the background token-refresh and app-on-behalf-of-user
authentications in `AADNonInteractiveUserSignInLogs`. These flows are a prime signal for
**token replay, compromised refresh tokens, and malicious apps**. V2 adds a tile-wide
**exclusion layer** (IP allowlist + Named Locations) plus an **active remediation layer**
and a dedicated **AI Agents** monitoring tab.

- **File:** `NonInteractive-SignIn-Security-Workbook_V2_IPExcl_NameLoc.json`
- **Tabs:** 11 (+ remediation action buttons) · **Query tiles:** 129 · **Parameters:** 14
- **Primary data source:** `AADNonInteractiveUserSignInLogs` (+ `ThreatIntelIndicators`)
- **Type:** Azure Monitor / Microsoft Sentinel workbook (Gallery Template JSON)

> **What's new in V2 (IP Exclusion + Named Locations):** every tile honours a shared
> noise-reduction layer — `ExcludedIPs` free text, a `NetworkAllowlist` watchlist toggle
> (`WatchlistFilter`), and a **Named Locations** exclusion pill — so hunting scope matches
> the companion analytic rules.

---

## Why this workbook

Non-interactive sign-ins are high-volume, machine-driven, and easy to overlook — which is
exactly why attackers hide token replay and refresh-token abuse in them. This workbook
turns that stream into a security surface: posture scoring, app/user/geo analysis,
token-theft and botnet detection, failure/Conditional-Access analysis, a broad AI-agent
and shadow-AI view, and playbook-backed remediation.

---

## Tabs

| Tab | What it covers |
|---|---|
| 📈 **Executive Summary** | Non-interactive security score, KPIs, top critical findings, failure-rate trend, user-risk distribution, top high-risk IPs and apps-at-risk. |
| 📊 **Overview** | Total/success/failed sign-ins, unique users/apps, timeline, top resources, client-app types, activity heatmap, 7-day baseline deviation. |
| 📱 **Application Analysis** | Top apps by volume, app-to-resource access matrix, high-failure apps, first-party vs third-party, newly detected apps. |
| 👤 **User Analysis** | Top users by volume, **multi-country** and multi-app users, high-failure users, per-user timelines. |
| 🗺️ **Geolocation** | Trusted-vs-untrusted distribution/trend, sign-ins from untrusted locations, success/failure location maps, **new countries** (60-day baseline), impossible travel. |
| 🚨 **Security & Threats** | Suspicious IPs, password spray, **known malicious IPs (TI match)**, anonymous/VPN/proxy sign-ins, risky sign-ins, new IPs, **token-refresh anomalies**. |
| ❌ **Failure Analysis** | Error-code distribution & baseline comparison, failure timeline, top failing users/apps, Conditional Access blocks, MFA-related failures, account-status issues. |
| 🕸️ **Botnet Detection** | Token-theft via geographic impossibility, credential-stuffing IP analysis, time-clustered attacks, suspicious app behavior, attack-pattern timeline. |
| 🛠️ **Remediation** | Click-to-select high-risk users / apps / IPs, then trigger playbook actions; recent remediation log. |
| 🔍 **Forensic Investigation** | Guided pivots for user / IP / application / device — profile, token-activity timeline, distributions, event details. |
| 🤖 **AI Agents** | Copilot Studio & Azure AI Foundry agent activity, Entra agent identities & service principals, **Security Copilot** usage, **external AI** (ChatGPT/Gemini/Claude), **AI shadow IT**, and **agent sprawl** (abandoned/inactive agents, scope creep). |

---

## Key capabilities

- **Token-theft & replay detection** — geographic impossibility, refresh-token anomalies,
  credential stuffing, and time-clustered attack patterns.
- **App & user risk analysis** — app-to-resource matrix, first/third-party split,
  multi-country users, and high-failure concentration.
- **Geo & trusted-location validation** — untrusted-location activity, new-country
  detection, and impossible travel.
- **Threat-intel correlation** — non-interactive sign-ins from known-malicious IPs.
- **AI-agent visibility** — Copilot Studio / AI Foundry / Security Copilot activity,
  external-AI shadow IT, and agent-sprawl (abandoned agents, excessive resource access).
- **Failure & Conditional Access analysis** — error-code baselines, CA blocks, MFA
  failures, and account-status issues.
- **Active remediation (playbook-driven)** — user actions (Revoke Sessions, Reset
  Password, Disable Account, Reset MFA, Confirm Compromised, Full Remediation), app
  actions (Disable SP, Rotate Credentials, Revoke Permissions), and IP actions (Block IP,
  Enrich via Threat Intel), plus Open in Portal / Named Locations.

---

## Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `TimeRange` | Time picker | 7 days | Global time scope. |
| `BaselineDays` / `BaselineOffsetDays` | Text | `30` / `1` | Baseline window & offset for deviation / first-seen tiles. |
| `ExcludedIPs` | Text | *(empty)* | Comma-separated IP / CIDR / range to exclude. |
| `WatchlistFilter` | Dropdown | `\| where true` (Off) | **V2** — **On** appends `\| invoke ExcludeAllowlistedIPs()` (the `NetworkAllowlist` watchlist function shared with the analytic rules); **Off** is zero-cost. |
| `NamedLocations` | Multi-select | *(empty)* | **V2** — drop rows matching selected Entra Named Locations. |
| `RemediationSubscription` | Text | *(your sub id)* | Subscription hosting the remediation playbooks. |
| `PlaybookResourceGroup` | Text | `rg-sentinel-playbooks` | Resource group of the playbooks/actions. |
| `SelectedAppDisplay` | Hidden | — | Row-selected application for remediation/investigation. |
| `ForensicTimeRange` | Time picker | 7 days | Investigation-period scope. |
| `UserSearchFilter` / `IPSearchFilter` / `AppSearchFilter` / `DeviceSearchFilter` | Text | *(empty)* | Forensic pivot search fields. |

**Exclusion order (applied to every tile):** `ExcludedIPs → WatchlistFilter
(NetworkAllowlist) → NamedLocations`.

---

## Data sources & prerequisites

| Source | Used by |
|---|---|
| `AADNonInteractiveUserSignInLogs` (Entra ID diagnostic settings → Log Analytics) | Every tab (primary) |
| `ThreatIntelIndicators` | 🚨 Security & Threats → known-malicious-IP match |
| Conditional Access fields on the sign-in table | ❌ Failure Analysis (CA blocks) |
| App-name patterns (Copilot Studio / AI Foundry / Security Copilot / ChatGPT / Gemini / Claude) | 🤖 AI Agents |
| Watchlist `NetworkAllowlist` + `ExcludeAllowlistedIPs()` | Optional — only when `WatchlistFilter = On` |

**Prerequisites**
- Route Entra ID **NonInteractiveUserSignInLogs** to the Sentinel workspace via
  diagnostic settings (this stream is separate from interactive `SigninLogs`).
- *(Optional)* Enable a threat-intelligence connector for the TI-match tiles.
- **For the Remediation tab:** deploy the corresponding Sentinel playbooks into
  `PlaybookResourceGroup`, set `RemediationSubscription`, and grant rights to trigger them.
- *(Optional)* Populate the `NetworkAllowlist` watchlist to use `WatchlistFilter = On`.

---

## Deploy / import

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `NonInteractive-SignIn-Security-Workbook_V2_IPExcl_NameLoc.json` and **Apply**.
3. **Done Editing** → **Save**, name it *Non-Interactive Sign-In Security*, and pick your
   resource group / workspace.
4. Set **Time Range** and **Baseline**, apply the V2 exclusion pills (**Excluded IPs**,
   **NetworkAllowlist**, **Named Locations**), and (for remediation) set the
   **Subscription** + **Playbook Resource Group**, then work the tabs.
5. *(Optional)* Set **NetworkAllowlist = On** (with the watchlist populated) to align the
   workbook 1:1 with the deployed analytic rules.

---

## Notes

- ⚠️ **The Remediation tab performs real actions.** Revoke/reset/disable/block buttons
  trigger playbooks that change identity or network state. Confirm the selected entity and
  scope before invoking, and restrict who can run them.
- **Read-only elsewhere.** All non-remediation tabs only query logs.
- **Graceful degradation.** TI, CA, and AI-agent tiles render empty (not error) when the
  relevant data isn't present.
