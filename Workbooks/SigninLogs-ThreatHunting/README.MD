# 🎯 SigninLogs Threat Hunting Workbook (V2 — IP Exclusion + Named Locations)

Behind SignInLogs: Detect Password Spray, Brute Force, Botnets and Much More https://youtu.be/cXwK2Rvrs3w

A Microsoft Sentinel **workbook** for advanced threat hunting and anomaly detection over
**Microsoft Entra ID (Azure AD) sign-in activity** in the `SigninLogs` table — brute
force, password spray, impossible travel, risky sign-ins, MFA gaps, and behavioral
botnet detection. This V2 adds a tunable, tile-wide **exclusion layer** (IP allowlist,
Named Locations, Trusted Devices) so hunting scope matches the companion analytic rules.

- **File:** `SigninLogs-ThreatHunting-Workbook_V2_IPExclusion_NameLocation_.json`
- **Tabs:** 8 · **Query tiles:** 61 · **Parameters:** 10
- **Primary data source:** `SigninLogs` (+ Identity Protection risk, `ThreatIntelIndicators`)
- **Type:** Azure Monitor / Microsoft Sentinel workbook (Gallery Template JSON)

> **What's new in V2 (IP Exclusion + Named Locations):** every tile honours a shared
> noise-reduction layer — `ExcludedIPs` free text, a `NetworkAllowlist` watchlist toggle
> (`WatchlistFilter`), plus **Named Locations**, **Trusted Devices**, and **Apps**
> exclusion pills — so what you hunt is exactly what the analytic rules alert on.

---

## Why this workbook

Sign-in telemetry is the frontline for identity attacks. This workbook turns
`SigninLogs` into a focused hunting surface: credential-attack detection, geographic and
temporal anomalies, Identity Protection correlation, MFA/Conditional Access posture, and
behavioral botnet patterns — all baseline-aware and filtered through the V2 exclusion
model so high-volume trusted activity doesn't drown the signal.

---

## Tabs

| Tab | What it covers |
|---|---|
| 📊 **Overview** | Security-metrics summary, sign-in activity trend, top failure reasons, sign-ins by country, and 7-day baseline deviation (current vs previous). |
| 🔴 **Brute Force** | Users under brute-force attack, **success-after-failure** potential compromises, top attacking source IPs, failed-login timeline. |
| 🟠 **Password Spray** | Spray sources (IPs targeting many users) and users targeted by spray. |
| 🌍 **Geolocation** | Impossible travel, high-risk countries (>50% failure), multi-country users, activity & attack-origin maps, **trusted-vs-untrusted location** analysis. |
| 🔍 **Anomalies** | Off-hours/weekend activity, **legacy authentication**, new devices (first seen), suspicious user agents, users accessing new applications. |
| ⚠️ **Risk Analysis** | Identity Protection risk summary, high-risk users, risk events by type, risk-level trend, Conditional Access blocks, top risky users/IPs, top risk detections, and **threat-intel IP correlation** (`ThreatIntelIndicators`). |
| 🔐 **MFA Analysis** | MFA usage summary, users without MFA, MFA failure reasons & methods, apps without MFA enforcement, auth-method distribution, **password-only users**, CA policy results/blocks, and per-app MFA prompt/enforcement rates. |
| 🕸️ **Botnet Detection** | Behavioral: users targeted by distributed sources, shared user-agent across many IPs, coordinated low-and-slow brute force, automated/headless user-agents, botnet timeline. |

---

## Key capabilities

- **Credential-attack detection** — brute force (with success-after-failure compromise
  signal), single-IP and distributed password spray, and low-and-slow coordination.
- **Geographic & temporal anomalies** — impossible travel, high-risk countries,
  off-hours/weekend activity, and trusted-vs-untrusted location validation.
- **Identity Protection correlation** — risky users/IPs, risk detections, risk-level
  trend, and Conditional Access blocks.
- **Threat-intel correlation** — sign-ins from known-malicious IPs and users targeted by
  TI-flagged infrastructure.
- **MFA & Conditional Access posture** — MFA gaps, password-only users, apps without MFA,
  and per-app enforcement rates.
- **Behavioral botnet detection** — shared user-agents, headless/automated clients, and
  distributed-source clustering.
- **Baseline-aware** — 7-day deviation and first-seen device/app detection.

---

## Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `Workspace` | Resource picker | — | Target Log Analytics / Sentinel workspace. |
| `TimeRange` | Time picker | — | Global time scope. |
| `FailureThreshold` | Text | `10` | Failure count threshold for brute-force / spray tiles. |
| `BaselineDays` / `BaselineOffsetDays` | Text | `30` / `1` | Baseline window & offset for deviation / first-seen tiles. |
| `ExcludedIPs` | Text | *(empty)* | Comma-separated IP / CIDR / range to exclude. |
| `WatchlistFilter` | Dropdown | `\| where true` (Off) | **V2** — **On** appends `\| invoke ExcludeAllowlistedIPs()` (the `NetworkAllowlist` watchlist function shared with the analytic rules); **Off** is zero-cost. |
| `NamedLocations` | Multi-select | *(empty)* | **V2** — drop rows matching selected Entra Named Locations. |
| `TrustedDevices` | Multi-select | *(empty)* | **V2** — drop rows from selected trusted / compliant devices. |
| `Apps` | Multi-select | *(empty)* | Drop rows by `AppDisplayName`. |

**Exclusion order (applied to every tile):** `ExcludedIPs → WatchlistFilter
(NetworkAllowlist) → NamedLocations → TrustedDevices → Apps`.

---

## Data sources & prerequisites

| Source | Used by |
|---|---|
| `SigninLogs` (Entra ID diagnostic settings → Log Analytics) | Every tab (primary) |
| Identity Protection risk (risky users / sign-ins / detections) | ⚠️ Risk Analysis |
| `ThreatIntelIndicators` | ⚠️ Risk Analysis → TI IP correlation |
| Conditional Access fields on `SigninLogs` | 🔐 MFA Analysis (CA results/blocks) |
| Watchlist `NetworkAllowlist` + `ExcludeAllowlistedIPs()` | Optional — only when `WatchlistFilter = On` |

**Prerequisites**
- Route Entra ID **SigninLogs** (and, for the risk tiles, Identity Protection) to the
  Sentinel workspace via diagnostic settings.
- *(Optional)* Enable a threat-intelligence connector so `ThreatIntelIndicators` is
  populated for the TI-correlation tiles.
- *(Optional)* Deploy/populate the `NetworkAllowlist` watchlist + `ExcludeAllowlistedIPs()`
  function to use `WatchlistFilter = On`.

---

## Deploy / import

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `SigninLogs-ThreatHunting-Workbook_V2_IPExclusion_NameLocation_.json` and **Apply**.
3. **Done Editing** → **Save**, name it *SigninLogs Threat Hunting*, and pick your
   resource group / workspace.
4. Set **Workspace** and **Time Range**, tune **Failure Threshold** and **Baseline**,
   then apply the V2 exclusion pills (**Excluded IPs**, **NetworkAllowlist**, **Named
   Locations**, **Trusted Devices**, **Apps**) to reduce noise.
5. *(Optional)* Set **NetworkAllowlist = On** (with the watchlist populated) to align the
   workbook 1:1 with the deployed analytic rules.

---

## Notes

- **Read-only hunting.** The workbook only queries logs; it changes nothing.
- **Match the rules.** Enabling `NetworkAllowlist` makes the workbook's scope identical
  to the companion analytic rules in this repo's `Analytic-Rules/`.
- **Graceful degradation.** Risk / TI tiles render empty (not error) when Identity
  Protection or `ThreatIntelIndicators` isn't onboarded.
