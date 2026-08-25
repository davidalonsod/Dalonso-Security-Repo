# 🔐 Workload Identity Security & Threat Investigation Workbook (V2 — IP Exclusion + Named Locations)

Stop Compromised Apps: How to Detect Compromised non-Human Identities with Microsoft Sentinel https://youtu.be/LW-rTQUovHo

A Microsoft Sentinel **workbook** for security monitoring of **non-human / application
identities** — OAuth apps, Service Principals, Managed Identities, and AI agents. It
focuses on application-identity threat detection (consent abuse, credential theft,
botnet patterns, impossible travel) and ships an **active remediation layer** that
triggers Sentinel playbooks / Azure actions directly from the workbook.

- **File:** `WI-Identity-Security-Workbook_V2_IPExclusion_NameLocations.json`
- **Tabs:** 11 (+ remediation action buttons) · **Query tiles:** 123 · **Parameters:** 20
- **Primary data sources:** `AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`, `AuditLogs`, `CloudAppEvents` (+ `SigninLogs` for cross-reference)
- **Type:** Azure Monitor / Microsoft Sentinel workbook (Gallery Template JSON)

> **What's new in V2 (IP Exclusion + Named Locations):** adds a tunable noise-reduction
> layer shared by every tile — a `NetworkAllowlist` watchlist toggle (`WatchlistFilter`)
> plus **Named Locations** and **Trusted Devices** exclusion pills, on top of the
> existing `ExcludedIPs` free-text filter. This aligns the workbook's scope with the
> companion analytic rules so what you hunt matches what alerts.

---

## Why this workbook

Non-human identities now outnumber users and are a prime attack surface: illicit OAuth
consent, over-privileged Graph permissions, leaked/rotated app credentials, and
service-principal abuse. This workbook gives a dedicated **app-identity** view —
posture scoring, governance, per-identity monitoring, botnet detection, threat
investigation, geolocation, forensics — and lets analysts **remediate in place** via
playbook-backed action buttons.

---

## Tabs

| Tab | What it covers |
|---|---|
| 📈 **Executive Summary** | Non-human identity posture: identity security score, KPIs, top critical findings, auth-failure trend, SP risk distribution, week-over-week, top active/at-risk SPs and high-risk IPs. |
| 📊 **Overview** | App-identity metrics, SP & MI activity timeline and sign-in status, top operations, most-active/most-failing identities, recent OAuth consent, 7-day baseline deviation. |
| 🔑 **OAuth & App Governance** | Consent activity, **high-risk permissions granted**, suspicious OAuth behavior, new app registrations, unused SPs (90+ days), multi-tenant apps with external sign-ins, Graph API permission analysis, **expiring app credentials**. |
| ⚙️ **Service Principals** | SP sign-in activity, credential changes, sensitive-resource access, sign-in from new IPs, SP↔user relationships & owners, non-interactive sign-in analysis, auth methods, top resources. |
| 🤖 **Managed Identities** | MI sign-in activity & failures, resources accessed, **accessing new resources**, by category, cross-resource access, non-interactive summary, high-volume activity. |
| 🕸️ **Botnet Detection** | Multiple SPs from same IP, time-clustered auth spikes, geographic impossibility, MI botnet detection, IP threat scoring. |
| 🚨 **Threat Investigation** | Non-human identity posture, **MITRE ATT&CK TTPs**, suspicious SP IP activity, **illicit consent-grant attacks**, OAuth apps with suspicious mail activity, SP impossible travel, Conditional Access insights (blocks, SPs with no CA). |
| 🛠️ **Remediation Actions** | Click-to-select high-risk users / SPs / IPs, then trigger playbook actions; recent remediation-action log. |
| 🗺️ **Geolocation** | Global activity map, **trusted-location validation**, trusted-vs-untrusted summary/trend, country activity with trust status. |
| 🔍 **Forensic Investigation** | Guided pivots for user / IP / service principal / managed identity / device — profile, activity timeline, resource/geo distribution, event details. |
| 🧩 **Baseline & Exclusions** | `NetworkAllowlist` trusted IPs, allowlist composition, SP country baseline (per `BaselineDays`/offset), exclusion-impact preview — **V2** also drives the Named Locations & Trusted Devices exclusion pills. |

---

## Key capabilities

- **App-identity posture & scoring** — a single identity security score plus KPIs and
  top critical findings for leadership.
- **OAuth governance** — high-risk permission grants, illicit-consent detection,
  multi-tenant exposure, Graph permission analysis, and expiring-credential tracking.
- **Service principal & managed identity monitoring** — sign-in status/failures,
  credential changes, sensitive/new-resource access, and non-interactive analysis.
- **Botnet & anomaly detection** — same-IP SP clustering, time-clustered spikes,
  geographic impossibility, and IP threat scoring.
- **Threat investigation** — MITRE ATT&CK mapping, impossible travel, suspicious mail
  activity, and Conditional Access coverage gaps.
- **Active remediation (playbook-driven)** — Disable / Rotate Credentials / Revoke
  Permissions / Block in Conditional Access for service principals, plus user actions
  (Disable, Force Password Reset, Revoke Sessions, Block Sign-In, Confirm Compromised,
  Full Remediation), Add to Threat Intelligence, and Open in Portal.
- **Geolocation & forensics** — trusted-location validation and multi-entity pivot
  investigation.

---

## Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `TimeRange` | Time picker | 7 days | Global time scope. |
| `UserFilter` | Text | `*` | UPN filter for cross-reference tiles. |
| `BaselineDays` / `BaselineOffsetDays` | Text | `14` / `1` | Baseline window & offset for deviation/first-seen tiles. |
| `ExcludedIPs` | Text | *(empty)* | Comma-separated IP / CIDR / range to exclude. |
| `WatchlistFilter` | Dropdown | `\| where true` (Off) | **V2** — **On** appends `\| invoke ExcludeAllowlistedIPs()` (the `NetworkAllowlist` watchlist function shared with the analytic rules); **Off** is zero-cost. |
| `NamedLocations` | Multi-select | *(empty)* | **V2** — drop rows matching selected Entra Named Locations. |
| `TrustedDevices` | Multi-select | *(empty)* | **V2** — drop rows from selected trusted / compliant devices. |
| `TrustedIPRanges` | Text | RFC1918 + Azure CIDRs | Trusted networks for location validation. |
| `TrustedCountries` | Text | US, CA, UK, DE, FR, NL, AU | Trusted countries for geo trust status. |
| `RemediationSubscription` | Subscription | — | Subscription hosting the remediation playbooks. |
| `PlaybookResourceGroup` | Text | `rg-sentinel-playbooks` | Resource group of the playbooks/actions. |
| `SelectedSPDisplay` / `SelectedSPId` | Hidden | — | Row-selected service principal for remediation. |
| `ForensicTimeRange` | Time picker | 7 days | Investigation-period scope. |
| `UserSearchFilter` / `IPSearchFilter` / `SPSearchFilter` / `MISearchFilter` / `DeviceSearchFilter` | Text | *(empty)* | Forensic pivot search fields. |

---

## Data sources & prerequisites

| Table | Purpose | Collection |
|---|---|---|
| `AADServicePrincipalSignInLogs` | Service principal auth events | Entra ID diagnostic settings → Log Analytics |
| `AADManagedIdentitySignInLogs` | Managed identity auth events | Entra ID diagnostic settings → Log Analytics |
| `AuditLogs` | App registrations, consents, role assignments, credential changes | Entra ID diagnostic settings → Log Analytics |
| `CloudAppEvents` | M365 cloud-app activity (mail/file access) for OAuth abuse | Defender for Cloud Apps → Sentinel connector |
| `SigninLogs` | User sign-in cross-reference | Entra ID diagnostic settings → Log Analytics |

**Prerequisites**
- Enable Entra ID diagnostic settings for ServicePrincipal / ManagedIdentity sign-ins
  and AuditLogs, routed to the Sentinel workspace (allow 15–30 min, up to 24–48 h for
  full population).
- Enable the Microsoft 365 Defender connector for `CloudAppEvents`.
- **For the Remediation tab:** deploy the corresponding Sentinel playbooks into
  `PlaybookResourceGroup` and grant the workbook user rights to trigger them.

---

## Deploy / import

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `WI-Identity-Security-Workbook_V2_IPExclusion_NameLocations.json` and **Apply**.
3. **Done Editing** → **Save**, name it *App Identity Security & Threat Investigation*,
   and pick your resource group / workspace.
4. Set **Time Range**, **Trusted IP Ranges/Countries**, the V2 exclusion pills
   (**Excluded IPs**, **NetworkAllowlist**, **Named Locations**, **Trusted Devices**),
   and (for remediation) the **Subscription** + **Playbook Resource Group**, then work
   the tabs.
5. *(Optional)* Populate the `NetworkAllowlist` watchlist and set **NetworkAllowlist =
   On** so the allowlist/exclusion tiles resolve real values and match the analytic
   rules.

---

## Notes

- **Exclusion model (V2).** Every tile honours the shared exclusion layer — `ExcludedIPs`
  → `WatchlistFilter` (NetworkAllowlist) → `NamedLocations` → `TrustedDevices` — so
  hunting scope matches the companion analytic rules. Use the **Baseline & Exclusions**
  tab's exclusion-impact preview to confirm you are not hiding real signal.
- ⚠️ **The Remediation tab performs real actions.** Disable/rotate/revoke/block buttons
  trigger playbooks that change identity state. Confirm the selected identity and scope
  before invoking, and restrict who can run them.
- **Read-only elsewhere.** All non-remediation tabs only query logs.
- **Graceful degradation.** Tiles render empty (not error) when a source table isn't
  onboarded; use the verification queries in the workbook's prerequisites section to
  confirm ingestion.
