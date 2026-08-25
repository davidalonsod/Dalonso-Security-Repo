# 🔥 Firewall Monitoring Workbook (CommonSecurityLog / CEF SOC)

Are Your Firewall Logs Too Noisy? Stop Attacks with Sentinel https://youtu.be/_q_tG7GscZA

A vendor-neutral Microsoft Sentinel **workbook** for monitoring **CEF firewalls in the
`CommonSecurityLog` table** — Fortinet, Palo Alto, Check Point, Cisco, and others. It
answers three operational questions across the perimeter: **what is happening on the
firewall, is it enforcing policy correctly, and is anything bypassing or abusing that
control?** — spanning traffic & flows, NGFW security services, policy, NAT/exposure,
health/HA, hunting, and entity behavior.

- **File:** `Firewall-CommonSecurityLog-SOC-Workbook.json`
- **Tabs:** 12 · **Query tiles:** 73 · **Parameters:** 12
- **Primary data source:** `CommonSecurityLog` (CEF)
- **Type:** Azure Monitor / Microsoft Sentinel workbook (Gallery Template JSON)

---

## Why this workbook

Firewall telemetry is high-volume and vendor-specific. This workbook normalizes it into
a SOC-ready surface: operational KPIs, North-South vs East-West flow analysis, NGFW
security-service outcomes (IPS/IDS, anti-malware, URL/web filtering, app control),
public-exposure/NAT mapping, policy-abuse detection, firewall health/HA, a hunting pack,
and a UEBA behavior layer — all written to be **schema-safe and vendor-neutral** so
tiles don't break when a connector omits a field.

---

## Tabs

| Tab | Capability | Key questions |
|---|---|---|
| 📊 **01 SOC Overview** | Sessions, allowed/denied, traffic GB, IPS/IDS, malware, TI hits, critical/high, firewalls reporting/silent | Is the perimeter healthy and where do I focus first? |
| 🔁 **02 Traffic & Flows** | Event & byte trends, **North-South vs East-West**, top flows with bytes, East-West spread | What is communicating, how much, is there lateral movement? |
| 🛡️ **03 Threats & Security Services** | Denies/scanning + **IPS/IDS, anti-malware, URL/web filtering, application control** | Is anything malicious, and what did the NGFW catch? |
| 🎯 **04 Sources / Targets** | Top external sources, targeted assets, **geolocation map**, **country heatmap**, concentration | Who is attacking, which assets are targeted, where is risk concentrated? |
| 🔄 **05 NAT & Public Exposure** | **Publicly exposed internal assets (DNAT)**, risky exposed RDP/SSH/SMB, source NAT, translation detail | Which internal host is behind a public IP, and what is exposed? |
| 🔐 **06 VPN & Remote Access** | VPN trend, auth failures by source, VPN source-country concentration | Is remote access being brute-forced or abused from risky geos? |
| 🧩 **07 Applications / Protocols** | Application mix, high-risk named ports, protocol & port mix per firewall | Which apps/ports/protocols dominate, and which are risky? |
| 📋 **08 Firewall Policy** | Top rules by sessions/bytes, **risky inbound allows**, overly permissive outbound, **new rules vs baseline** | Are rules risky, overly broad, or newly/covertly added? |
| 🏥 **09 Firewall Health** | Inventory & reporting status, **silent firewalls**, event-rate anomalies, vendor/version, **admin/config activity**, failed admin logins | Are firewalls healthy/HA, and is the management plane being abused? |
| 🔬 **10 Investigation** | IP pivot + detailed schema-safe event stream | What exactly did a suspicious IP do? |
| 🧭 **11 Threat Hunting** | Watchlist allowlist, beaconing, exfiltration, port/host scan, lateral movement, high-risk country, new external destinations, protocol anomaly, VPN brute force, TI IP correlation | Hunter-driven validation of suspicious activity. |
| 🧠 **12 UEBA / Behavior** | `SentinelBehaviorInfo` / `SentinelBehaviorEntities` + `BehaviorAnalytics`: behavior timeline, MITRE categories/techniques, anomaly-enriched & rare behaviors, entity-linked summary | What entity behaviors relate to perimeter IPs, users, and hosts? |

---

## Key capabilities

- **Operational + security in one view** — KPIs, flow/byte trends, and NGFW
  security-service outcomes side by side.
- **Exposure & NAT mapping** — resolve public IP → internal host (DNAT), flag exposed
  RDP/SSH/SMB, and map outbound source NAT.
- **Policy abuse detection** — risky internet-to-sensitive-port allows, overly
  permissive outbound, and new rules vs a 7-day baseline.
- **Threat hunting pack** — beaconing, >500 MB exfiltration, port/host scanning,
  internal lateral movement, DoH/Tor/miner egress, first-seen external destinations,
  protocol anomalies, VPN brute force, and threat-intel IP correlation.
- **UEBA behavior layer** — perimeter entities correlated with Sentinel behaviors and
  classical UEBA network anomalies.
- **Firewall health/HA** — silent-firewall detection, event-rate flood/drop anomalies,
  and management-plane (admin/config, failed logins) monitoring.

---

## Cross-cutting design

- 🎛️ **Persistent filters** — Workspace, Time Range, Vendor, Firewall, Source/Destination
  IP, Action, Severity, Protocol, Application, Country, and Investigation IP propagate to
  every tile.
- 🌍 **Geolocation without geo columns** — country is resolved at query time with
  `geo_info_from_ip_address()` (CEF has no `SourceCountry`/`DestinationCountry`).
- 🧱 **Vendor-neutral & schema-safe KQL** — optional fields (`Severity`/`LogSeverity`,
  `DeviceAction`, `Protocol`, `SentBytes`, NAT and rule fields) are guarded with
  `column_ifexists()`, so tiles never fail when a connector omits a field.
- 📋 **Watchlist integration** — allowlisting via `_GetWatchlist('NetworkAllowlist')`.

---

## Parameters

| Parameter | Type | Purpose |
|---|---|---|
| `Workspace` | Resource picker | Target Log Analytics / Sentinel workspace. |
| `TimeRange` | Time picker | Global time scope. |
| `Vendor` | Multi-select | Filter by `DeviceVendor`. |
| `Firewall` | Multi-select | Filter by device / `DeviceName`. |
| `SourceIP` / `DestinationIP` | Multi-select | Scope by source / destination IP. |
| `Action` | Multi-select | Filter by `DeviceAction`. |
| `Severity` | Multi-select | Filter by `LogSeverity` / `Severity`. |
| `Protocol` | Multi-select | Filter by protocol. |
| `Application` | Multi-select | Filter by application. |
| `Country` | Multi-select | Filter by geo-resolved country. |
| `InvestigationIP` | Multi-select | Drives the 🔬 Investigation drill-down. |

---

## Data sources & prerequisites



| Source | Used by |
|---|---|
| `CommonSecurityLog` (CEF via AMA / Sentinel CEF connector) | Every tab (primary) |
| `ThreatIntelIndicators` | 🧭 Threat Hunting → TI IP correlation |
| `SentinelBehaviorInfo` / `SentinelBehaviorEntities` / `BehaviorAnalytics` | 🧠 UEBA / Behavior |
| Watchlist `NetworkAllowlist` | 🧭 Threat Hunting allowlisting (`_GetWatchlist`) |

> Some tiles (NAT, bytes, rule names, admin activity) depend on the vendor populating
> the relevant CEF fields (`SourceTranslatedAddress` / `DestinationTranslatedAddress`,
> `SentBytes` / `ReceivedBytes`, `DeviceCustomString1`, `Activity` / `Message`). **Empty
> tiles usually mean those fields aren't being sent** for the selected devices, not a
> query error — Fortinet/Palo Alto-specific fields are enrichment, not a hard dependency.

---

## Deploy / import

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `Firewall-CommonSecurityLog-SOC-Workbook.json` and **Apply**.
3. **Done Editing** → **Save**, name it *Firewall Monitoring (CommonSecurityLog)*, and
   pick your resource group / workspace.
4. Select **Workspace** and **Time Range**, then use the Vendor / Firewall / IP filters
   to focus. Use **Investigation IP** on the 🔬 Investigation tab for pivots.
5. *(Optional)* Populate the `NetworkAllowlist` watchlist so the hunting allowlist tiles
   resolve real values.

---

## Notes

- **Read-only.** The workbook only queries logs; it changes no firewall configuration.
- **Companion content.** This folder also ships analytic rules and hunting queries for
  `CommonSecurityLog` (see `Analytic-Rules/`, `Firewall/`, and the folder `README.md`).
- **UEBA table names.** Workbook tiles query the workspace-ingested
  `SentinelBehaviorInfo` / `SentinelBehaviorEntities` (not the Defender-portal
  `BehaviorInfo` / `BehaviorEntities` Advanced Hunting names).
