# 🛡️ Windows DNS — Threat Hunting, Health & Cost Workbook (V2 — IP Exclusion)

Stop DNS Attacks:  Hunting Threats, Advanced Monitoring and Filtering Logs https://youtu.be/XNf1iu3W-C8

An end-to-end Microsoft Sentinel **workbook** for **Windows DNS** visibility — from
executive KPIs to analyst pivots. It hunts DNS-based threats (DGA, tunneling/exfil,
beaconing, fast flux), tracks telemetry health and ingestion **cost**, and correlates
with threat intelligence. Built on the ASIM DNS schema, with tunable detection thresholds
and a V2 IP-exclusion layer so hunting scope matches the companion analytic rules.

- **File:** `WindowsDNS-ThreatHunting-Workbook_V2_IPExclusion.workbook`
- **Tabs:** 10 · **Query tiles:** 66 · **Parameters:** 17
- **Primary data source:** `ASimDnsActivityLogs` (ASIM DNS via AMA)
- **Also uses:** `DnsAuditEvents`, `ThreatIntelIndicators`, `SecurityAlert`, `SecurityIncident` (+ `DeviceNetworkEvents`, `CommonSecurityLog` for URL impact)
- **Type:** Azure Monitor / Microsoft Sentinel workbook

> **V2 (IP Exclusion):** every tile honours `ExcludedIPs` (client `SrcIpAddr` / CIDR /
> range) plus a `NetworkAllowlist` toggle that drops IPs allow-listed by the shared
> `ExcludeAllowlistedIPs_AzureCustom()` function — the same one the analytic rules use.

---

## Why this workbook

DNS is both a top exfiltration/C2 channel and a major ingestion-cost driver. This workbook
unifies **threat hunting**, **telemetry health**, and **cost control** in one place: find
malicious patterns with tunable thresholds, verify your DNS pipeline is healthy and
normalized, quantify (and reduce) noisy PTR/query cost, and pivot straight to the affected
device.

---

## Tabs

| Tab | Capabilities |
|---|---|
| 📊 **Overview** | Executive summary + consolidated security findings; total queries, unique clients/domains, DNS servers, NXDOMAIN, TXT/NULL; volume trend, response-code mix, top servers, **day×hour heatmap**, top TLDs, per-/24 subnet. |
| 📡 **Telemetry Health** | Ingestion KPIs (events/hour, sources, GB), **silent/stale source detection**, ingestion trend, ASIM parsing/normalization health. |
| 📈 **Noisy Traffic** | Top talkers & domains, query-type mix, PTR/reverse noise, **cost estimate** (GB/day, PTR share, projected savings, top domains by GB). |
| 🧭 **Behavioral** | Record-type monitoring (TXT/NULL/ANY), query-length analytics (avg/median/P95/P99 + histogram), internal vs external, newly-active clients, **client baseline spike**, **query-volume anomaly** (spikes & drops). |
| 🚨 **Suspicious & Malicious** | Malicious summary by client/server, NXDOMAIN, long-query & subdomain tunneling, TXT abuse, DGA (digit-ratio), **Shannon entropy**, risky TLDs, zone transfers (AXFR/IXFR), newly-observed & rare domains, **beaconing**, **dynamic DNS**, **fast flux**, domain drill-down. |
| 🌍 **Geolocation** | Country choropleth (green→red by % malicious), malicious-city bubble map, top source-geo table. |
| 🎯 **Threat Intelligence** | IOC **domain** hits, IOC **IP** hits, infected devices, TI indicator lookup, actor-attributed IOCs, top malicious URLs seen in proxy/firewall & on endpoints. |
| 🔔 **Alerts & Incidents** | DNS-related `SecurityAlert` + open `SecurityIncident`, searchable by IP/domain; alerts by severity. |
| 🔎 **Investigation** | One-click **device pivot**: DNS profile, recent queries, and TI hits for a client IP. |
| 🗺️ **ATT&CK Coverage** | DNS analytics mapped to MITRE ATT&CK + detections currently firing. |

---

## Key capabilities

- **DNS threat hunting** — DGA and high-entropy domains, tunneling/exfil (long queries,
  excessive subdomains, TXT/NULL/CNAME abuse), beaconing, dynamic DNS, fast flux, zone
  transfers, NXDOMAIN bursts, suspicious TLDs, and newly-observed/rare domains.
- **Tunable detection** — threshold pills (NXDOMAIN, subdomain, query-length, TXT/NULL,
  DGA digit-ratio, entropy) tune each detection without editing KQL.
- **Telemetry health** — silent/stale source detection and ASIM parsing/normalization
  health so you trust the data.
- **Cost control** — ingestion GB estimates, PTR/noise share, and projected savings driven
  by the `PricePerGB` pill.
- **Threat-intel correlation** — domain and IP IOC hits, infected devices, actor-attributed
  indicators, and cross-source malicious-URL impact.
- **Behavioral baselines** — query-length distribution, internal/external split, newly-active
  clients, baseline spikes, and volume anomalies.
- **Guided investigation** — device DNS profile pivot and MITRE ATT&CK coverage.

---

## Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `Workspace` | Resource picker | — | Target Log Analytics / Sentinel workspace. |
| `TimeRange` | Time picker | 7 days | Global scope (except fixed-window baseline/anomaly tiles). |
| `WatchlistFilter` | Dropdown | `\| where true` (Off) | **V2** — **On** drops IPs allow-listed by `ExcludeAllowlistedIPs_AzureCustom(SrcIpAddr)`. |
| `ExcludedIPs` | Text | *(empty)* | Comma-separated client IP / CIDR / range removed from every tile (`SrcIpAddr`). |
| `DomainSearch` | Text | *(empty)* | Substring filter for the Malicious-tab domain drill-down. |
| `NXDOMAINThreshold` | Text | `50` | Distinct-NXDOMAIN threshold. |
| `SubdomainThreshold` | Text | `100` | Unique-subdomain (tunneling) threshold. |
| `QueryLenThreshold` | Text | `50` | Long-query length threshold. |
| `TunnelRecordThreshold` | Text | `50` | TXT/NULL/CNAME request threshold. |
| `DigitRatioThreshold` | Text | `0.3` | DGA digit-ratio threshold. |
| `EntropyThreshold` | Text | `3.5` | Domain Shannon-entropy threshold. |
| `PricePerGB` | Text | `2.30` | Ingestion price for cost-estimate tiles. |
| `IPorDomainSearch` | Text | *(empty)* | Pivot the Alerts & TI lookup to an IP or domain. |
| `InternalDomains` | Text | *(empty)* | Internal domain suffixes for internal-vs-external classification. |
| `DeviceSearch` | Text | *(empty)* | Client IP for the Investigation device pivot. |
| `selectedTab` | Hidden | `overview` | Tab navigation. |

---

## Data sources & prerequisites

| Source | Used by |
|---|---|
| `ASimDnsActivityLogs` (ASIM DNS via AMA) | Every tab (primary) |
| `DnsAuditEvents` | Telemetry / audit context |
| `ThreatIntelIndicators` | 🎯 Threat Intelligence |
| `SecurityAlert` / `SecurityIncident` | 🔔 Alerts & Incidents |
| `DeviceNetworkEvents` / `CommonSecurityLog` | 🎯 TI → malicious-URL environment impact |
| `ExcludeAllowlistedIPs_AzureCustom()` + `NetworkAllowlist` | Optional — only when `WatchlistFilter = On` |

**Prerequisites**
- Collect Windows DNS via the **ASIM DNS** path (AMA) so `ASimDnsActivityLogs` is
  populated.
- *(Optional)* A Threat Intelligence connector for `ThreatIntelIndicators`; MDE / CEF for
  the URL-impact tiles.
- *(Optional)* Deploy the `NetworkAllowlist` watchlist + `ExcludeAllowlistedIPs_AzureCustom()`
  function to use `WatchlistFilter = On`.

---

## Deploy / import

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `WindowsDNS-ThreatHunting-Workbook_V2_IPExclusion.workbook` and **Apply**.
3. **Done Editing** → **Save**, name it *Windows DNS — Threat Hunting, Health & Cost*, and
   pick your resource group / workspace.
4. Set **Workspace** and **Time range**, tune the threshold pills for your environment, set
   **Price per GB** for cost tiles, and (optionally) **NetworkAllowlist = On**.

---

## Notes & dependencies

- **Read-only.** The workbook only queries logs; it changes nothing.
- **IOC-IP hits / Fast flux** depend on the resolved IP (`DstIpAddr`) being logged —
  query-side Windows DNS logs may leave it sparse; the **domain-IOC path is always reliable**.
- **Baseline/anomaly tiles** (newly-observed domains, newly-active clients, client baseline
  spike, volume anomaly) use a fixed historical window and ignore `TimeRange` by design.
- **Not implemented** (need external enrichment): domain **age / registrar reputation** and
  newly-registered-domain feeds — add a WHOIS/RDAP or domain-reputation watchlist to enable.
