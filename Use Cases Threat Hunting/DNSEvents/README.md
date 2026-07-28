# Windows DNS Threat Hunting — Microsoft Sentinel

Detection and hunting content for **Windows DNS Server** logs ingested via the **Azure Monitor Agent (AMA)** and the **Windows DNS Events via AMA** data connector.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Data Connector — Windows DNS Events via AMA](#data-connector--windows-dns-events-via-ama)
3. [AMA DCR Filtering — Cost Optimization](#ama-dcr-filtering--cost-optimization)
4. [DNS Attack Coverage](#dns-attack-coverage)
5. [Analytic Rules](#analytic-rules)
6. [Hunting Queries](#hunting-queries)
7. [MITRE ATT&CK Coverage](#mitre-attck-coverage)
8. [Prerequisites](#prerequisites)
9. [Deployment](#deployment)
10. [References](#references)

---

## Architecture Overview

```
Windows DNS Server
       │
       │  DNS Audit & Query Logs (Event IDs 256-260, 541)
       ▼
  AMA Agent (with DCR filter)
       │
       │  Filtered events only  ──► Cost savings up to 80%
       ▼
Log Analytics Workspace
  (table: ASimDnsActivityLogs / DnsEvents)
       │
       ▼
Microsoft Sentinel
  ├── Analytic Rules  (21 rules)
  └── Hunting Queries (40 queries)
```

## Data Connector — Windows DNS Events via AMA

**Connector name:** `Windows DNS Events via AMA`  
**Table:** `ASimDnsActivityLogs` (ASIM-normalized) and legacy `DnsEvents`  
**Requires:** Windows Server 2012 R2+ with DNS Server role; AMA 1.28+  

### Required Windows DNS Debug/Audit Logging

Enable via PowerShell on each DNS server:

```powershell
# Enable DNS Server Audit log (Event IDs 512–582)
wevtutil set-log "Microsoft-Windows-DNSServer/Audit" /enabled:true

# Enable DNS Server Analytical log (full query logging)
# Note: high volume — filter at DCR level (see below)
wevtutil set-log "Microsoft-Windows-DNSServer/Analytical" /enabled:true /quiet:true

# Or via DNS Server settings (recommended for production):
Set-DnsServerDiagnostics -All $true -LogFilePath "C:\dns.log"
```

---

## AMA DCR Filtering — Cost Optimization

> **This is the single most important cost-control lever for Windows DNS ingestion.**
> Raw DNS query logs can generate **hundreds of GB per day** in busy environments.
> Use Data Collection Rules (DCR) XPath filters to drop noise at the agent level — data that is never sent is never billed.

Step-by-step guide for using data collection filters on the Windows DNS Events via AMA connector to cut ingestion cost. This connector writes to ASimDnsActivityLogs (and DnsAuditEvents), and DNS is one of the highest-volume, noisiest sources — so filtering pays off fast.
Step 0 — Measure first (know what to cut)
Before filtering, find your biggest cost drivers so you filter noise, not signal. Run these in Logs:

// Top noisy domains (last 24h)
ASimDnsActivityLogs
| where TimeGenerated > ago(24h)
| summarize Events = count() by DnsQuery
| top 30 by Events desc

// Volume by query type (PTR/reverse lookups are usually pure noise)
ASimDnsActivityLogs
| where TimeGenerated > ago(24h)
| summarize Events = count() by DnsQueryTypeName
| order by Events desc

// Estimate ingestion volume (GB) for this table over 30 days
ASimDnsActivityLogs
| where TimeGenerated > ago(30d)
| summarize GB = sum(_BilledSize) / 1024 / 1024 / 1024

Good candidates to exclude: PTR/reverse-lookup queries, successful internal domains (your own AD/corp domains), chatty telemetry domains (e.g., *.microsoft.com, CDN/OS-update domains), and health-probe clients.
Exclude high-volume benign domains from your Step 0 top-30 list

Step 1 — Open the connector filter UI
Microsoft Sentinel → Configuration → Data connectors.
Open Windows DNS Events via AMA → Open connector page (the panel in your screenshot).
Under Configuration → 2. Define data collection filters to exclude events, click + Add data collection filters.

Step 2 — Add an exclusion filter
For each filter you add:

Give it a filter name (e.g., Exclude-PTR-Queries).
Choose the filter type / field to match on (the connector exposes DNS fields such as query type, query name/domain, client IP, event type).
Enter the value(s) to exclude (this connector's filters are exclusion rules — matching events are dropped before ingestion).
Click Add.
Repeat to stack multiple filters. Recommended starter set:

Exclude PTR / reverse lookups (query type = PTR)
Exclude known-good internal domains (your AD domain suffixes)

Step 3 — Apply
Click Apply changes. This updates the underlying Data Collection Rule (DCR) for the connector. New agents/events honor it within a few minutes; existing agents pick it up on their next config refresh.

Step 4 — Validate the drop
After ~30–60 min, confirm volume fell and you didn't lose needed data:
ASimDnsActivityLogs
| where TimeGenerated > ago(2h)
| summarize Events = count() by bin(TimeGenerated, 15m)
| render timechart

Re-run the "top domains" and "query type" queries — the excluded categories should be gone.

Step 5 — Stack additional cost levers (from the same connector page)
The Table management section in your screenshot (both tables at Analytics tier, 90-day retention) gives you two more big levers:

Step 6 — (Optional) Go granular with a workspace transformation DCR
Portal filters are field-level exclusions. For surgical control (e.g., "keep NXDOMAIN and external domains, drop only successful internal lookups"), use an ingestion-time transformation (transformKql) on the DCR:
source
| where not(DnsQueryTypeName == "PTR")
| where not(DnsResponseCodeName == "NOERROR" and DnsQuery endswith ".corp.contoso.com")

This runs before billing, so filtered rows are never charged. You can also use it to project away unused columns to shrink row size.



### What is a DCR XPath Filter?

The AMA collects Windows Event Log entries through **Data Collection Rules**. Each DCR can specify XPath queries to pre-filter which events are forwarded to Log Analytics. Events excluded by the filter are **dropped at the agent** — they never traverse the network and are **never ingested**, so you pay nothing for them.

### Recommended DCR XPath Filters

The goal is to keep **high-signal DNS events** and drop routine recursive resolutions of well-known safe domains.

> **AMA XPath Validation Rules — Must Follow:**
> - XPath must be a **single-line string** — no line breaks inside the query
> - Each condition on `EventData` must be its **own separate predicate**: `EventData[Data[@Name='X']='Y']` — using `or` inside a single `EventData[...]` causes a validation error
> - Wildcard domain matching (`*.domain.com`) is **not supported** in XPath 1.0 — use `contains()` instead
> - All examples below use the **JSON DCR format** required by AMA (ARM template / REST API)

---

#### 1. Scope to DNS Audit Events Only (Minimal Footprint)

Collects only DNS Server Audit events: zone changes, server config, DNSSEC operations. Very low volume — recommended as a baseline for all environments.

```json
{
  "dataSources": {
    "windowsEventLogs": [
      {
        "name": "dns-audit-only",
        "streams": ["Microsoft-Windows-DNSServer/Audit"],
        "xPathQueries": [
          "Microsoft-Windows-DNSServer/Audit!*"
        ]
      }
    ]
  }
}
```

**Estimated volume:** Very low (~hundreds of events/day). **Recommended for all environments** as a baseline.

---

#### 2. Analytical Log — Filter Out Internal Lookups

Scopes to query/response event IDs and excludes well-known safe domains using `contains()`. Each domain is a **separate `EventData[...]` predicate** joined with `or` inside `not()` to comply with AMA validation.

> **Note:** `*.microsoft.com` wildcard syntax is invalid in AMA XPath. Use `contains(Data[@Name='QNAME'],'.microsoft.com')` to match any subdomain.  
> If you need to exclude more than ~10 domains, use a **DCR Transformation** (KQL-based filter) instead — it is more flexible and has no length limit.

```json
{
  "dataSources": {
    "windowsEventLogs": [
      {
        "name": "dns-analytical-filtered",
        "streams": ["Microsoft-Windows-DNSServer/Analytical"],
        "xPathQueries": [
          "Microsoft-Windows-DNSServer/Analytical!*[System[(EventID=256 or EventID=257 or EventID=260 or EventID=541)] and not(EventData[contains(Data[@Name='QNAME'],'.microsoft.com')] or EventData[contains(Data[@Name='QNAME'],'.windows.com')] or EventData[contains(Data[@Name='QNAME'],'.windowsupdate.com')] or EventData[contains(Data[@Name='QNAME'],'.office.com')] or EventData[contains(Data[@Name='QNAME'],'.office365.com')] or EventData[contains(Data[@Name='QNAME'],'.azure.com')] or EventData[Data[@Name='QNAME']='wpad'] or EventData[Data[@Name='QNAME']='isatap'])]"
        ]
      }
    ]
  }
}
```

**Event ID reference:**

| EventID | Description |
|---|---|
| 256 | DNS query received from client (includes QNAME, QTYPE) |
| 257 | DNS response sent to client (includes RCODE) |
| 260 | DNS recursive query sent upstream |
| 541 | DNS internal lookup |

---

#### 3. High-Signal Only — TXT/MX/NULL/ANY Record Types

Tunnel exfiltration and C2 traffic almost always uses uncommon record types. Collect only those. `QTYPE` in the Windows DNS analytical log is the **string name** of the record type, not a numeric code. Each type is a separate `EventData[...]` predicate.

> **Note:** `ANY` (type 255) and `NULL` (type 10) are high-signal for DNS tunneling tools (iodine, dnscat2). EventID 256 is the query-received event — QTYPE is not populated on response events (EventID 257).

```json
{
  "dataSources": {
    "windowsEventLogs": [
      {
        "name": "dns-hv-record-types",
        "streams": ["Microsoft-Windows-DNSServer/Analytical"],
        "xPathQueries": [
          "Microsoft-Windows-DNSServer/Analytical!*[System[EventID=256] and (EventData[Data[@Name='QTYPE']='TXT'] or EventData[Data[@Name='QTYPE']='MX'] or EventData[Data[@Name='QTYPE']='NULL'] or EventData[Data[@Name='QTYPE']='ANY'])]"
        ]
      }
    ]
  }
}
```

---

#### 4. NXDOMAIN / SERVFAIL Only (Brute Force / Tunneling Indicator)

High volumes of NXDOMAIN responses are a leading indicator for DNS tunneling, DGA, and password spray via DNS enumeration. `RCODE` is a **numeric field** on response events (EventID 257): `3` = NXDOMAIN, `2` = SERVFAIL.

> **Note:** RCODE is only present on EventID 257 (response events) — not on 256 (query events). Each RCODE value must be its own `EventData[...]` predicate.

```json
{
  "dataSources": {
    "windowsEventLogs": [
      {
        "name": "dns-failure-responses",
        "streams": ["Microsoft-Windows-DNSServer/Analytical"],
        "xPathQueries": [
          "Microsoft-Windows-DNSServer/Analytical!*[System[EventID=257] and (EventData[Data[@Name='RCODE']='3'] or EventData[Data[@Name='RCODE']='2'])]"
        ]
      }
    ]
  }
}
```

### Cost Estimation Reference

| Filter Strategy | Est. Events/Day (1K users) | Approx. GB/Day | Monthly Cost* |
|---|---|---|---|
| No filter (all events) | 5–50M | 50–500 GB | $1,000–$10,000 |
| Audit log only | ~5,000 | < 0.05 GB | ~$1 |
| Analytical + type filter (TXT/MX/NULL/ANY) | ~50,000 | ~0.5 GB | ~$10 |
| NXDOMAIN + failure responses | ~200,000 | ~2 GB | ~$40 |
| Analytical + domain exclusions | ~500,000 | ~5 GB | ~$100 |

*Based on Log Analytics pay-as-you-go rate of ~$2.30/GB. Commitment tiers reduce cost significantly.

### Tiered Filtering Strategy (Recommended)

```
Tier 1 (Always): DNS Audit log ─── Config changes, zone transfers, DNSSEC
Tier 2 (Recommended): NXDOMAIN/SERVFAIL responses ─── Tunneling, DGA, spray
Tier 3 (High-value): TXT/MX/NULL/ANY queries ─── Exfiltration detection
Tier 4 (Optional): Full query log with domain exclusions ─── Deep hunting
```

> **Tip:** Start with Tiers 1 + 2. Add Tiers 3 and 4 if you see specific threats or have budget. Use a **2-week commitment tier** in Log Analytics to cut per-GB cost by 30–50%.

---

## DNS Attack Coverage

This package detects the following DNS attack categories, mapped to real-world threat actors and techniques:

| # | Attack Category | MITRE Technique | Threat Actors / Tools |
|---|---|---|---|
| 1 | **DNS Tunneling — TXT Records** | T1071.004 | Cobalt Strike, DNScat2, iodine, OilRig (APT34) |
| 2 | **DNS Tunneling — MX/NULL Records** | T1071.004 | MX-based tunneling (as documented by Octoberfest7), APT32 |
| 3 | **DNS C2 Beaconing** | T1071.004, T1132 | Cobalt Strike DNS beacon, Silver, Havoc |
| 4 | **ClickFix / nslookup Payload Delivery** | T1059.001, T1071.004 | ModeloRAT, TA577 (Feb 2026 campaign) |
| 5 | **DNS-Based DGA (Domain Generation Algorithm)** | T1568.002 | Emotet, QakBot, Dridex, TrickBot |
| 6 | **DNS Amplification / Reflection (DoS)** | T1498.002 | Anonymous, various DDoS-for-hire |
| 7 | **DNS Zone Transfer Abuse (AXFR)** | T1590.002 | Reconnaissance phase — APT groups, red teams |
| 8 | **DNS Rebinding** | T1557, T1090 | Browser-based SSRF via rebinding (Singularity tool) |
| 9 | **Subdomain Takeover** | T1584.001 | Supply chain attacks — dangling DNS records |
| 10 | **DNS Exfiltration (Data-over-DNS)** | T1048.003 | APT34, APT32, Turla, Wizard Spider |
| 11 | **DNSSEC Downgrade / Bypass** | T1562.010 | Advanced persistent threats |
| 12 | **Internal DNS Recon (Rapid Enumeration)** | T1018, T1046 | Post-compromise lateral movement |
| 13 | **WPAD / NetBIOS Name Poisoning via DNS** | T1557.001 | Responder, Inveigh |
| 14 | **High-Entropy Domain Lookups** | T1568 | DGA malware families |
| 15 | **Certutil / LOLBin DNS Payload Staging** | T1218, T1027 | ClickFix campaigns, LotL techniques |

---

## Analytic Rules

| # | Rule Name | Severity | MITRE Technique |
|---|---|---|---|
| 01 | DNS Tunneling via High-Volume TXT Record Queries | High | T1071.004 |
| 02 | DNS C2 Beaconing — Low TTL Periodic Lookups | High | T1071.004, T1132 |
| 03 | ClickFix nslookup Payload Delivery via DNS | High | T1059.001, T1071.004 |
| 04 | DGA — High-Entropy Subdomain Pattern | High | T1568.002 |
| 05 | DNS Zone Transfer (AXFR) from Internal Host | Medium | T1590.002 |
| 06 | DNS Amplification Attack — Open Resolver Abuse | Medium | T1498.002 |
| 07 | DNS Rebinding — Rapid TTL Change Same Domain | Medium | T1557, T1090 |
| 08 | Data Exfiltration via Long DNS Subdomain Labels | High | T1048.003 |
| 09 | WPAD Auto-Discovery DNS Lookup Abuse | Medium | T1557.001 |
| 10 | DNS-Based Internal Network Reconnaissance | Medium | T1018, T1046 |
| 11 | Certutil Decoding after DNS Lookup (LOLBin Chain) | High | T1218, T1027 |
| 12 | Repeated NXDOMAIN — Potential DGA Malware | High | T1568.002 |
| 13 | NULL/ANY Record Type Queries — Tunneling Indicator | Medium | T1071.004 |
| 14 | DNS MX Record Abuse for Payload Staging | High | T1071.004, T1132 |
| 15 | Subdomain Enumeration Burst (Brute Force DNS) | Medium | T1590.002, T1046 |

---

## Hunting Queries

| # | Query Name | Data Source | Description |
|---|---|---|---|
| Q01 | Top TXT Query Senders | ASimDnsActivityLogs | Volume baseline for TXT record hunters |
| Q02 | High Subdomain Label Length Distribution | ASimDnsActivityLogs | Data-in-DNS detection |
| Q03 | nslookup Process with Non-Standard Server | SecurityEvent | ClickFix pivot hunting |
| Q04 | DGA Score Distribution by Domain | ASimDnsActivityLogs | Entropy-based DGA hunting |
| Q05 | Zone Transfer Attempts Map | ASimDnsActivityLogs | AXFR timeline |
| Q06 | DNS Beacon Interval Analysis | ASimDnsActivityLogs | C2 heartbeat regularity |
| Q07 | Rare External DNS Resolvers Used | ASimDnsActivityLogs | Bypassing corporate DNS |
| Q08 | DNS Exfil Bytes Estimate by Client | ASimDnsActivityLogs | Subdomain data volume |
| Q09 | NXDOMAIN Storm per Client | ASimDnsActivityLogs | DGA / spray detection |
| Q10 | Long-Running DNS Queries (Timing Anomaly) | ASimDnsActivityLogs | Tunneling detection |
| Q11 | WPAD Lookup Sources | ASimDnsActivityLogs | WPAD poisoning candidates |
| Q12 | Newly Observed Domains (NOD) | ASimDnsActivityLogs | First-seen domain detection |
| Q13 | Low-TTL Domain Flip (Rebinding) | ASimDnsActivityLogs | DNS rebinding preparation |
| Q14 | Top SERVFAIL Sources | ASimDnsActivityLogs | Recon / misconfig hunting |
| Q15 | Certutil + DNS Lookup Process Chain | SecurityEvent + ASimDnsActivityLogs | LOLBin chain |
| Q16 | Domains per Client Volume Outliers | ASimDnsActivityLogs | Internal recon sweep |
| Q17 | PTR (Reverse DNS) Bulk Lookups | ASimDnsActivityLogs | Network mapping |
| Q18 | Wildcard DNS Query Patterns | ASimDnsActivityLogs | Tool-generated signatures |
| Q19 | MX Record Queries Outside Mail Flow | ASimDnsActivityLogs | MX tunnel staging |
| Q20 | DNS Queries to TOR-Related Domains | ASimDnsActivityLogs | Evasion routing |
| Q21 | High-Frequency Single-Label Lookups | ASimDnsActivityLogs | WPAD/ISATAP / LAN scope |
| Q22 | Subdomain Depth Outliers (Tunneling) | ASimDnsActivityLogs | Deep subdomain chains |
| Q23 | DNS Traffic to Non-Corporate Nameservers | ASimDnsActivityLogs | DNS hijack / bypass |
| Q24 | Repeated Identical Queries (Beaconing) | ASimDnsActivityLogs | Exact-match C2 poll |
| Q25 | Domain Aging Analysis (DGA Registration Freshness) | ASimDnsActivityLogs | New domain registration |
| Q26 | DNS Response Size Anomaly | ASimDnsActivityLogs | Oversized TXT/NULL responses |
| Q27 | Lateral Movement via DNS Lookup Patterns | ASimDnsActivityLogs | Internal east-west recon |
| Q28 | Process-to-DNS Mapping (Unusual Parents) | SecurityEvent | Suspicious DNS callers |
| Q29 | Base64 Patterns in DNS Labels | ASimDnsActivityLogs | Encoded payload detection |
| Q30 | DNS Activity by Newly Created Accounts | ASimDnsActivityLogs + IdentityInfo | Insider / compromised account |

---

## MITRE ATT&CK Coverage

```
Initial Access      : T1190 (exploiting public DNS)
Execution           : T1059.001 (PowerShell via DNS payload)
Persistence         : -
Defense Evasion     : T1027, T1036, T1562.010, T1218
Credential Access   : T1557.001 (WPAD/NBT-NS poisoning)
Discovery           : T1018, T1046, T1590.002
Lateral Movement    : T1557
Collection          : T1114, T1213
C2                  : T1071.004 (DNS), T1090, T1132
Exfiltration        : T1048.003 (Exfil over DNS)
Impact              : T1498.002 (DNS amplification)
```

---

## Prerequisites

| Requirement | Details |
|---|---|
| Microsoft Sentinel | Any tier — with Log Analytics workspace |
| Data Connector | **Windows DNS Events via AMA** (enable in Sentinel → Data Connectors) |
| Agent | Azure Monitor Agent (AMA) 1.28+ on Windows DNS Servers |
| Table | `ASimDnsActivityLogs` (ASIM normalized) |
| Windows | Server 2012 R2 or later with DNS Server role |
| DNS Logging | Analytical log or Debug log enabled (see above) |
| UEBA | Optional — enables Q30 (account correlation) |

---

## Deployment

### Network Allowlist Watchlist (false-positive suppression)

All 14 `ASimDnsActivityLogs`-based rules call a KQL function
`ExcludeAllowlistedIPs()` that filters out `SrcIpAddr` values matching the
`NetworkAllowlist` Sentinel watchlist (sanctioned internal resolvers,
management subnets, DNS sinkholes). The 3 `SecurityEvent`-only rules
(ClickFix nslookup, Certutil-after-DNS, DNSAdmins privesc) keep their
host-centric logic unchanged.

The watchlist + function are deployed automatically by the ARM template.
For scheduled sync from Entra Named Locations, see
[`Watchlists/README.md`](Watchlists/README.md).

### New ARM template parameters

| Parameter | Default | Purpose |
|---|---|---|
| `workspaceName` | (required) | Sentinel workspace name. |
| `enableAnalyticRules` | `true` | If `false`, all 21 rules deploy in **disabled** state for staged rollout. |
| `watchlistAlias` | `NetworkAllowlist` | Alias of the trusted-IP exclusion watchlist. |
| `functionAlias` | `ExcludeAllowlistedIPs_WindowsDNS` | KQL `savedSearches` alias for the filter function. |
| `watchlistRawContent` | empty (seed RFC1918) | Override CSV content (CRLF-separated; header `IPOrRange,Description,Owner,AddedDate`). Daily sync runbook replaces this with Entra Named Locations. |

### Threshold tuning (May 2026)

Inline thresholds have been raised ~2-3x to reduce production noise.
Override per-rule via the Sentinel rule editor if needed.

| # | Rule | Threshold | Old → New |
|---|---|---|---|
| 01 | DNS TXT Tunneling | `TxtQueryCount` | 100 → **250** |
| 02 | DNS C2 Beaconing | `QueryCount` | 20 → **50** |
| 04 | DGA High-Entropy | `DgaLikeDomains` | 10 → **25** |
| 06 | DNS Amplification | `AmpQueryCount` | 200 → **500** |
| 07 | DNS Rebinding | `QueryCount` | 5 → **10** |
| 08 | DNS Data Exfil long labels | `MaxLabelLen` / `EstimatedKB` | 35/50 → **45/100** |
| 09 | WPAD Auto-Discovery | `UniqueHosts` | 3 → **5** |
| 10 | DNS Internal Recon Sweep | `UniqueDomains` | 300 → **750** |
| 11 | Certutil after nslookup | `NslookupCount` | 5 → **10** |
| 12 | NXDOMAIN flood | `NxdomainCount` | 200 → **500** |
| 13 | NULL/ANY queries | `NullAnyCount` | 5 → **15** |
| 14 | MX Record Payload Staging | `MxQueryCount` / `NumericPrefixed` | 10/3 → **25/5** |
| 15 | Subdomain Enum Burst | `SubdomainCount` | 30 → **75** |
| 17 | ADIDNS Wildcard | `FlippedDomains` | 5 → **10** |

### Detection logic fixes (Jul 2026)

Beyond threshold tuning, these correctness/false-positive fixes were applied to both the rule YAMLs and `azuredeploy.json`:

| # | Rule | Fix |
|---|---|---|
| 03 | ClickFix nslookup | `queryFrequency`/`queryPeriod` aligned to `PT1H` (was 15m/1d → re-alerted ~96×/day on the same event) |
| 04 | DGA High-Entropy | added `DnsResponseCode == 0` so it scores **resolved** domains only (matches its stated intent; stops overlap with rule 12) |
| 06 | DNS Amplification | removed `TXT` from the record-type set (common SPF/DKIM traffic → FP; covered by rules 01/13) |
| 09 | WPAD Abuse | now requires **NOERROR** (an active WPAD responder) instead of firing on every benign `wpad`/`isatap` lookup |
| 15 | Subdomain Enum | added `NxdomainRate > 40` gate (enumeration produces mostly NXDOMAIN; excludes CDN/analytics fan-out) |
| 16 | DNSAdmins DLL | restart correlation changed to `leftouter` + null-safe — fires on `dnscmd /serverlevelplugindll` alone (EventID 7036 is not in `SecurityEvent`) |

### New detections (Jul 2026)

| # | Rule | What it catches |
|---|---|---|
| 18 | DoH Resolver Bypass | clients resolving public DNS-over-HTTPS endpoints to bypass the corporate resolver/filtering |
| 19 | Threat-Intel Domain Match | deterministic IOC hit: DNS query to a domain in `ThreatIntelIndicators` |
| 20 | Dynamic DNS Provider Abuse | DuckDNS/No-IP/ngrok/trycloudflare and similar C2-staging providers |
| 21 | Suspicious TLD Volume | high volume of unique domains under abuse-heavy TLDs (.zip .mov .top .cfd …) |

Hunting-query fixes: Q04 (invalid entropy function + broken consonant/`dcount` logic), Q13 (rebinding — counted the wrong column, now uses the answer IP), Q26 (meaningless `max(DnsResponseCode)` → `DnsAnswerCount`). New hunts Q36–Q40: DoH endpoints, TI domain match, dynamic-DNS providers, punycode/IDN homoglyphs, and PowerShell `Resolve-DnsName` (ClickFix variant).

### Staged deployment

```powershell
# Stage 1 - deploy disabled for review
New-AzResourceGroupDeployment `
  -ResourceGroupName "your-rg" `
  -TemplateFile ".\Analytic-Rules\azuredeploy.json" `
  -workspaceName "your-workspace-name" `
  -enableAnalyticRules $false

# Stage 2 - enable after watchlist sync + rule review
New-AzResourceGroupDeployment `
  -ResourceGroupName "your-rg" `
  -TemplateFile ".\Analytic-Rules\azuredeploy.json" `
  -workspaceName "your-workspace-name" `
  -enableAnalyticRules $true
```

### Convenience script

```powershell
# Deploy all rules and hunting queries
.\Analytic-Rules\deploy-dns-rules.ps1 `
    -WorkspaceName "your-workspace-name" `
    -ResourceGroupName "your-rg" `
    -SubscriptionId "your-subscription-id"
```

Or deploy via ARM template directly:

```powershell
New-AzResourceGroupDeployment `
    -ResourceGroupName "your-rg" `
    -TemplateFile ".\Analytic-Rules\azuredeploy.json" `
    -workspaceName "your-workspace-name"
```

---

## References

| Source | Topic |
|---|---|
| Octoberfest7/DNS_Tunneling | MX record tunneling, nslookup payload staging via PowerShell |
| BleepingComputer — ClickFix DNS | nslookup DNS payload delivery (ModeloRAT, Feb 2026) |
| GitHub Security Lab — DNS Rebinding | Browser-based SSRF via DNS TTL rebinding attacks |
| PopLabSec/DNS-Penetration-Testing | Zone transfer, enumeration, DNS attack taxonomy |
| SANS — DNS Tunneling | Detection methodologies for DNS C2 channels |
| OilRig / APT34 TTPs | DNS-based C2 and data exfiltration via TXT records |
| Cobalt Strike DNS beacon | Periodic low-TTL beaconing, MX/TXT staging |
| Emotet/QakBot DGA | High-entropy domain generation, NXDOMAIN flood |
| Microsoft ASIM | ASimDnsActivityLogs normalized schema documentation |
| Azure Monitor DCR | XPath filter syntax for cost-optimized ingestion |
