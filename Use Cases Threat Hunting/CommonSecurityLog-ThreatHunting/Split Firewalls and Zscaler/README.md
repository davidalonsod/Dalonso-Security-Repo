# Repository Changes – March 2026

## Folder Reorganization

Content previously stored flat under `Analytic-Rules/` has been split into two vendor-specific folders. The original `Analytic-Rules/` folder is kept as-is for backward compatibility.

---

## New Folder: `Firewall/`

Covers **Fortinet FortiGate**, **Palo Alto Networks**, and cross-vendor (all-vendor) queries.

| Sub-folder | Contents |
|---|---|
| `Firewall/Analytic-Rules/rules/` | 16 YAML analytic rules: 01–08, 12–17, 19–20 |
| `Firewall/Analytic-Rules/azuredeploy.json` | ARM template — deploys 16 analytic rules + 16 hunting queries |
| `Firewall/Analytic-Rules/deploy-rules.ps1` | PowerShell deployment script |
| `Firewall/Hunting-Queries/CSL-Firewall-HuntingQueries.kql` | 16 KQL hunting queries (Q01–Q08, Q12–Q17, Q19–Q20) |

Rules included: Beaconing Detection, Data Exfiltration, TI IP/Domain Match, Port Scan, High-Risk Country Traffic, Lateral Movement, Fortinet IPS, Palo Alto Threats, First-Seen External IP, Firewall+AAD Correlation, IOC Correlation, Palo Alto Zone Denies, Fortinet VPN Brute Force, Protocol Anomaly, Risky Identity Correlation.

---

## New Folder: `Zscaler/`

Covers **Zscaler ZIA** and **Zscaler ZPA**.

| Sub-folder | Contents |
|---|---|
| `Zscaler/Analytic-Rules/rules/` | 21 YAML analytic rules: 09–11, 18, 21–37 |
| `Zscaler/Analytic-Rules/azuredeploy.json` | ARM template — deploys 21 analytic rules + 15 hunting queries |
| `Zscaler/Analytic-Rules/deploy-rules.ps1` | PowerShell deployment script |
| `Zscaler/Hunting-Queries/CSL-Zscaler-HuntingQueries.kql` | 15 KQL hunting queries (Q09–Q11, Q18, Q21–Q31) |

Rules included: Malicious Category Blocks, Shadow IT/File Sharing, DNS Tunneling, Impossible Travel, DLP Violation, ATP Sandbox, Mass Cloud Storage Download, Uncategorized Domain Spike, Tunnel/Proxy Bypass, Off-Hours Activity, Multi-User Phishing, High Threat Risk Allowed, Category Shift Anomaly, Visibility Loss, ZPA Anomalous Geolocation, ZPA Connection Failures, ZPA First-Time App Access, ZPA Volume Spike, ZIA Low & Slow Exfiltration, ZPA Perfect Impostor, ZIA Control Evasion.

---

## Hunting Queries Added to ARM Templates

All ARM templates now also deploy **hunting queries** as `savedSearches` resources. After deployment, queries appear in the Microsoft Sentinel **Hunting** blade with full MITRE ATT&CK tagging.

| Template | Analytic Rules | Hunting Queries |
|---|---|---|
| `Analytic-Rules/azuredeploy.json` | 37 | 31 |
| `Firewall/Analytic-Rules/azuredeploy.json` | 16 | 16 |
| `Zscaler/Analytic-Rules/azuredeploy.json` | 21 | 15 |

---

## KQL Bug Fixes

| Query | Field | Fix |
|---|---|---|
| Q05 – High-Risk Country Traffic | `DestinationCountry`, `SourceCountry` — not columns in `CommonSecurityLog` | Replaced with `geo_info_from_ip_address()` to derive country from IP |
| Q18 – Impossible Travel | `SourceGeoCity` — not a column in `CommonSecurityLog` | Replaced with `geo_info_from_ip_address(SourceIP).country` |
| Q20 – Risky Identity Correlation | `ManagerUPN` — not a column in `IdentityInfo` | Replaced with `Manager` |
| Q20 – Risky Identity Correlation | `AccountEnabled` — not a column in `IdentityInfo` | Replaced with `IsAccountEnabled` |
| Q31 – APT Control Evasion | `Message` / `RenderedDescription` — not resolvable in `SecurityEvent` summarize | Replaced with `Activity` |
| Q03, Q15, Q24 – TI Correlation queries | `ThreatIntelligenceIndicator` — deprecated table | Migrated to `ThreatIntelIndicators` with updated schema (see section below) |

All fixes applied to: source TXT, KQL files, YAML analytic rules, and ARM template JSON.

---

## ThreatIntelligenceIndicator → ThreatIntelIndicators Migration

`ThreatIntelligenceIndicator` is deprecated. All three TI-correlated queries have been migrated to `ThreatIntelIndicators`.

**Schema changes applied:**

| Old (`ThreatIntelligenceIndicator`) | New (`ThreatIntelIndicators`) |
|---|---|
| `Active == true` | `isempty(ValidUntil) or ValidUntil > now()` |
| `ThreatType` (string) | `make_set(Tags)` — `Tags` is the string column; `ThreatTypes` dynamic column does not exist |
| `ConfidenceScore` | `Confidence` |
| `NetworkIP` | `isnotnull(parse_ipv4(ObservableValue))` — IPs are filtered by value format |
| `DomainName` | `ObservableKey has "domain"` + `ObservableValue` |
| `Url` | `ObservableKey has "url"` + `ObservableValue` |
| `coalesce(DomainName, NetworkIP)` | `(ipv4_is_valid(ObservableValue) or ObservableKey has "domain")` + `ObservableValue` |
| `Value` (indicator value column) | `ObservableValue` — STIX observable value column |

**Migrated queries:**
- **Q03** – Threat Intelligence IP Correlation (Firewall folder)
- **Q15** – Correlation: Firewall Traffic + TI Domain/URL Match (Firewall folder)
- **Q24** – ZIA Allowed Traffic to TI-Listed Domains/IPs (Zscaler folder)

> **Prerequisite:** The `ThreatIntelIndicators` table must be provisioned in the workspace (i.e., the **Microsoft Defender Threat Intelligence** or **Threat Intelligence Platforms** data connector must be enabled) before deploying these rules.
