# Microsoft Defender for Office 365 — Threat Hunting Pack

The Email and Collaboration Security Gap: Threat Hunting with Defender for Office https://youtu.be/1Sj-L_GGEj4

**Advanced Hunting** queries for Microsoft Defender for Office 365 (MDO) and
the wider Microsoft 365 collaboration surface (Exchange Online, Microsoft Teams, SharePoint,
OneDrive). Each use case is a standalone hunting query (`queries/MDO-XX-*.yaml`) in the
Microsoft Sentinel / Defender hunting-query schema (`id`, `name`, `description`,
`requiredDataConnectors`, `tactics`, `relevantTechniques`, `query`).

> **Where to run.** These are **Advanced Hunting** queries. Run them in the
> **Microsoft Defender portal** (Hunting)  when onboarded to the
> unified platform with the **Microsoft Defender XDR** connector streaming the MDO tables. or in **Microsoft Sentinel** if tables are ingested 

---

## Repository layout

| Path | Contents |
|------|----------|
| `queries/` | **21 hunting queries** (YAML) — the full catalogue below. |
| `deploy/azuredeploy.json` | **One-shot ARM template (26 resources)** - deploys all 21 hunting queries **and** the 5 analytic rules together. Parameters: `workspace` + `deployAnalyticRulesEnabled` (true/false) - this is where you choose whether the rules deploy enabled or disabled. |
| `deploy/azuredeploy-hunting-queries.json` | ARM template - deploys only the 21 hunting queries as Sentinel `savedSearches` (Hunting Queries category). No enable/disable option (saved searches have no state). |
| `analytic-rules/` | **5 scheduled analytic rules** (YAML) promoted from the low-noise use cases, plus `azuredeploy-analytic-rules.json` (ARM) to deploy only the rules with the `deployAnalyticRulesEnabled` choice. |
| `custom-detections/` | **5 Defender XDR custom detection rules** (Graph `detectionRules` JSON) + `README.md` with portal and Graph-API deployment steps. |

### Promoted use cases (analytic rules + custom detections)

The five highest-value / lowest-noise hunts are shipped as both a Sentinel **analytic rule**
and a Defender **custom detection**:

| Hunt | Analytic rule | Custom detection |
|------|---------------|------------------|
| 05 Safe Links click-through | `MDO-AR-01` | `MDO-CD-01` |
| 08 BEC display-name impersonation | `MDO-AR-02` | `MDO-CD-02` |
| 13 Compromised internal sender | `MDO-AR-03` | `MDO-CD-03` |
| 25 Inbox rule after phishing click | `MDO-AR-04` | `MDO-CD-04` |
| Illicit OAuth consent *(hunting query removed; analytic rule + custom detection retained)* | `MDO-AR-05` | `MDO-CD-05` |

### Deployment

**Recommended - one-shot (portal or PowerShell).** Deploy `deploy/azuredeploy.json`. In the
portal **Custom deployment** you will see a **Workspace** field and a **Deploy Analytic Rules
Enabled** true/false dropdown - that dropdown is your enabled-vs-disabled choice for the
analytic rules (the hunting queries are always just saved searches).

```powershell
# Everything (21 hunting queries + 5 analytic rules) in one pass.
# deployAnalyticRulesEnabled: $true = rules enabled (default), $false = rules disabled (staged rollout)
New-AzResourceGroupDeployment -ResourceGroupName RG_Sentinel `
  -TemplateFile deploy/azuredeploy.json `
  -workspace lawsentinel -deployAnalyticRulesEnabled $true
```

**Or deploy the pieces separately:**

```powershell
# Hunting queries only (21) -> Sentinel savedSearches (no enable/disable option)
New-AzResourceGroupDeployment -ResourceGroupName RG_Sentinel `
  -TemplateFile deploy/azuredeploy-hunting-queries.json -workspace lawsentinel

# Analytic rules only (5) -> your choice via -deployAnalyticRulesEnabled ($true = enabled, $false = disabled)
New-AzResourceGroupDeployment -ResourceGroupName RG_Sentinel `
  -TemplateFile analytic-rules/azuredeploy-analytic-rules.json `
  -workspace lawsentinel -deployAnalyticRulesEnabled $false
```

Defender custom detections deploy separately — see
[`custom-detections/README.md`](custom-detections/README.md) (portal wizard or Graph API).

> Analytic rules and custom detections reference the Defender XDR tables (`EmailEvents`,
> `UrlClickEvents`, `CloudAppEvents`), so the **Microsoft Defender XDR** connector must be
> streaming them into the workspace. Customise the `Execs` / `CorpDomains` lists in the BEC
> rule before enabling.

---

## Query catalogue

### A. Email threats (EmailEvents / EmailAttachmentInfo / EmailUrlInfo / UrlClickEvents / EmailPostDeliveryEvents)

| # | Query | Primary table(s) | MITRE |
|---|-------|------------------|-------|
| 01 | Malicious email delivered to inbox (block failure) | EmailEvents | T1566 |
| 02 | Phishing campaign clustering | EmailEvents | T1566 |
| 03 | Confirmed malware attachments | EmailAttachmentInfo | T1566 |
| 04 | Dangerous file types delivered | EmailAttachmentInfo + EmailEvents | T1566, T1204 |
| 05 | Safe Links click-through to blocked URL | UrlClickEvents | T1204 |
| 06 | Users who clicked later-confirmed malicious mail | EmailEvents + UrlClickEvents | T1566, T1204 |
| 07 | Email auth failures (SPF/DKIM/DMARC spoofing) | EmailEvents | T1566, T1656 |
| 08 | BEC display-name impersonation | EmailEvents | T1656, T1534 |
| 09 | Lookalike / typosquatting domains in URLs | EmailUrlInfo | T1566 |
| 10 | ZAP gaps — threats detected after delivery | EmailPostDeliveryEvents | T1566 |
| 11 | Exposure window — delivery to remediation | EmailEvents + EmailPostDeliveryEvents | T1566 |
| 12 | Quishing (QR phishing) & suspicious images | EmailAttachmentInfo + EmailEvents | T1566 |
| 13 | Compromised internal sender (intra-org phishing) | EmailEvents | T1534, T1566 |

### B. Malicious campaigns (CampaignInfo / EmailClusterId)

| # | Query | Primary table(s) | MITRE |
|---|-------|------------------|-------|
| 14 | Malicious campaign overview (EmailClusterId) | EmailEvents | T1566 |
| 15 | Campaign view via CampaignInfo *(validate schema)* | CampaignInfo | T1566 |
| 16 | Campaign exposure (delivered + clicked) | EmailEvents + UrlClickEvents | T1566, T1204 |

### C. Microsoft Teams & collaboration (UrlClickEvents)

| # | Query | Primary table(s) | MITRE |
|---|-------|------------------|-------|
| 20 | Teams Safe Links click-through | UrlClickEvents (Workload = Teams) | T1204 |

### D. SharePoint / OneDrive & post-compromise cloud activity (FileMaliciousContentInfo / CloudAppEvents / OfficeActivity)

| # | Query | Primary table(s) | MITRE |
|---|-------|------------------|-------|
| 22 | Malicious files in SharePoint / OneDrive *(validate schema)* | FileMaliciousContentInfo | T1080, T1213 |
| 23 | Mass file download / exfil after phishing click | UrlClickEvents + CloudAppEvents | T1213, T1567 |
| 25 | Suspicious inbox rule after phishing click | UrlClickEvents + CloudAppEvents | T1114, T1564 |

### E. Cross-product kill chain

| # | Query | Primary table(s) | MITRE |
|---|-------|------------------|-------|
| 29 | Kill chain — email → click → identity → cloud | EmailEvents + UrlClickEvents + CloudAppEvents | T1566, T1204, T1098 |

---

## Required data / connectors

| Connector | Tables | Used by |
|---|---|---|
| Microsoft Defender XDR (MicrosoftThreatProtection) | EmailEvents, EmailAttachmentInfo, EmailUrlInfo, EmailPostDeliveryEvents, UrlClickEvents | 01–16, 20, 23, 25, 29 |
| Microsoft Defender XDR (Safe Attachments for collaboration) | FileMaliciousContentInfo | 22 |
| Microsoft Defender XDR (MDCA) | CloudAppEvents | 23, 25, 29 |

MDO tables require **Microsoft Defender for Office 365 Plan 2** (Safe Links / Safe
Attachments / Threat Explorer). Teams protection tables require **Defender for Office 365 for
Microsoft Teams**. `CloudAppEvents` requires **Microsoft Defender for Cloud Apps**.

---

## Schema-validation note (newer tables)

Queries marked *(validate schema)* use MDO tables that are newer / still evolving, so their
column names can vary by tenant ring. Those queries are intentionally **filter-only**
(`Timestamp` + `ThreatTypes` + `sort`) so they will not fail on a column mismatch. Before
extending them, confirm the columns in your tenant:

```kql
CampaignInfo | getschema
FileMaliciousContentInfo | getschema
```

Then enrich the `project` / `summarize` clauses with the confirmed fields.

---

## Customisation before operational use

Replace the sample values in the relevant queries:

- **Domains** — `contoso.com`, `contoso.es` (MDO-07, 08, 09).
- **Brand string** — `contoso` for typosquat / lookalike detection (MDO-09).
- **Executive display names** — `Execs` list in MDO-08 (BEC).
- **Thresholds & windows** — recipient counts, download/share counts and lookback windows
  are starting points; tune to your organisation's baseline.

Maintain exclusion lists for **phishing-simulation** tooling, **reporting mailboxes** and
**trusted bulk senders** to keep false positives low.

---

## Triage & correlation guidance

- **MDO → MDE → MDI**: the highest value comes from linking the email (MDO) to endpoint
  execution (MDE — `DeviceFileEvents`/`DeviceProcessEvents` via SHA256) and identity
  compromise (MDI / Entra sign-ins). MDO-29 stitches email → click → cloud.
- **Leadership KPIs**: MDO-01, MDO-10 and MDO-11 (undue deliveries, ZAP gaps, exposure
  window) are strong metrics to report product effectiveness.
- **Custom Detection Rule candidates**: MDO-05, MDO-08, MDO-13, MDO-25 (malicious
  click-through, BEC display-name, internal compromised sender, inbox rule after click) —
  high value and low noise once tuned.

---

*Source: Defender-for-Office-Hunting-UseCases.md — converted & extended. Column references
follow Microsoft Defender Advanced Hunting documentation; validate `*(validate schema)*`
tables against your tenant before operationalising.*
