
# 📧 Defender for Office 365 — BEC & AiTM Threat Hunting Workbook (V2)

Boost SOC Visibility: Defender for Office Workbook with Sentinel & Advanced Hunting https://youtu.be/zXUjATEWxJs
A comprehensive Microsoft Sentinel **workbook** for hunting **Business Email Compromise
(BEC)** and **Adversary-in-the-Middle (AiTM)** phishing, plus full email-security
protection analytics for **Microsoft Defender for Office 365** — detonation stats, Safe
Links / Safe Attachments, ZAP, campaigns, geo threat mapping, XDR attack chains, and
configuration posture.

- **File:** `DefenderForOffice365-BEC-AiTM-Workbook-V2.json`
- **Version:** v2.3 (V2 line — `OfficeActivity` removed, Advanced Hunting section added)
- **Tabs:** 13 · **Query tiles:** 185 · **Parameters:** 5
- **Type:** Azure Monitor / Microsoft Sentinel workbook (Gallery Template JSON)

---

## Why this workbook

BEC and AiTM are the highest-impact email-borne threats: AiTM steals session tokens to
bypass MFA, and BEC drives invoice fraud, executive impersonation, and payment
diversion. This workbook correlates **Defender for Office 365 email telemetry** with
**identity sign-ins** and **XDR incidents** so you can see the full chain — phishing
email → malicious click → risky sign-in → post-compromise inbox rules / OAuth consent —
and measure how well protection controls are working.

---

## Tabs

| Tab | What it covers |
|---|---|
| 🎯 **Executive Summary** | Protection KPIs for leadership, URL/file threats stopped at delivery & time-of-click, users protected, link protection by platform, risk score, cost-savings framing. |
| 🔴 **BEC Detection** | Domain impersonation, BEC financial/urgent keyword detection, email-auth failures (SPF/DKIM/DMARC), display-name (executive) spoofing, potential account-compromise via unusual outbound. |
| 🟠 **AiTM Phishing** | Phishing email → suspicious sign-in correlation, URL click → sign-in correlation, known AiTM/phishing toolkit URLs, XDR AiTM & credential-theft alerts. |
| 🎣 **Phishing Analysis** | Phishing metrics, detection methods, timeline, top phishing domains, delivered-phish requiring investigation. |
| 🦠 **Malware & Attachments** | Attachment metrics, detection methods, delivery actions, timeline, top sources, targeted recipients (Safe Attachments detonation). |
| 🌍 **Geo Threat Map** | Email threat-source map, threats by TLD, sign-in locations with trust status, sign-ins from untrusted locations / email-threat-source IPs, countries by risk. |
| 📊 **Campaigns** | Pattern-based campaign detection, threat-type distribution, top sender domains, common lures (subject lines), content-based email clustering. |
| 🔗 **URL Analysis** | URL click metrics, users who clicked malicious URLs, top malicious domains, threat-click timeline (Safe Links). |
| 🛡️ **ZAP & Remediation** | Zero-Hour Auto Purge status, post-delivery actions by type/timeline, users protected, Teams Safe Links & collaboration security. |
| 🚨 **XDR & Attack Chains** | Multi-stage email → credential-theft chains, AiTM/session-hijacking alerts, MITRE ATT&CK, phishing → risky sign-in, post-compromise inbox rules & forwarding, OAuth/consent-grant attacks, combined email+identity high-risk users, tagged BEC/credential-phishing/AiTM incidents. |
| ⚙️ **Email Security Config** | Preset security policies coverage, anti-phishing/spam/malware & Safe Attachments/Links status, email-auth summary, quarantine policy, tenant allow/block, config recommendations & compliance, external-forwarding check. |
| 🔎 **Investigation** | Guided user (email) and domain pivots — per-user threats received, emails from a domain. |
| 🔍 **Advanced Hunting (M365D)** | M365 Defender-exclusive tables: campaigns, Teams messaging / URLs / post-delivery ZAP / calls, and malicious files across SharePoint / OneDrive / Teams. |

---

## Key capabilities

- **BEC fraud detection** — invoice fraud, executive/display-name impersonation, vendor
  compromise, payment-diversion language, and outbound-anomaly account-compromise
  signals.
- **AiTM investigation** — token theft / session hijacking / MFA-bypass via
  email-to-sign-in and click-to-sign-in correlation, plus known toolkit URLs.
- **Protection analytics** — threats stopped at delivery vs time-of-click, Safe Links /
  Safe Attachments detonation, users protected, and ZAP/post-delivery remediation.
- **Campaigns & MITRE** — pattern-based campaign clustering, lures, and ATT&CK mapping.
- **Geo & trusted-location validation** — threat-source mapping and sign-ins from
  untrusted locations or email-threat-source IPs.
- **XDR attack chains** — email → credential theft → post-compromise persistence
  (inbox rules, forwarding, OAuth consent) with tagged-incident views.
- **Configuration posture** — preset policies, DMARC/DKIM/SPF enforcement, and
  actionable gap/compliance recommendations.
- **Collaboration security** — Teams / SharePoint / OneDrive malicious-file and URL
  telemetry via M365D Advanced Hunting.

---

## Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `Workspace` | Resource picker | — | Target Log Analytics / Sentinel workspace. |
| `TimeRange` | Time picker | 7 days | Global time scope for all tiles. |
| `InvestigateUser` | Text (email) | *(empty)* | Drives the 🔎 Investigation per-user views. |
| `InvestigateDomain` | Text | *(empty)* | Drives the domain-investigation views. |
| `SelectedThreatType` | Multi-select | `All` | Scopes threat-type filtered tiles. |

---

## Data sources & connectors

| Connector / product | Tables | Notes |
|---|---|---|
| **Defender for Office 365** | `EmailEvents`, `EmailPostDeliveryEvents`, `UrlClickEvents`, `EmailAttachmentInfo`, `EmailUrlInfo` | Core email-security telemetry (primary). |
| **Microsoft Sentinel** | `SecurityIncident`, `SecurityAlert` | Incident/alert trends, tagged BEC/phishing/AiTM. |
| **Microsoft Defender XDR** | `AlertInfo`, `AlertEvidence` | XDR alerts & attack-chain evidence. |
| **Microsoft Entra ID** | `SigninLogs`, `AADNonInteractiveUserSignInLogs`, `IdentityInfo` | AiTM email→sign-in correlation, risky sign-ins. |
| **M365 Defender Advanced Hunting** | Teams messages / URLs / post-delivery / calls, collaboration file malware, campaigns | 🔍 Advanced Hunting tab — requires the M365D streaming connector or the AH endpoint. |

> **V2 change:** `OfficeActivity` was removed in this version; mailbox-rule / forwarding
> signals are now sourced from Defender XDR and email telemetry. Tiles use graceful
> patterns so a missing table renders empty rather than erroring.

---

## Deploy / import

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `DefenderForOffice365-BEC-AiTM-Workbook-V2.json` and **Apply**.
3. **Done Editing** → **Save**, name it *DfO365 — BEC & AiTM Threat Hunting*, and pick
   your resource group / workspace.
4. Set **Workspace** and **Time Range**, then work the tabs. Use **Investigate User /
   Domain** on the 🔎 Investigation tab for pivots.

---

## Notes

- **Read-only.** The workbook only queries logs; it changes no mail-flow or policy.
- **Time-of-click** tiles reflect Safe Links re-detonation across Outlook, Teams, and
  Office clients.
- **Priority-account** and impersonation tiles depend on your Defender for Office 365
  priority-account and impersonation-protection configuration.
- **Advanced Hunting tab** needs M365 Defender tables streamed to the workspace (or run
  those queries directly in the Defender Advanced hunting endpoint).
