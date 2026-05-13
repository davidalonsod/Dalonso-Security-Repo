# M365 Office Activity — Custom Detections Package

> **Workspace:** `LAWSentinel`
> **Created:** March 16, 2026
> **Status:** Production-ready (ARM template validated — 30 analytic rules · 26 hunting queries)
> **Primary table:** `OfficeActivity` · Secondary: `SigninLogs`, `ThreatIntelligenceIndicator`

Custom Microsoft Sentinel analytic rules and hunting queries covering the full **Microsoft 365 OfficeActivity** audit log surface: **Teams**, **Exchange Online**, **SharePoint**, **OneDrive**, and **Compliance Center**. All rules are designed not to duplicate confirmed Microsoft-built-in detections and are grounded in live table schemas.

> **Companion repository:** [WorkloadIdentitiesDetections](../WorkloadIdentitiesDetections) — Service Principal and Managed Identity detections using `AADServicePrincipalSignInLogs` / `AADManagedIdentitySignInLogs`. Together the two repositories cover the full Microsoft 365 + Azure identity and data-plane attack surface.

---

## Table of Contents

- [Folder Structure](#folder-structure)
- [Prerequisites](#prerequisites)
- [Threat Actor Coverage: Storm-0558](#threat-actor-coverage-storm-0558)
- [Analytic Rules Reference](#analytic-rules-reference)
- [Hunting Queries Reference](#hunting-queries-reference)
- [MITRE ATT&CK Coverage Matrix](#mitre-attck-coverage-matrix)
- [Deployment Guide](#deployment-guide)
- [Detection Design Principles](#detection-design-principles)

---

## Folder Structure

```
M365OfficeActivity/
├── README.md                                          ← This file
├── ARM-Template/
│   └── M365OfficeActivity-Detections.json            ← Deploy all 30 rules at once
├── Watchlists/                                        ← Trusted-IP allowlist + scheduled sync
│   ├── azuredeploy-automation.bicep                  ← Automation Account + SP-auth Runbook
│   ├── Sync-NamedLocationsToWatchlist.ps1            ← Pulls Entra Named Locations → watchlist
│   └── README.md
├── AnalyticRules/                                     ← 30 scheduled analytic rules
│   ├── RULE-01_M365-Teams-GuestInvite-Bulk.kql
│   ├── RULE-02_M365-Teams-GuestActivity-SensitiveChannel.kql
│   ├── RULE-03_M365-Teams-SuspiciousApp-Installed.kql
│   ├── RULE-04_M365-Exchange-InboxRule-ForwardOrHide.kql
│   ├── RULE-05_M365-Exchange-MailboxDelegate-Anomaly.kql
│   ├── RULE-06_M365-Exchange-MassEmailDownload.kql
│   ├── RULE-07_M365-SharePoint-SensitivityLabel-Downgraded.kql
│   ├── RULE-08_M365-SharePoint-MassFileDownload.kql
│   ├── RULE-09_M365-SharePoint-AnonymousLink-SensitiveFile.kql
│   ├── RULE-10_M365-OneDrive-RansomwareLike-Behavior.kql
│   ├── RULE-11_M365-DLP-HighVolume-SensitiveMatch.kql
│   ├── RULE-12_M365-DLP-PolicyOverride-Abuse.kql
│   ├── RULE-13_M365-SharePoint-SiteAdmin-Added.kql
│   ├── RULE-14_M365-Exchange-TransportRule-Manipulation.kql
│   ├── RULE-15_M365-Teams-Bulk-Delete-Channels-Teams.kql
│   ├── RULE-16_M365-OneDrive-ExternalShare-NewDomain.kql
│   ├── RULE-17_M365-Exchange-FullAccess-DelegateGranted.kql
│   ├── RULE-18_M365-Guest-OffHours-FileAccess.kql
│   ├── RULE-19_M365-Exchange-PhishingCampaign-MultiUser.kql
│   ├── RULE-20_M365-CrossWorkload-Exfiltration-Chain.kql
│   ├── RULE-21_M365-Exchange-BEC-MultiMailbox-SameDest.kql
│   ├── RULE-22_M365-Compliance-ContentSearch-NonAdmin.kql
│   ├── RULE-23_M365-SharePoint-AnonymousLink-Accessed.kql
│   ├── RULE-24_M365-Activity-ThreatIntel-IP-Match.kql
│   ├── RULE-25_M365-RiskySignIn-FileDownload-Correlation.kql
│   ├── RULE-26_M365-Teams-MassMessage-Deletion.kql
│   ├── RULE-27_M365-SuspiciousFileExtension-Upload.kql
│   ├── RULE-28_M365-MassDeletion-AllWorkloads.kql
│   ├── RULE-29_M365-MalwareFile-Detected.kql
│   └── RULE-30_M365-DataExfiltration-USB-EndpointDLP.kql
└── HuntingQueries/                                    ← 26 proactive hunting queries
    ├── HUNT-01_M365-Teams-Guest-Invitation-History-90d.kql
    ├── HUNT-02_M365-Exchange-InboxTransportRule-Audit-30d.kql
    ├── HUNT-03_M365-SensitivityLabel-Change-History-90d.kql
    ├── HUNT-04_M365-DLP-Violations-PerUser-30d.kql
    ├── HUNT-05_M365-SharePoint-ExternalSharing-Audit-30d.kql
    ├── HUNT-06_M365-OneDrive-Stale-Guest-Access-90d.kql
    ├── HUNT-07_M365-Teams-Apps-Bots-Installed-90d.kql
    ├── HUNT-08_M365-Exchange-MailboxPermission-Audit-30d.kql
    ├── HUNT-09_M365-OneDrive-TopDownloaders-30d.kql
    ├── HUNT-10_M365-SharePoint-AdminPermission-Audit-90d.kql
    ├── HUNT-11_M365-Teams-Guest-MessageLinks-30d.kql
    ├── HUNT-12_M365-OneDrive-Deleted-Files-Timeline-30d.kql
    ├── HUNT-13_M365-CrossWorkload-UserActivity-Timeline-30d.kql
    ├── HUNT-14_M365-Exchange-BEC-MultiMailbox-Forward-Map-30d.kql
    ├── HUNT-15_M365-Compliance-eDiscovery-FullAudit-90d.kql
    ├── HUNT-16_M365-ThreatIntel-IP-Correlation-30d.kql
    ├── HUNT-17_M365-Guest-CrossWorkload-Profile-90d.kql
    ├── HUNT-18_M365-InactiveUser-ActivePermissions-90d.kql
    ├── HUNT-19_M365-DormantUser-ActivityBurst-90d.kql
    ├── HUNT-20_M365-Guest-ElevatedPermissions-90d.kql
    ├── HUNT-21_M365-InactiveHumanUsers-NullActivity-90d.kql
    ├── HUNT-22_M365-Guest-Dormancy-Reactivation-30d.kql
    ├── HUNT-23_M365-AgentID-AppAccess-Profile-30d.kql
    ├── HUNT-24_M365-Copilot-HighVolume-OffHours-30d.kql
    ├── HUNT-25_M365-Copilot-SensitiveContent-BulkAccess-30d.kql
    └── HUNT-26_M365-Copilot-XPIA-Jailbreak-Detections-30d.kql
```

---

## Prerequisites

| Requirement | Details |
|---|---|
| Microsoft Sentinel | Connected to `LAWSentinel` workspace |
| M365 Audit Logging | **Unified Audit Log** enabled in Microsoft 365 Compliance Center |
| Data connector | **Microsoft 365** connector in Sentinel (streams `OfficeActivity`) |
| Workloads enabled | Exchange Online, SharePoint, OneDrive, Microsoft Teams audit events |
| Tables required (core) | `OfficeActivity` |
| Tables required (RULE-24, HUNT-16) | `ThreatIntelligenceIndicator` — requires Threat Intelligence connector + active TI feeds |
| Tables required (RULE-25) | `SigninLogs` — requires Azure Active Directory connector |
| Tables required (RULE-30) | `OfficeActivity` with `RecordType = ComplianceDLPEndpoint` — requires **Microsoft Purview Endpoint DLP** enabled and MDE onboarded devices |
| Licensing | Microsoft 365 E3 or higher for full audit log retention; E5 for Advanced Audit (`MailItemsAccessed`) |
| Permissions (deploy) | Microsoft Sentinel Contributor + Log Analytics Contributor |
| ARM API version | `2023-02-01-preview` |

> **Advanced Audit note:** `MailItemsAccessed` events (used in RULE-05, RULE-06) require **Microsoft 365 E5** or the **Microsoft 365 E5 Compliance / E5 eDiscovery and Audit** add-on. Without E5, these operations do not appear in the audit log and the corresponding rules will return no results.

---

## Threat Actor Coverage: Storm-0558

**Storm-0558** (also tracked as Antique Typhoon) is a China-based threat actor known primarily for **token forgery attacks** against Microsoft cloud environments, most notably the 2023 breach of US federal agency email accounts via a forged MSA signing key. The package provides detection signals for several of their known TTPs.

### TTP Mapping

| Storm-0558 TTP | Technique | Coverage in this repo | Rule / Hunt |
|---|---|---|---|
| Forged token used to access Exchange via EWS/OWA | T1550.001, T1528 | **Partial** — anomalous `MailItemsAccessed` with new delegate pair | RULE-05 |
| Stealthy incremental mailbox access (EWS API, avoid bulk patterns) | T1114.002 | **Covered** — new delegate pair baseline; access volume anomaly | RULE-05, RULE-06 |
| Atypical `AppId` in `MailItemsAccessed` events | T1550.001 | **Covered** — delegate anomaly detects previously-unseen accessor identities | RULE-05 |
| Mailbox access by `MailItemsAccessed` spike | T1114.001 | **Covered** — mass email download / access threshold | RULE-06 |
| VPN / proxy IPs associated with Storm-0558 infrastructure | Indicator matching | **Covered** — ThreatIntelligenceIndicator join on all M365 ClientIPs | RULE-24, HUNT-16 |
| Cross-workload access after initial email compromise | T1530, T1114 | **Covered** — cross-workload exfiltration correlation | RULE-20, RULE-25 |
| Risky sign-in followed by file or mail access spike | T1078.004 | **Covered** — risky sign-in + download correlation | RULE-25 |
| Inbox rule created to forward or hide mail (post-compromise persistence) | T1114.003 | **Covered** | RULE-04, RULE-21 |
| FullAccess delegate granted to attacker-controlled identity | T1098.002 | **Covered** | RULE-17 |
| Multiple mailboxes targeted from same infrastructure | T1114.003 | **Covered** | RULE-21, HUNT-14 |

### Multi-Modal Social Engineering / Vishing Phase (Volt Typhoon / Storm-1811 overlap techniques)

The request also references the **email bombing + Teams IT support impersonation + Quick Assist** technique (attributed to Storm-1811 and observed in conjunction with Storm-0558 operations). Coverage map:

| TTP | Coverage | Notes |
|---|---|---|
| Email bombing (inbox flood to trigger urgency) | **Partial** — DLP volume spike on inbound | RULE-11 detects volume anomalies; direct email-flood-as-tactic is not surfaced by `OfficeActivity` |
| Teams message from external/guest posing as IT support | **Covered** — guest activity in channels | RULE-02 (guest in sensitive channels), RULE-18 (guest off-hours) |
| Mass Teams invite to gain channel access foothold | **Covered** | RULE-01 (bulk guest invite) |
| Teams message containing suspicious external URL (phishing link) | **Covered** | RULE-26 context; HUNT-11 (guest message links) |
| Quick Assist / remote access tool installation | ⚠️ **Not covered here** | Requires `DeviceEvents` or `SecurityEvent` — out of scope for `OfficeActivity` layer |
| DLL side-loading of A0Backdoor as Teams component | ⚠️ **Not covered here** | Requires `DeviceFileEvents`, `DeviceImageLoadEvents` — endpoint telemetry scope |

> **Recommendation for complete Storm-0558 / Storm-1811 coverage:** Complement this package with endpoint detection rules on `DeviceEvents` tables to detect Quick Assist abuse (`quickassist.exe` spawning unexpected child processes) and DLL side-loading patterns (`MicrosoftTeams.exe` loading unsigned DLLs from non-standard paths). Token-forgery detection at the authentication layer is best addressed by the companion [WorkloadIdentitiesDetections](../WorkloadIdentitiesDetections) repository (RULE-03: Token Replay MultiIP, RULE-14: Risky Auth Flow).

---

## Analytic Rules Reference

Rules are scheduled Sentinel analytic rules with full ARM template deployment support, custom entity mappings, alert name/description overrides, and incident grouping configured.

### Microsoft Teams

| Rule | Description | Severity | Freq | MITRE |
|---|---|---|---|---|
| [RULE-01](AnalyticRules/RULE-01_M365-Teams-GuestInvite-Bulk.kql) | **Bulk Guest User Invitation** — Single user invites ≥10 external guests in 1 hour. Escalates to High at ≥30. | Medium | PT1H | T1136.003, T1078 |
| [RULE-02](AnalyticRules/RULE-02_M365-Teams-GuestActivity-SensitiveChannel.kql) | **Guest Activity in Sensitive Channel** — `#EXT#` user sends messages or shares files in channels matching sensitive naming (finance, legal, security, board, etc.). | Medium | PT1H | T1213.003, T1537 |
| [RULE-03](AnalyticRules/RULE-03_M365-Teams-SuspiciousApp-Installed.kql) | **Suspicious Bot or App Installed** — App name matches known post-exploitation patterns (ngrok, webhook, tunnel, shell, forward, proxy). | Medium | PT1H | T1546, T1059 |
| [RULE-15](AnalyticRules/RULE-15_M365-Teams-Bulk-Delete-Channels-Teams.kql) | **Bulk Channel / Team Deletion** — ≥3 delete operations in 1 hour, or any `TeamDeleted` / `TeamArchived` event. | Medium | PT1H | T1485, T1070 |
| [RULE-26](AnalyticRules/RULE-26_M365-Teams-MassMessage-Deletion.kql) | **Mass Channel Message Deletion** — ≥30 `MessageDeleted` events or any `MessageDeletedAll` / `MessageHardDeletedAll` (bulk API) in 30 min. Evidence removal signal. | High | PT30M | T1070, T1485 |

### Exchange Online

| Rule | Description | Severity | Freq | MITRE |
|---|---|---|---|---|
| [RULE-04](AnalyticRules/RULE-04_M365-Exchange-InboxRule-ForwardOrHide.kql) | **Inbox Rule for Forwarding or Hiding** — Detects `New-InboxRule` / `Set-InboxRule` with ForwardTo, RedirectTo, or folder-hiding (deleted items, RSS feeds, junk) parameters. External destination = High. | High | PT1H | T1114.003, T1564.008 |
| [RULE-05](AnalyticRules/RULE-05_M365-Exchange-MailboxDelegate-Anomaly.kql) | **Mailbox Accessed by Unusual Delegate** — `MailboxOwnerUPN ≠ UserId` pair not seen in 14-day baseline. Covers EWS / OWA API access by atypical `AppId` patterns. | High | PT1H | T1114.002, T1078 |
| [RULE-06](AnalyticRules/RULE-06_M365-Exchange-MassEmailDownload.kql) | **Mass Email Download or Export** — ≥200 `MailItemsAccessed` / `MessageViewed` operations, or any `New-MailboxExportRequest` / `New-ComplianceSearchAction` in 1 hour. | High | PT1H | T1114.001, T1530 |
| [RULE-14](AnalyticRules/RULE-14_M365-Exchange-TransportRule-Manipulation.kql) | **Transport Rule Modified** — `New-TransportRule` / `Set-TransportRule` with forwarding, redirect, or external-domain destination. Bypasses DLP for in-transit mail. | High | PT1H | T1114.003, T1036 |
| [RULE-17](AnalyticRules/RULE-17_M365-Exchange-FullAccess-DelegateGranted.kql) | **FullAccess or SendAs Delegate Granted** — `Add-MailboxPermission` granting FullAccess / SendAs, especially to `#EXT#` guests or on executive/sensitive mailboxes. Guest + FullAccess = Critical. | High | PT1H | T1098.002, T1114 |
| [RULE-19](AnalyticRules/RULE-19_M365-Exchange-PhishingCampaign-MultiUser.kql) | **Phishing Campaign (Multi-User Reports Same Sender)** — ≥3 distinct users report the same sender within 30 min — active campaign signal. | High | PT30M | T1566 |
| [RULE-21](AnalyticRules/RULE-21_M365-Exchange-BEC-MultiMailbox-SameDest.kql) | **BEC Campaign: Multiple Mailboxes → Same External Forward** — ≥3 mailboxes with forwarding rules pointing to the same external address within 24 hours. BEC campaign infrastructure detection. | High | PT1H | T1114.003 |
| [RULE-22](AnalyticRules/RULE-22_M365-Compliance-ContentSearch-NonAdmin.kql) | **eDiscovery / Compliance Content Search Initiated** — Dedicated detection for `SecurityComplianceCenter` events: `SearchCreated`, `SearchExported`, `AuditLogSearchStarted`, etc. Any export action = High. Attackers use these to collect data tenant-wide. | Medium | PT1H | T1213.003, T1119 |

### SharePoint Online

| Rule | Description | Severity | Freq | MITRE |
|---|---|---|---|---|
| [RULE-07](AnalyticRules/RULE-07_M365-SharePoint-SensitivityLabel-Downgraded.kql) | **Sensitivity Label Downgraded or Removed** — `SensitivityLabelRemoved` or label changed to lower classification (e.g., Confidential → Public). Exfiltration staging signal. | High | PT1H | T1565.001, T1078 |
| [RULE-08](AnalyticRules/RULE-08_M365-SharePoint-MassFileDownload.kql) | **Mass File Download (Baseline-Aware)** — Current-hour downloads exceed 3× 14-day per-user baseline or absolute threshold of 100 files. | High | PT1H | T1530, T1537 |
| [RULE-09](AnalyticRules/RULE-09_M365-SharePoint-AnonymousLink-SensitiveFile.kql) | **Anonymous Sharing Link Created on Sensitive File** — `AnonymousLinkCreated` / `SharingLinkCreated` on files in sensitive-named sites (HR, finance, legal, board). Anonymous + sensitive site = Critical. | High | PT1H | T1567.002, T1078 |
| [RULE-13](AnalyticRules/RULE-13_M365-SharePoint-SiteAdmin-Added.kql) | **Site Collection Administrator Added** — `SiteCollectionAdminAdded` or Full Control granted, especially on sensitive sites or to guest accounts. Guest + admin = Critical. | High | PT1H | T1098, T1078 |
| [RULE-23](AnalyticRules/RULE-23_M365-SharePoint-AnonymousLink-Accessed.kql) | **Anonymous Link Actively Accessed (Data Made Public)** — Distinct from RULE-09 (creation). Triggers on `AnonymousLinkUsed` / `FileAccessedAnonymously`: ≥10 accesses/hour or ≥5 distinct IPs on same file — data harvesting via leaked link. | High | PT1H | T1567.002, T1530 |

### OneDrive for Business

| Rule | Description | Severity | Freq | MITRE |
|---|---|---|---|---|
| [RULE-10](AnalyticRules/RULE-10_M365-OneDrive-RansomwareLike-Behavior.kql) | **Ransomware-Like File Replacement** — ≥50 `FileDeleted`/`FileVersionsAllDeleted` ops or upload of files with known ransom extensions (.locked, .wncry, .crypted, etc.) in 30 min. | High | PT30M | T1486 |
| [RULE-16](AnalyticRules/RULE-16_M365-OneDrive-ExternalShare-NewDomain.kql) | **External Sharing Spike to New Domains** — Files shared with external domains not seen in 14-day baseline; ≥10 shares or ≥3 new domains in 1 hour. | High | PT1H | T1567.002 |

### DLP & Information Protection

| Rule | Description | Severity | Freq | MITRE |
|---|---|---|---|---|
| [RULE-11](AnalyticRules/RULE-11_M365-DLP-HighVolume-SensitiveMatch.kql) | **DLP High Volume or High-Sensitivity Match** — ≥20 DLP matches/hour or any match for Credit Card, SSN, Passport, Medical data types across Exchange, SharePoint, OneDrive. | High | PT1H | T1537, T1567 |
| [RULE-12](AnalyticRules/RULE-12_M365-DLP-PolicyOverride-Abuse.kql) | **DLP Policy Override Abuse** — ≥3 DLP block overrides per user per hour with justification text. Repeat offenders for sensitive data types. | Medium | PT1H | T1222, T1537 |
| [RULE-30](AnalyticRules/RULE-30_M365-DataExfiltration-USB-EndpointDLP.kql) | **Data Exfiltration to USB / Removable Media (Endpoint DLP)** — Detects Microsoft Purview Endpoint DLP events for `CopyToUsbDrive` / `CopyToRemovableMedia`. Severity escalates for high-sensitivity types (SSN, credit card, IBAN). Requires Endpoint DLP enabled. | High | PT30M | T1052.001, T1074.001 |

### Guest Users

| Rule | Description | Severity | Freq | MITRE |
|---|---|---|---|---|
| [RULE-18](AnalyticRules/RULE-18_M365-Guest-OffHours-FileAccess.kql) | **Guest File Access During Off-Hours** — `#EXT#` accounts accessing SharePoint/OneDrive files between 22:00–06:00 UTC with ≥20 accesses/hour. | Medium | PT1H | T1530, T1078 |

### Cross-Workload Correlation

| Rule | Description | Severity | Freq | MITRE |
|---|---|---|---|---|
| [RULE-20](AnalyticRules/RULE-20_M365-CrossWorkload-Exfiltration-Chain.kql) | **Cross-Workload Exfiltration Chain** — User simultaneously triggers suspicious activity in ≥2 workloads (OneDrive downloads + Exchange mailbox access + Teams file sharing) within 1 hour. Multi-vector = highest confidence. | High | PT1H | T1530, T1537, T1114 |
| [RULE-24](AnalyticRules/RULE-24_M365-Activity-ThreatIntel-IP-Match.kql) | **Office Activity from ThreatIntel-Known Malicious IP** — Joins `ThreatIntelligenceIndicator` against all M365 ClientIPs. Flags any workload activity from active TI IOCs — known actor logins, C2 infrastructure. | High | PT1H | T1078, T1530 |
| [RULE-25](AnalyticRules/RULE-25_M365-RiskySignIn-FileDownload-Correlation.kql) | **Risky Sign-In + File Download Spike Correlation** — Joins `SigninLogs` (medium/high risk or `confirmedCompromised`) with same-user OneDrive/SharePoint download spike ≥20 files in same hour. Same IP in both = Critical. | High | PT1H | T1078, T1530 |
| [RULE-27](AnalyticRules/RULE-27_M365-SuspiciousFileExtension-Upload.kql) | **Suspicious File Extension Uploaded (Executable / Script)** — Any upload of `.exe`, `.dll`, `.ps1`, `.bat`, `.vbs`, `.jar`, `.msi`, and 15+ other high-risk extensions to SharePoint, OneDrive, or Teams. Three risk tiers (binary, script, installer). | High | PT1H | T1105, T1566.002, T1204.002 |
| [RULE-28](AnalyticRules/RULE-28_M365-MassDeletion-AllWorkloads.kql) | **Massive Deletion Across All Workloads** — ≥50 hard-deletes or ≥200 total deletions (files, folders, email, Teams messages) in a 30-minute window by a single user. Covers ransomware staging, insider sabotage, post-exfiltration cleanup. | High | PT30M | T1485, T1070.004 |
| [RULE-29](AnalyticRules/RULE-29_M365-MalwareFile-Detected.kql) | **Malware File Detected by ATP (SharePoint / OneDrive / Teams)** — Every `FileMalwareDetected` / `VirusDetected` event from M365 ATP Safe Attachments. No volume threshold — any single detection fires. Severity escalates when the uploader is a guest or same malware seen across multiple users. | High | PT15M | T1566, T1105, T1204.002 |

---

## Hunting Queries Reference

Long-period queries designed to be run manually or on a schedule during threat hunts and incident investigations.

| Hunt | Description | Period | Primary Use Case |
|---|---|---|---|
| [HUNT-01](HuntingQueries/HUNT-01_M365-Teams-Guest-Invitation-History-90d.kql) | **Teams Guest Invitation History** — All guest invites by user and domain, invite count, teams involved. | 90d | Insider threat, shadow IT, BEC staging |
| [HUNT-02](HuntingQueries/HUNT-02_M365-Exchange-InboxTransportRule-Audit-30d.kql) | **Inbox & Transport Rule Audit** — All rule create/modify/delete ops with forwarding, redirect, and hide indicators pre-computed. | 30d | BEC, exfiltration path reconstruction |
| [HUNT-03](HuntingQueries/HUNT-03_M365-SensitivityLabel-Change-History-90d.kql) | **Sensitivity Label Change Full History** — All upgrades, downgrades, and removals with justification text, auto-label flag. | 90d | Compliance audit, exfiltration staging |
| [HUNT-04](HuntingQueries/HUNT-04_M365-DLP-Violations-PerUser-30d.kql) | **DLP Violations & Overrides Per User** — Ranked by total violations, overrides, blocks; policy and sensitive-type breakdown. | 30d | Repeat-offender identification, insider threat |
| [HUNT-05](HuntingQueries/HUNT-05_M365-SharePoint-ExternalSharing-Audit-30d.kql) | **SharePoint External Sharing Full Audit** — All sharing events with domain classification, file types, anonymous link count. | 30d | Exfiltration path reconstruction |
| [HUNT-06](HuntingQueries/HUNT-06_M365-OneDrive-Stale-Guest-Access-90d.kql) | **Stale Guest Access (No Activity After Invite)** — Guests invited but inactive for ≥30 days. Unrevoked attack surface. | 90d | Access review, guest offboarding |
| [HUNT-07](HuntingQueries/HUNT-07_M365-Teams-Apps-Bots-Installed-90d.kql) | **Teams Bots & Apps Installed Inventory** — All installed apps with publisher, installer, teams affected, suspicious-name flag. | 90d | Shadow IT discovery, persistence review |
| [HUNT-08](HuntingQueries/HUNT-08_M365-Exchange-MailboxPermission-Audit-30d.kql) | **Mailbox Permission Audit** — All FullAccess / SendAs grants and removals; external delegate and sensitive mailbox flags. | 30d | BEC, privilege escalation, access review |
| [HUNT-09](HuntingQueries/HUNT-09_M365-OneDrive-TopDownloaders-30d.kql) | **Top File Downloaders / Uploaders** — Ranked by downloads; download/upload ratio; site and IP breakdown. | 30d | Insider threat, data hoarding |
| [HUNT-10](HuntingQueries/HUNT-10_M365-SharePoint-AdminPermission-Audit-90d.kql) | **SharePoint Admin & Permission Changes** — Site collection admin grants, full-control assignments, group membership changes; guest and sensitive-site flags. | 90d | Privilege escalation, compliance audit |
| [HUNT-11](HuntingQueries/HUNT-11_M365-Teams-Guest-MessageLinks-30d.kql) | **Guest Messages with External Links** — Guest `#EXT#` accounts sending Teams messages containing URL shorteners, ngrok, pastebin, or tunneling service domains. | 30d | Phishing link distribution, C2 |
| [HUNT-12](HuntingQueries/HUNT-12_M365-OneDrive-Deleted-Files-Timeline-30d.kql) | **OneDrive Deleted Files Timeline** — All file and version deletions ranked by user; permanent vs. recycle-bin distinction; extension breakdown. | 30d | Ransomware impact assessment, sabotage |
| [HUNT-13](HuntingQueries/HUNT-13_M365-CrossWorkload-UserActivity-Timeline-30d.kql) | **Cross-Workload User Activity Timeline** — Unified per-user activity summary across all M365 workloads. Set `TargetUser` to investigate a specific UPN. | 30d | Incident investigation, full-scope forensics |
| [HUNT-14](HuntingQueries/HUNT-14_M365-Exchange-BEC-MultiMailbox-Forward-Map-30d.kql) | **BEC Campaign Infrastructure Map** — Groups all external forwarding destinations; destinations receiving from ≥2 source mailboxes ranked first. Reveals campaign collection addresses. | 30d | BEC campaign scoping, IOC extraction |
| [HUNT-15](HuntingQueries/HUNT-15_M365-Compliance-eDiscovery-FullAudit-90d.kql) | **eDiscovery & Compliance Activity Full Audit** — Start → export → purge chains; audit-log self-review; all compliance center actions per user. | 90d | Insider threat, compromised admin |
| [HUNT-16](HuntingQueries/HUNT-16_M365-ThreatIntel-IP-Correlation-30d.kql) | **ThreatIntelligence IP Retroactive Correlation** — "Did this known-bad IP ever touch the tenant?" — joins all 30-day M365 activity against active TI indicators. | 30d | Retroactive TI sweep, post-IOC-publish hunt |
| [HUNT-17](HuntingQueries/HUNT-17_M365-Guest-CrossWorkload-Profile-90d.kql) | **Guest User Complete Cross-Workload Profile** — Full risk profile for every guest (`#EXT#`): workloads accessed, distinct sites, exfiltration op ratio, after-hours activity, free-email domain flag, computed risk score. | 90d | Guest access review, insider threat, overprivileged guests |
| [HUNT-18](HuntingQueries/HUNT-18_M365-InactiveUser-ActivePermissions-90d.kql) | **Inactive Users Holding Active Mailbox or SharePoint Permissions** — Internal users with FullAccess / SendAs delegations or SharePoint admin roles but zero or very low OfficeActivity in 60+ days. | 90d | Access review, privilege hygiene, dormant account risk |
| [HUNT-19](HuntingQueries/HUNT-19_M365-DormantUser-ActivityBurst-90d.kql) | **Dormant User Sudden Activity Burst** — Internal users silent for 30–90 days who then generate a burst of ≥5 events in the last 30 days. Surfaces exfil ratio, after-hours count, and site spread of the burst. | 90d | Account compromise, identity reactivation, credential stuffing |
| [HUNT-20](HuntingQueries/HUNT-20_M365-Guest-ElevatedPermissions-90d.kql) | **Guests with Elevated Permissions (SharePoint Admin / Mailbox Delegate)** — External guest accounts granted SharePoint site admin or Exchange FullAccess / SendAs. Includes post-elevation activity profile and risk score. | 90d | Guest overprivilege, insider threat, access review |
| [HUNT-21](HuntingQueries/HUNT-21_M365-InactiveHumanUsers-NullActivity-90d.kql) | **Inactive Human Users — No M365 Activity (90d)** — Internal user accounts (not guests, not service accounts) with prior activity that have produced zero OfficeActivity in 90 days. Categorised as Abandoned / Dormant / Fading. | 180d | Dormant account hygiene, credential-stuffing risk, access review |
| [HUNT-22](HuntingQueries/HUNT-22_M365-Guest-Dormancy-Reactivation-30d.kql) | **Guest Dormancy → Reactivation Pattern** — Guest accounts silent during a 30–90 day window that suddenly generate activity in the last 7 days. Includes exfil ratio, after-hours count, and risk score for the burst period. | 90d | Compromised guest credential, forgotten account reuse |
| [HUNT-23](HuntingQueries/HUNT-23_M365-AgentID-AppAccess-Profile-30d.kql) | **Agent / AppID Anomalous Access Profile** — Profiles all M365 access by OAuth `AppId` (agents, connectors, Copilot agents, custom scripts). Surfaces apps with high exfil ratios, after-hours bulk access, high guest-op ratios, or wide site spread. Does NOT cover service principal sign-ins (see WorkloadIdentitiesDetections). | 30d | OAuth app abuse, shadow IT agents, delegated access review |
| [HUNT-24](HuntingQueries/HUNT-24_M365-Copilot-HighVolume-OffHours-30d.kql) | **Copilot High-Volume and Off-Hours Anomalies** — Per-user profile of `CopilotInteraction` volume vs. the tenant median, off-hours / weekend share, and source IP diversity. Flags users whose Copilot usage is statistically anomalous in volume or timing. Guest accounts with high Copilot activity receive extra risk weight. | 30d | AI-assisted data exfiltration, insider threat, credential sharing |
| [HUNT-25](HuntingQueries/HUNT-25_M365-Copilot-SensitiveContent-BulkAccess-30d.kql) | **Copilot Bulk or Sensitive-Labeled File Access** — Expands the `Contexts` array from each Copilot interaction to enumerate every file, email, and page Copilot read. Flags users by sensitivity label hits (Confidential, Highly Confidential, etc.) and by bulk-prompt patterns (≥5 resources per single interaction). Returns sample resource IDs for investigation. | 30d | Data exfiltration via AI, over-privileged Copilot usage, sensitive-data enumeration |
| [HUNT-26](HuntingQueries/HUNT-26_M365-Copilot-XPIA-Jailbreak-Detections-30d.kql) | **Copilot XPIA and Jailbreak Threat Detections** — Surfaces Copilot interactions where Microsoft's Prompt Shield or AI safety layer recorded a threat signal: XPIA (Cross-Plugin Injection Attack — malicious instructions embedded in accessed documents that try to hijack Copilot's output), jailbreak prompts (user attempts to override safety guardrails), or other threat categories (HarmfulContent, InsecureOutput). Results grouped per user with raw threat metadata, context URLs of involved documents, and full WhySuspicious explanation. | 30d | AI prompt injection, XPIA, jailbreak abuse, data exfiltration via AI agent |

---

## MITRE ATT&CK Coverage Matrix

| Tactic | Techniques Covered |
|---|---|
| **Initial Access** | T1566.001/2 (Phishing), T1078.004 (Cloud Accounts), T1105 (Ingress Tool Transfer), T1204.002 (Malicious File Execution) |
| **Persistence** | T1136.003 (Cloud Account Creation), T1098 (Account Manipulation), T1098.002 (Email Delegate) |
| **Privilege Escalation** | T1098, T1078.004 |
| **Defense Evasion** | T1564.008 (Email Hiding Rules), T1070 (Indicator Removal), T1222 (Permission Modification), T1565.001 (Stored Data Manipulation) |
| **Collection** | T1114.001/2/3 (Email Collection), T1213.003 (Information Repositories), T1119 (Automated Collection), T1530 (Cloud Storage) |
| **Exfiltration** | T1537 (Transfer to Cloud), T1567.002 (Exfiltration via Web Service), T1052.001 (Exfiltration over USB) |
| **Impact** | T1485 (Data Destruction), T1486 (Data Encrypted for Impact) |
| **Execution** | T1059 (Command and Scripting) |
| **Lateral Movement** | T1550.001 (Application Access Token — via cross-workload correlation) |
| **AI / LLM Abuse** | T1059 (LLM-as-execution-layer via XPIA), T1119 (Automated Collection via Copilot), T1530 (Cloud Storage via Copilot), T1204.002 (XPIA via malicious document), T1213.003 (Information Repositories via Copilot bulk access) |

---

## Deployment Guide

### Network Allowlist Watchlist (false-positive suppression)

All 30 rules now call a KQL function `ExcludeAllowlistedIPs()` that filters
out IPs / CIDRs / IPv4 ranges defined in the `NetworkAllowlist` Sentinel
watchlist (e.g. corporate egress, VPN concentrators, known-good SaaS).
The watchlist and the function are deployed automatically by the ARM
template. The function is `OfficeActivity`-aware: it strips the optional
port suffix from `ClientIP` (`1.2.3.4:443` → `1.2.3.4`) before comparison.

To keep the watchlist in sync with Entra ID Named Locations, deploy the
scheduled runbook described in [`Watchlists/README.md`](Watchlists/README.md).

### New ARM template parameters

| Parameter | Default | Purpose |
|---|---|---|
| `workspaceName` | `LAWSentinel` | Sentinel workspace name. |
| `location` | `[resourceGroup().location]` | Region. |
| `enableAnalyticRules` | `true` | If `false`, all 30 rules deploy in **disabled** state for staged rollout. |
| `watchlistAlias` | `NetworkAllowlist` | Alias of the trusted-IP exclusion watchlist. |
| `functionAlias` | `ExcludeAllowlistedIPs` | KQL `savedSearches` alias for the filter function. |
| `watchlistRawContent` | empty (seed RFC1918) | Override CSV content (CRLF-separated; header `IPOrRange,Description,Owner,AddedDate`). Leave empty to use the built-in default; the daily sync runbook then replaces the content with Entra Named Locations. |

### Threshold tuning (May 2026)

To reduce noise in production, the following analytic-rule thresholds were
raised ~2-3x from initial values. Override via the rule editor in Sentinel
after deployment if your tenant needs tighter / looser settings.

| Rule | Threshold | Old → New |
|---|---|---|
| RULE-01 Teams Bulk Guest Invitation | `BulkThreshold` | 10 → **20** |
| RULE-06 Exchange Mass Email Download | `MassDownloadThreshold` | 200 → **500** |
| RULE-08 SharePoint Mass File Download | `AbsoluteThreshold` | 100 → **250** |
| RULE-10 OneDrive Ransomware-Like | `MassDeleteThreshold` | 50 → **150** |
| RULE-11 DLP High Volume | `DLPThreshold` | 20 → **50** |
| RULE-12 DLP Policy Override Abuse | `OverrideThreshold` | 3 → **5** |
| RULE-15 Teams Bulk Channel/Team Delete | `BulkDeleteThreshold` | 3 → **5** |
| RULE-16 OneDrive External Share Spike | `SharingThreshold` | 10 → **25** |
| RULE-18 Guest Off-Hours File Access | `AccessThreshold` | 20 → **50** |
| RULE-19 Exchange Phishing Campaign | `UniqueUserThreshold` | 3 → **5** |
| RULE-21 Exchange BEC Multi-Mailbox | `MailboxThreshold` | 3 → **5** |
| RULE-23 SharePoint Anonymous Link Accessed | `AnonymousAccessThreshold` | 10 → **25** |
| RULE-25 Risky Sign-In + File Download | `DownloadThreshold` | 20 → **50** |
| RULE-26 Teams Mass Message Deletion | `MsgDeleteThreshold` | 30 → **75** |
| RULE-28 Massive Deletion All Workloads | `HardDeleteThreshold` / `SoftDeleteThreshold` | 50/200 → **150/500** |

### Staged deployment

```powershell
# Stage 1 - deploy disabled for review
az deployment group create -g <rg> `
  --template-file ARM-Template/M365OfficeActivity-Detections.json `
  --parameters workspaceName=<ws> enableAnalyticRules=false

# Stage 2 - enable after watchlist sync + rule review
az deployment group create -g <rg> `
  --template-file ARM-Template/M365OfficeActivity-Detections.json `
  --parameters workspaceName=<ws> enableAnalyticRules=true
```

### Option 1 — ARM Template (Recommended, deploys all 30 rules)

**Azure Portal:**
1. Go to `portal.azure.com/#create/Microsoft.Template`
2. Click **Build your own template in the editor**
3. Paste or upload `ARM-Template/M365OfficeActivity-Detections.json`
4. Set parameter `workspaceName` = your Sentinel workspace name (default: `LAWSentinel`)
5. Select the resource group hosting your Sentinel workspace
6. Click **Review + Create → Create**

**Azure CLI:**
```bash
az deployment group create \
  --resource-group <your-rg> \
  --template-file ARM-Template/M365OfficeActivity-Detections.json \
  --parameters workspaceName=<your-workspace>
```

**Azure PowerShell:**
```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName "<your-rg>" `
  -TemplateFile "ARM-Template/M365OfficeActivity-Detections.json" `
  -workspaceName "<your-workspace>"
```

### Option 2 — Individual KQL rules (manual import)

1. In **Microsoft Sentinel → Analytics**, click **+ Create → Scheduled query rule**
2. Copy the KQL content from `AnalyticRules/RULE-XX_*.kql`
3. Set the rule frequency and period from the header comments in each file
4. Configure entity mappings and alert details as described in the ARM template

### Option 3 — Hunting Queries

1. In **Microsoft Sentinel → Hunting**, click **+ New query**
2. Paste the KQL content from `HuntingQueries/HUNT-XX_*.kql`
3. For `HUNT-13` (cross-workload user timeline), replace `<UPN_OF_USER_TO_INVESTIGATE>` with the target user's UPN before running

---

## Detection Design Principles

- **No built-in duplication:** All rules were validated against the Sentinel built-in template library to avoid duplicate coverage.
- **Baseline-aware anomaly detection:** RULE-08 (mass file download) and RULE-16 (external sharing) use 14-day per-user baselines rather than static thresholds alone.
- **Tiered severity model:** Each rule uses `case()` expressions to produce `Low / Medium / High / Critical` within a single alert, eliminating the need for duplicate rules per severity level.
- **Cross-table enrichment:** RULE-24 and HUNT-16 join `ThreatIntelligenceIndicator`; RULE-25 joins `SigninLogs`. This enables the correlation patterns most relevant to nation-state actor TTPs (Storm-0558, Midnight Blizzard).
- **Guest / external identity focus:** Six rules (RULE-01, RULE-02, RULE-16, RULE-18, HUNT-01, HUNT-06, HUNT-11) specifically target `#EXT#` pattern accounts — a common blind spot in default M365 monitoring configurations.
- **BEC campaign sequencing:** RULE-04 + RULE-21 + HUNT-14 form a detection chain: individual rule creation → multi-mailbox pattern → full campaign map.
- **eDiscovery abuse chain:** RULE-22 + HUNT-15 cover the full attacker eDiscovery workflow: search creation → content preview → export → purge evidence.
- **Entity mappings:** All ARM rules include `Account`, `Mailbox`, `IP`, and/or `File` entity mappings for automatic entity enrichment and graph population in Sentinel incidents.
- **Incident grouping:** All rules use `lookbackDuration` grouping to cluster related alerts from the same user/IP into a single incident rather than flooding the queue.
