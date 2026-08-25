# 🏰 Active Directory & Domain Controller Security Workbook

A comprehensive Microsoft Sentinel / Azure Monitor **workbook** for monitoring Windows
**Security Events from Domain Controllers and Active Directory** infrastructure. It
provides real-time visibility into authentication activity, privileged access,
directory changes, credential-attack detection, protocol hygiene (Kerberos/NTLM/RC4),
and forensic investigation — all from the `SecurityEvent` table, enriched with MDI,
UEBA, and Defender XDR data where available.

- **File:** `ActiveDirectory-SecurityEvent-Workbook.json`
- **Tabs:** 15 · **Query tiles:** 251 · **Parameters:** 5
- **Primary data source:** `SecurityEvent` (Windows Security Events via AMA)
- **Type:** Azure Monitor / Microsoft Sentinel workbook (Gallery Template JSON)

---

## Why this workbook

Domain Controllers are the highest-value target in an enterprise. This workbook turns
the raw Windows security-event stream into a full DC security program: authentication
and privileged-access monitoring, AD change auditing, a broad **attack-detection**
library mapped to MITRE ATT&CK, **weak-protocol/cipher deprecation** tracking
(including Windows Server 2025 RC4 events), DC health/availability/backup, MDI/UEBA/XDR
correlation, and a guided forensic investigation surface.

---

## Tabs

| Tab | What it covers |
|---|---|
| 📈 **Executive Summary** | Identity Security Risk Score, 7-day KPIs, critical alerts, top high-risk users, MITRE ATT&CK detections (click-through), top risky accounts / computers / IPs, DC health. |
| 📊 **Overview** | Logon/lockout/AD-change KPIs, 7-day baseline deviation, authentication timeline, logon-type & protocol distribution, RDP internal-vs-external analysis, audit-configuration inventory. |
| 🔒 **Stale Protocols & Weak Auth** | NTLMv1/LM, WDigest cleartext exposure, TLS/SSL versions, LDAP signing / channel binding, SMBv1, weak Kerberos ciphers (RC4/DES), RC4 deprecation (Server 2025 events 201–210, KDC 16–19), AS-REP-roastable accounts, PtH indicators. |
| 🔐 **Authentication** | Logon activity by account, failed logons by reason/IP/device, failed-logon heatmap, account lockouts, explicit credentials (4648), RDP logons, service-account & after-hours auth. |
| 👑 **Privileged Access** | Special-privilege assignment (4672), privileged logons, security-group membership changes, privileged logons from new locations, sensitive-account password changes. |
| 📝 **AD Changes** | User/group/computer account changes, directory-service changes (5136/5137/5141), changes by administrator, change timeline, new accounts (4720). |
| 🗺️ **Geolocation** | Trusted vs untrusted location distribution & trend, authentication by country, sign-ins from untrusted locations, failed-logon source map. |
| 🚨 **Security Threats** | Brute force / password spray, lateral movement, Golden Ticket (KRBTGT), DCSync, NTDS.dit exfiltration/dumping, Kerberoasting, AS-REP roasting, Pass-the-Hash, SID history (4765), AdminSDHolder, DCShadow, skeleton key, log clearing (1102), scheduled tasks (4698), rapid privilege escalation, honeypot access, domain-trust changes. MITRE ATT&CK, top AD vulns/CVEs. |
| 🖥️ **DC Health** | Event volume & health per DC, AD replication health, availability/heartbeat monitoring, silent-period gaps, uptime, backup status (WBAdmin/VSS), Security-log-cleared anti-forensics. |
| 🛡️ **MDI Coverage** | Microsoft Defender for Identity sensor coverage, data-table status, per-DC coverage detail, MDI alerts and detection types. |
| ⚠️ **Misconfigurations** | Password-never-expires accounts, service accounts with interactive logon, admin accounts with network logon (PtH), NTLM usage, cleartext (type 8) logons, lockout gaps, security-posture checks, audit-policy coverage. |
| 🧠 **UEBA & Anomalies** | `BehaviorAnalytics`, `UserPeerAnalytics`, `Anomalies`, `IdentityInfo` correlation; unusual logon times (Z-score), first-time computer access (90-day baseline), anomalous failed-logon patterns, high-risk identity active logons. |
| 🔬 **Forensics** | Attack-chain timeline (click a phase for detail), attack-phase activity, guided user / IP / server investigation, lateral-movement chain, suspicious server processes. |
| 🛡️ **XDR Correlation** | Defender for Endpoint beyond MDI: LSASS memory access, suspicious DC processes, outbound network from DCs, registry persistence, skeleton-key LSASS DLLs, WDigest registry/DLL evidence, MDI identity-logon correlation. |
| 👻 **Stale Accounts & Devices** | Idle/stale accounts by last authentication, privileged/service-account activity, computer & workstation activity, service-principal (Kerberos TGS) activity. |

---

## Key capabilities

- **Authentication analytics** — success/failure trends, logon types, RDP internal vs
  external, after-hours activity, failed-logon heatmaps.
- **Kerberos / NTLM / cipher hygiene** — protocol distribution and trend, TGT/service
  ticket encryption types, DES/RC4/AES usage, and **Windows Server 2025 RC4
  deprecation** tracking (events 201–210, KDC 16–19) with a remediation priority list.
- **Weak-protocol detection** — NTLMv1/LM, WDigest cleartext, legacy TLS, LDAP simple
  bind / signing gaps, SMBv1.
- **Credential-attack library** — Kerberoasting, AS-REP roasting, Golden Ticket,
  DCSync, DCShadow, NTDS.dit theft, Pass-the-Hash, SID history injection,
  AdminSDHolder, skeleton key — mapped to **MITRE ATT&CK**.
- **Privileged & change auditing** — 4672 special privileges, group membership
  changes, GPO/directory-service changes, new-location privileged logons.
- **DC operations** — availability/heartbeat, replication health, backup coverage,
  event-volume gaps, anti-forensics (1102).
- **MDI / UEBA / XDR correlation** — enriches `SecurityEvent` with Defender for
  Identity, Sentinel UEBA, and Defender for Endpoint device tables.
- **Executive reporting** — Identity Security Risk Score, KPIs, top risky
  users/computers/IPs, and 7-day baseline deviation.
- **Guided investigation** — pivot by user, IP, or server for forensic timelines.

---

## Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `TimeRange` | Time picker | 7 days | Global time scope for all tiles. |
| `DomainController` | Multi-select | *(all)* | Scope tiles to one or more DCs (`Computer`). |
| `InvestigateUser` | Text | *(empty)* | Drives the 🔬 Forensics user-investigation timeline. |
| `InvestigateIP` | Text | *(empty)* | Drives the IP-investigation summary. |
| `InvestigateServer` | Text | *(empty)* | Drives the server-investigation summary. |

---

## Data sources & prerequisites

**Primary:** `SecurityEvent` (Windows Security Events via **AMA**, recommended, or the
legacy agent). Optional enrichments render only when their tables exist:

| Source | Tab(s) |
|---|---|
| `SecurityEvent` | All tabs (primary) |
| `System` log (RC4 events 201–210) + KDC `Operational` (16–19) | 🔒 Stale Protocols |
| Microsoft Defender for Identity tables | 🛡️ MDI Coverage, 🔬/🛡️ correlations |
| Sentinel UEBA — `BehaviorAnalytics`, `UserPeerAnalytics`, `Anomalies`, `IdentityInfo` | 🧠 UEBA & Anomalies |
| Defender for Endpoint — `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents` | 🛡️ XDR Correlation |

### Data Collection Rule (DCR) XPath — add to your AMA DC data source

```
Security!*[System[(EventID=4624 or EventID=4625 or EventID=4648 or EventID=4672 or EventID=4634)]]
Security!*[System[(EventID=4768 or EventID=4769 or EventID=4770 or EventID=4771 or EventID=4776)]]
Security!*[System[(EventID=4720 or EventID=4722 or EventID=4723 or EventID=4724 or EventID=4725 or EventID=4726 or EventID=4738 or EventID=4740)]]
Security!*[System[(EventID=4728 or EventID=4729 or EventID=4732 or EventID=4733 or EventID=4756 or EventID=4757)]]
Security!*[System[(EventID=5136 or EventID=5137 or EventID=5141 or EventID=1102)]]
```

**Windows Server 2025+ RC4 deprecation (System / KDC Operational logs):**

```
System!*[System[(EventID=201 or EventID=206 or EventID=207 or EventID=208 or EventID=209 or EventID=210)]]
Microsoft-Windows-Kerberos-Key-Distribution-Center/Operational!*[System[(EventID=16 or EventID=17 or EventID=18 or EventID=19)]]
```

> Copy each XPath **completely**, including `Security!*[System[(` and the trailing `]]]`.

### Required audit policies (GPO)

| Category | Subcategory | Setting |
|---|---|---|
| Account Logon | Credential Validation | Success, Failure |
| Account Logon | Kerberos Authentication Service | Success, Failure |
| Account Logon | Kerberos Service Ticket Operations | Success, Failure |
| Account Management | User / Security Group / Computer Account Management | Success, Failure |
| Logon/Logoff | Logon | Success, Failure |
| Logon/Logoff | Special Logon | Success |
| DS Access | Directory Service Changes | Success, Failure |
| Policy Change | Audit Policy Change | Success, Failure |

**Key Event IDs:** 4624/4625 (logon), 4648 (explicit creds), 4672 (special privileges),
4720–4726/4738 (account mgmt), 4728/4732/4756 (group membership), 4740 (lockout),
4768/4769/4770/4771 (Kerberos), 4776 (NTLM), 5136/5137/5141 (directory service),
1102 (log cleared), plus RC4 201–210 and KDC 16–19.

---

## Deploy / import

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `ActiveDirectory-SecurityEvent-Workbook.json` and **Apply**.
3. **Done Editing** → **Save**, name it *Active Directory & DC Security*, and pick your
   resource group / workspace.
4. Set **Time Range** and (optionally) **Domain Controller**, then work the tabs. Use
   the **Investigate User / IP / Server** fields on the 🔬 Forensics tab for pivots.

---

## Notes

- **Read-only.** The workbook only queries logs; it never changes AD or DC configuration.
- **Graceful degradation.** Optional MDI / UEBA / XDR tiles render empty (not error) on
  tenants without those tables; several tiles use `column_ifexists()` for schema
  resilience.
- **Honeypot / canary tiles** require you to configure your decoy account names in the
  tile query.
- **Tuning.** Adjust trusted-location, sensitive-group, and baseline windows in the
  relevant tiles to match your environment before relying on the anomaly detections.
