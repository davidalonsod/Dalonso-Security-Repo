# AD Security Events — Custom Detections Package

Stop Active Directory Attacks: Advanced Monitoring with Microsoft Sentinel https://youtu.be/zYLU93U22Ew

> **Workspace:** `xxxxxx`
> **Created:** March 23, 2026
> **Primary table:** `SecurityEvent` · Secondary: `SigninLogs`, `AzureActivity`, `IdentityLogonEvents`, `DeviceProcessEvents`, `WindowsEvent`

Custom Microsoft Sentinel analytic rules and hunting queries covering the full **Active Directory attack surface**. Rules cover the complete kill chain: initial access → credential access → privilege escalation → lateral movement → persistence → domain dominance.

All rules are designed **not to duplicate** confirmed Microsoft Sentinel built-in detections (brute force, password spray, new account in admin group, explicit credential use, multiple failed logons) and are grounded in the live `SecurityEvent` table schema.

## Table of Contents

- [Folder Structure](#folder-structure)
- [Prerequisites](#prerequisites)
- [AD Attack Chain Coverage](#ad-attack-chain-coverage)
- [Analytic Rules Reference](#analytic-rules-reference)
- [Hunting Queries Reference](#hunting-queries-reference)
- [MITRE ATT&CK Coverage Matrix](#mitre-attck-coverage-matrix)
- [Deployment Guide](#deployment-guide)
- [Detection Design Principles](#detection-design-principles)

---

## Folder Structure

```
ADSecurityEvents/
├── README.md                                                  ← This file
├── ARM-Template/
│   └── ADSecurityEvents-Detections.json                      ← Deploy all 30 rules at once
├── AnalyticRules/                                             ← 30 scheduled analytic rules
│   ├── RULE-01_AD-Kerberoasting-RC4-Bulk.kql
│   ├── RULE-02_AD-ASREP-Roasting-NoPreAuth.kql
│   ├── RULE-03_AD-DCSync-NonDC-Replication.kql
│   ├── RULE-04_AD-GoldenTicket-Orphaned-Logon.kql
│   ├── RULE-05_AD-ShadowCredentials-KeyCredentialLink.kql
│   ├── RULE-06_AD-RBCD-AllowedToAct-Modified.kql
│   ├── RULE-07_AD-ADCS-Certificate-SAN-Mismatch.kql
│   ├── RULE-08_AD-AdminSDHolder-Backdoor.kql
│   ├── RULE-09_AD-DnsAdmins-DLL-Injection.kql
│   ├── RULE-10_AD-GPO-Modified-By-NonAdmin.kql
│   ├── RULE-11_AD-LSASS-Credential-Dump.kql
│   ├── RULE-12_AD-VSS-NTDS-Dump-Attempt.kql
│   ├── RULE-13_AD-WDigest-Reenabled.kql
│   ├── RULE-14_AD-DSRM-Backdoor-Registry.kql
│   ├── RULE-15_AD-SIDHistory-Injection.kql
│   ├── RULE-16_AD-DCShadow-Rogue-DC-Object.kql
│   ├── RULE-17_AD-NoPac-SAMAccountName-Spoof.kql
│   ├── RULE-18_AD-PrinterBug-Coercion-Auth.kql
│   ├── RULE-19_AD-PassTheHash-NTLM-Type3.kql
│   ├── RULE-20_AD-Machine-Account-Quota-Abuse.kql
│   ├── RULE-21_AD-Unconstrained-Delegation-Coercion.kql
│   ├── RULE-22_AD-Targeted-Kerberoasting-WriteSPN.kql
│   ├── RULE-23_AD-Domain-Policy-Weakening.kql
│   ├── RULE-24_AD-Disabled-Account-Reactivated.kql
│   ├── RULE-25_AD-Certifried-DNSHostname-Manipulation.kql
│   ├── RULE-26_AD-KrbRelayUp-LocalEscalation.kql
│   ├── RULE-27_AD-SkeletonKey-LSASS-Patch.kql
│   ├── RULE-28_AD-Exchange-WriteDACL-DCSync.kql
│   ├── RULE-29_AD-ADIDNS-Wildcard-Record-Inject.kql
│   ├── RULE-30_AD-GoldenCertificate-CA-Backup.kql
│   ├── RULE-31_AD-LAPS-GMSA-SensitiveAttribute-Read.kql
│   └── RULE-32_AD-AccessibilityFeature-IFEO-Backdoor.kql
└── HuntingQueries/                                            ← 30 proactive hunting queries
    ├── HUNT-01_AD-Kerberoasting-ServiceAccount-Profile-90d.kql
    ├── HUNT-02_AD-ASREP-Roastable-Accounts-Audit-90d.kql
    ├── HUNT-03_AD-DCSync-Rights-Audit-90d.kql
    ├── HUNT-04_AD-ACL-Sensitive-Object-Timeline-30d.kql
    ├── HUNT-05_AD-Delegation-Attack-Surface-90d.kql
    ├── HUNT-06_AD-ADCS-Vulnerable-Template-Audit-30d.kql
    ├── HUNT-07_AD-Machine-Account-Creation-Audit-90d.kql
    ├── HUNT-08_AD-SIDHistory-Enabled-Accounts-90d.kql
    ├── HUNT-09_AD-AdminSDHolder-ACL-Audit-90d.kql
    ├── HUNT-10_AD-PrivilegedAccount-LogonSource-Profile-30d.kql
    ├── HUNT-11_AD-PassTheHash-NTLM-Pattern-30d.kql
    ├── HUNT-12_AD-GPO-Modification-Full-Audit-30d.kql
    ├── HUNT-13_AD-CrossWorkload-AttackChain-30d.kql
    ├── HUNT-14_AD-NTDS-VSS-Dump-History-90d.kql
    ├── HUNT-15_AD-ServiceAccount-Kerberos-Profile-30d.kql
    ├── HUNT-16_AD-ADIDNS-Poisoning-Records-30d.kql
    ├── HUNT-17_AD-Forest-Trust-Abuse-Indicators-30d.kql
    ├── HUNT-18_AD-SensitivePrivilege-Usage-Anomaly-30d.kql
    ├── HUNT-19_AD-Pre2k-MachineAccount-Risk-90d.kql
    ├── HUNT-20_AD-Certificate-Enrollment-Anomaly-30d.kql
    ├── HUNT-21_AD-Coercion-Attack-Indicators-30d.kql
    ├── HUNT-22_AD-LSASS-Access-Attempts-30d.kql
    ├── HUNT-23_AD-ScheduledTask-Suspicious-Encoding-30d.kql
    ├── HUNT-24_AD-Service-Creation-Modification-Audit-30d.kql
    ├── HUNT-25_AD-LocalPrivEsc-Path-Analysis-30d.kql
    ├── HUNT-26_AD-WSUS-Attack-Surface-90d.kql
    ├── HUNT-27_AD-NTLMv1-Downgrade-HashCoercion-30d.kql
    ├── HUNT-28_AD-RDP-Session-Hijacking-30d.kql
    ├── HUNT-29_AD-Legacy-NTLM-Auth-Usage-30d.kql
    └── HUNT-30_AD-RC4-DES-Kerberos-WeakEncryption-30d.kql
```

---

## Prerequisites

| Requirement | Details |
|---|---|
| Microsoft Sentinel | Connected to `xxxxx` workspace |
| Windows Security Auditing | Advanced Audit Policy fully configured (see below) |
| Data connector |  **Windows Security Events via AMA** |
| Audit Policy | **Process Creation** (4688 + CommandLine), **DS Access** (5136/5137), **Kerberos Authentication** (4768/4769), **Directory Service Changes** |
| Tables required (core) | `SecurityEvent` |
| Tables required (cross-correlation) | `SigninLogs` — Azure AD connector · `AzureActivity` — Azure connector · `WindowsEvent` — for System channel (7045) |
| Tables required (EDR rules) | `DeviceProcessEvents`, `DeviceEvents` — Defender for Endpoint / MDE connector |
| Permissions (deploy) | Microsoft Sentinel Contributor + Log Analytics Contributor |
| ARM API version | `2023-02-01-preview` |

### Required Audit Policy Settings

To capture all events used by these rules, ensure the following Advanced Audit policies are enabled via GPO:

| Audit Subcategory | Setting | Key Events |
|---|---|---|
| Credential Validation | Success + Failure | 4776 |
| Kerberos Authentication Service | Success + Failure | 4768, 4771 |
| Kerberos Service Ticket Operations | Success + Failure | 4769 |
| Other Account Logon Events | Success + Failure | 4648 |
| Account Management | Success + Failure | 4720–4743 |
| DS Access / DS Changes | Success | 5136, 5137, 5141 |
| Directory Service Replication | Success + Failure | 4662 |
| Logon / Logoff | Success + Failure | 4624, 4625, 4634 |
| Privilege Use | Success | 4672, 4673 |
| Process Creation | Success | 4688 (with CommandLine logging) |
| System | Success | 4657 (registry changes), 7045, 7040 |
| Certificate Services | Success + Failure | 4886, 4887 |

---

## AD Attack Chain Coverage

This package maps directly to the AD kill chain:

### Full Kill Chain Coverage

| Phase | Technique | Coverage | Rule / Hunt |
|---|---|---|---|
| **Credential Access** | Kerberoasting (TGS-REP RC4) | **Covered** | RULE-01, HUNT-01, HUNT-15 |
| **Credential Access** | AS-REP Roasting (no pre-auth) | **Covered** | RULE-02, HUNT-02 |
| **Credential Access** | DCSync via DS-Replication rights | **Covered** | RULE-03, HUNT-03 |
| **Credential Access** | LSASS credential dump (Mimikatz/procdump) | **Covered** | RULE-11, HUNT-22 |
| **Credential Access** | VSS shadow / NTDS.dit exfil | **Covered** | RULE-12, HUNT-14 |
| **Credential Access** | WDigest re-enablement | **Covered** | RULE-13 |
| **Credential Access** | Pass-the-Hash via NTLM Type 3 | **Covered** | RULE-19, HUNT-11 |
| **Credential Access** | Shadow Credentials (msDS-KeyCredentialLink) | **Covered** | RULE-05 |
| **Credential Access** | Targeted Kerberoasting via WriteSPN | **Covered** | RULE-22, HUNT-15 |
| **Defense Evasion** | Golden Ticket / orphaned privileged logon | **Covered** | RULE-04 |
| **Defense Evasion** | DCShadow rogue DC registration | **Covered** | RULE-16 |
| **Defense Evasion** | Skeleton Key LSASS patch | **Covered** | RULE-27 |
| **Defense Evasion** | DSRM backdoor activation | **Covered** | RULE-14 |
| **Privilege Escalation** | RBCD attribute modification | **Covered** | RULE-06, HUNT-05 |
| **Privilege Escalation** | AdminSDHolder ACL backdoor | **Covered** | RULE-08, HUNT-09 |
| **Privilege Escalation** | DnsAdmins DLL injection on DC | **Covered** | RULE-09 |
| **Privilege Escalation** | GPO modified by non-admin | **Covered** | RULE-10, HUNT-12 |
| **Privilege Escalation** | SID History injection | **Covered** | RULE-15, HUNT-08 |
| **Privilege Escalation** | NoPac SAMAccountName spoofing (CVE-2021-42278/87) | **Covered** | RULE-17 |
| **Privilege Escalation** | Certifried dNSHostName manipulation (CVE-2022-26923) | **Covered** | RULE-25 |
| **Privilege Escalation** | KrbRelayUp local escalation | **Covered** | RULE-26, HUNT-22 |
| **Privilege Escalation** | Machine account quota abuse (RBCD prep) | **Covered** | RULE-20, HUNT-07 |
| **Privilege Escalation** | Domain policy weakening | **Covered** | RULE-23 |
| **Privilege Escalation** | ADCS ESC1/ESC8 certificate abuse | **Covered** | RULE-07, HUNT-06, HUNT-20 |
| **Privilege Escalation** | Exchange WriteDACL → DCSync | **Covered** | RULE-28 |
| **Lateral Movement** | PrinterBug / Coercion authentication | **Covered** | RULE-18, HUNT-21 |
| **Lateral Movement** | Unconstrained delegation coercion | **Covered** | RULE-21, HUNT-05 |
| **Lateral Movement** | Pass-the-Hash NTLM lateral movement | **Covered** | RULE-19, HUNT-11 |
| **Lateral Movement** | Disabled account reactivation for privilege | **Covered** | RULE-24 |
| **Persistence** | ADIDNS wildcard record injection | **Covered** | RULE-29, HUNT-16 |
| **Persistence** | Golden Certificate CA backup | **Covered** | RULE-30, HUNT-20 |
| **Persistence** | Pre-Windows 2000 predictable machine passwords | **Covered** | HUNT-19 |
| **Persistence** | Forest trust abuse (SID History cross-forest) | **Covered** | HUNT-17 |
| **Persistence** | Sensitive privilege usage anomalies | **Covered** | HUNT-18 |

---

## Analytic Rules Reference

### Credential Access

| Rule | Description | Severity | Freq | MITRE |
|---|---|---|---|---|
| [RULE-01](AnalyticRules/RULE-01_AD-Kerberoasting-RC4-Bulk.kql) | **Kerberoasting — Bulk RC4 TGS Requests** — ≥5 TGS requests using RC4 (0x17) encryption for different service accounts in 30 min from a single user. Correlates with `SigninLogs` for risky sign-in context. | High | PT30M | T1558.003 |
| [RULE-02](AnalyticRules/RULE-02_AD-ASREP-Roasting-NoPreAuth.kql) | **AS-REP Roasting — No Pre-Auth TGT Request** — Event 4768 with Pre-Auth Type = 0 (DONT_REQ_PREAUTH). Any single event is an immediate signal on hardened environments; ≥3 different accounts in 1h = High. | Medium | PT1H | T1558.004 |
| [RULE-03](AnalyticRules/RULE-03_AD-DCSync-NonDC-Replication.kql) | **DCSync from Non-Domain Controller** — Event 4662 with `DS-Replication-Get-Changes-All` or `DS-Replication-Get-Changes` from a source that is NOT a known DC computer account. Covers secretsdump, Mimikatz dcsync. | Critical | PT15M | T1003.006 |
| [RULE-04](AnalyticRules/RULE-04_AD-GoldenTicket-Orphaned-Logon.kql) | **Golden Ticket — Privileged Logon with No TGT Request** — Event 4624 with LogonType 3 + Event 4672 (SeDebugPrivilege/DA token) but no preceding 4768 (TGT request) from the same account in the same hour. Flags forged TGTs that bypass the KDC. | High | PT1H | T1558.001 |
| [RULE-05](AnalyticRules/RULE-05_AD-ShadowCredentials-KeyCredentialLink.kql) | **Shadow Credentials — msDS-KeyCredentialLink Modified** — Event 5136 modifying the `msDS-KeyCredentialLink` attribute on any user or computer object. Any write = High. Attacker-written key enables PKINIT auth without the account password. | High | PT15M | T1556.006 |
| [RULE-11](AnalyticRules/RULE-11_AD-LSASS-Credential-Dump.kql) | **LSASS Credential Dump — Process Access or Suspicious CLI** — Event 4688 CommandLine matching lsass dump patterns (procdump/ProcDump targeting lsass, comsvcs.dll MiniDump, Mimikatz sekurlsa). Correlates with `DeviceProcessEvents` when MDE is present. | Critical | PT15M | T1003.001 |
| [RULE-12](AnalyticRules/RULE-12_AD-VSS-NTDS-Dump-Attempt.kql) | **NTDS.dit Dump via VSS Shadow Copy** — Event 4688 with vssadmin create shadow, ntdsutil, or diskshadow targeting C: or NTDS. Also flags `esentutl /p` against ntds.dit. | Critical | PT15M | T1003.003 |
| [RULE-19](AnalyticRules/RULE-19_AD-PassTheHash-NTLM-Type3.kql) | **Pass-the-Hash — NTLM Network Logon from Unusual Source** — Event 4624 LogonType=3 with Auth Package = NTLM from a source that has NOT performed an interactive logon (Type 2) to that computer. Escalates to Critical when source is a Tier 0 asset. | High | PT30M | T1550.002 |
| [RULE-22](AnalyticRules/RULE-22_AD-Targeted-Kerberoasting-WriteSPN.kql) | **Targeted Kerberoasting — SPN Set then TGS Requested** — Event 5136 setting `servicePrincipalName` on a user account (without COMPUTER$ suffix) followed within 5 min by a 4769 TGS request for that new SPN. Covers `targetedKerberoast.py` and similar. | High | PT15M | T1558.003 |

### Privilege Escalation

| Rule | Description | Severity | Freq | MITRE |
|---|---|---|---|---|
| [RULE-06](AnalyticRules/RULE-06_AD-RBCD-AllowedToAct-Modified.kql) | **RBCD Setup — msDS-AllowedToActOnBehalfOfOtherIdentity Modified** — Event 4742 or 5136 modifying `msDS-AllowedToActOnBehalfOfOtherIdentity` on a computer object. Non-admin writers = Critical. Covers RBCD-based privilege escalation chains. | High | PT15M | T1134.001, T1098 |
| [RULE-07](AnalyticRules/RULE-07_AD-ADCS-Certificate-SAN-Mismatch.kql) | **ADCS Certificate with SAN Mismatch (ESC1/ESC8)** — Event 4887 (Certificate Issued) where the certificate Subject Alternative Name contains a UPN different from the requester's account. Or ≥3 certificate requests in 10 min from one account. | High | PT15M | T1649, T1078 |
| [RULE-08](AnalyticRules/RULE-08_AD-AdminSDHolder-Backdoor.kql) | **AdminSDHolder ACL Backdoor** — Event 5136 modifying the `ntSecurityDescriptor` of `CN=AdminSDHolder,CN=System`. Any modification by a non-built-in admin = Critical. Modification propagates to all DA/EA/BA protected objects every 60min. | Critical | PT15M | T1098, T1207 |
| [RULE-09](AnalyticRules/RULE-09_AD-DnsAdmins-DLL-Injection.kql) | **DnsAdmins DLL Injection on DC** — WindowsEvent (System channel) Event 4 or EventID 7045 showing DNS Server service loading a DLL from a non-standard path (not `%SystemRoot%\System32\dns.exe`). Correlates with 4728/4756 additions to DnsAdmins. | Critical | PT15M | T1543.003, T1574.002 |
| [RULE-10](AnalyticRules/RULE-10_AD-GPO-Modified-By-NonAdmin.kql) | **GPO Modified by Non-Admin Account** — Event 5136 modifying a Group Policy Object's `gPCFileSysPath` or `versionNumber` attribute by a user NOT in Domain Admins or Group Policy Creator Owners. Any match = High. | High | PT15M | T1484.001 |
| [RULE-15](AnalyticRules/RULE-15_AD-SIDHistory-Injection.kql) | **SID History Injection** — Event 4765 (SID History added to account) or Event 5136 modifying `sIDHistory` attribute. Any cross-domain SID injection especially RID-500 or Enterprise Admins (RID-519) SID = Critical. | Critical | PT15M | T1134.005 |
| [RULE-16](AnalyticRules/RULE-16_AD-DCShadow-Rogue-DC-Object.kql) | **DCShadow — Rogue Domain Controller Object Created** — Event 5137 creating an object of class `nTDSDSA` in the Configuration NC, or a new `server` object in `CN=Sites` from a machine that is not an existing DC. | Critical | PT15M | T1207 |
| [RULE-17](AnalyticRules/RULE-17_AD-NoPac-SAMAccountName-Spoof.kql) | **NoPac / SAMAccountName Spoofing (CVE-2021-42278/42287)** — Event 4781 (account rename) on a machine account to match a DC name (without $), followed within 5 min by 4768 (TGT request), then another 4781 back. Classic noPac sequence. | Critical | PT15M | T1554, T1078.002 |
| [RULE-20](AnalyticRules/RULE-20_AD-Machine-Account-Quota-Abuse.kql) | **Machine Account Quota Bulk Abuse** — ≥3 new computer account objects (Event 5137, objectClass=computer) created by the same non-admin user within 1 hour. Signals RBCD, KrbRelayUp, or noPac staging. | High | PT1H | T1136.001, T1098 |
| [RULE-21](AnalyticRules/RULE-21_AD-Unconstrained-Delegation-Coercion.kql) | **Unconstrained Delegation + DC Authentication (Coercion)** — Event 4624 (Type 3 Kerberos) from a Domain Controller computer account to a non-DC host that has `TRUSTED_FOR_DELEGATION` set. Signals PrinterBug/PetitPotam coercion to steal DC TGT. | Critical | PT15M | T1187, T1558.001 |
| [RULE-23](AnalyticRules/RULE-23_AD-Domain-Policy-Weakening.kql) | **Domain Security Policy Weakened** — Event 4739 (Domain Policy Changed) or 4713 (Kerberos Policy Changed) with NoPreauth, LockoutThreshold=0, or MinPasswordLength decrease. Flags deliberate weakening for attack enablement. | High | PT15M | T1484, T1562.001 |
| [RULE-24](AnalyticRules/RULE-24_AD-Disabled-Account-Reactivated.kql) | **Disabled Privileged Account Re-Enabled (Walking Dead)** — Event 4722 (account enabled) for an account that was a member of Domain Admins, Enterprise Admins, or other tier-0 group at any point in the past 30 days. Correlates prior group membership from 4728 events. | High | PT15M | T1098, T1078 |
| [RULE-25](AnalyticRules/RULE-25_AD-Certifried-DNSHostname-Manipulation.kql) | **Certifried — Machine Account dNSHostName Set to DC FQDN (CVE-2022-26923)** — Event 4742 changing a machine account's `dNSHostName` to match an existing Domain Controller's DNS name. Prerequisite for Certifried certificate-based escalation to DA. | Critical | PT15M | T1098.001, T1649 |
| [RULE-26](AnalyticRules/RULE-26_AD-KrbRelayUp-LocalEscalation.kql) | **KrbRelayUp — Local Kerberos Relay Escalation Pattern** — Machine account creation (5137) on a host by a low-privilege user followed within 10 min by LDAP-related attribute modification (4742/5136) on that same host's computer object. Signals single-host RBCD/Shadow Credentials via KrbRelayUp. | High | PT15M | T1548, T1134 |
| [RULE-28](AnalyticRules/RULE-28_AD-Exchange-WriteDACL-DCSync.kql) | **Exchange Trusted Subsystem — DCSync Rights Granted** — Event 5136 granting `DS-Replication-Get-Changes-All` right on the domain root object where the writer's account is a member of `Exchange Windows Permissions` or `Exchange Trusted Subsystem`. PrivExchange chain detection. | Critical | PT15M | T1003.006, T1078 |

### Defense Evasion / Persistence

| Rule | Description | Severity | Freq | MITRE |
|---|---|---|---|---|
| [RULE-13](AnalyticRules/RULE-13_AD-WDigest-Reenabled.kql) | **WDigest Credential Caching Re-Enabled** — Event 4657 (Registry value changed) setting `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential` to 1. Enables plaintext password caching in LSASS. | High | PT15M | T1556.002 |
| [RULE-14](AnalyticRules/RULE-14_AD-DSRM-Backdoor-Registry.kql) | **DSRM Admin Backdoor Activated** — Event 4657 setting `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior` to 2 on a DC. Enables the DSRM local admin to authenticate over the network — a DC backdoor independent of domain accounts. | Critical | PT15M | T1003.004, T1098 |
| [RULE-18](AnalyticRules/RULE-18_AD-PrinterBug-Coercion-Auth.kql) | **Print Spooler Coercion — DC Authenticates to Non-DC** — Event 4624 (Type 3, Kerberos) from a Domain Controller's computer account to a workstation or member server, where the Print Spooler service is confirmed running on the DC. Signals PrinterBug coercion in progress. | High | PT15M | T1187 |
| [RULE-27](AnalyticRules/RULE-27_AD-SkeletonKey-LSASS-Patch.kql) | **Skeleton Key — LSASS In-Memory Patch Detected** — Event 4611 (trusted logon process registered) or behavioral pattern: new LSA package registration event, or `DeviceEvents` `MimikatzCommand` matching `misc::skeleton`. Also correlates Sysmon Event 10 LSASS write access from unusual processes. | Critical | PT15M | T1556.001 |
| [RULE-29](AnalyticRules/RULE-29_AD-ADIDNS-Wildcard-Record-Inject.kql) | **ADIDNS Wildcard Record Injection** — Event 5137 creating a new `dnsNode` object with a wildcard (`*`) name or a hostname that matches a common infrastructure pattern, written by a non-admin user. Enables MITM capture via DNS-based credential capture. | High | PT15M | T1557.001, T1071.004 |
| [RULE-30](AnalyticRules/RULE-30_AD-GoldenCertificate-CA-Backup.kql) | **Golden Certificate — CA Private Key Backup** — Event 4880 (Certificate Services started) or 4886 combined with 4688 showing `certutil` or `certipy` executing a CA backup (`-backup`, `-exportPFX`, or backup flag on CA object). Stolen CA key enables forging certs valid for domain lifetime. | Critical | PT15M | T1553.004, T1649 |
| [RULE-31](AnalyticRules/RULE-31_AD-LAPS-GMSA-SensitiveAttribute-Read.kql) | **Unauthorized LAPS / GMSA Password Attribute Read** - EventID 4662 reads of ms-Mcs-AdmPwd (LAPS) or msDS-ManagedPassword (GMSA) by accounts outside the legitimate readers list. Flags mass harvest (5+ targets). | High | PT15M | T1552.004, T1555 |
| [RULE-32](AnalyticRules/RULE-32_AD-AccessibilityFeature-IFEO-Backdoor.kql) | **Accessibility Feature IFEO Backdoor (Sticky Keys, Utilman, Narrator)** - EventID 4657 write to IFEO debugger key for accessibility binaries, OR EventID 4688 showing accessibility binary spawning cmd/PowerShell. Critical if both registry write and spawn observed. | High | PT10M | T1546.008 |

---

## Hunting Queries Reference

| Hunt | Description | Period | Primary Use Case |
|---|---|---|---|
| [HUNT-01](HuntingQueries/HUNT-01_AD-Kerberoasting-ServiceAccount-Profile-90d.kql) | **Kerberoasting Service Account Profile** — All RC4 TGS requests per service account, requester, and hour. Baseline for spray pattern vs. targeted. | 90d | Credential access path reconstruction |
| [HUNT-02](HuntingQueries/HUNT-02_AD-ASREP-Roastable-Accounts-Audit-90d.kql) | **AS-REP Roastable Account Audit** — Accounts with `DONT_REQ_PREAUTH` set + historical AS-REP requests. Surfaces accounts that never required patches. | 90d | Exposure assessment |
| [HUNT-03](HuntingQueries/HUNT-03_AD-DCSync-Rights-Audit-90d.kql) | **DCSync Rights Holder Audit** — All principals who hold `DS-Replication-Get-Changes-All` identified via 4662 events or 5136 ACL grants, filtered to non-DC sources. | 90d | Privilege hygiene |
| [HUNT-04](HuntingQueries/HUNT-04_AD-ACL-Sensitive-Object-Timeline-30d.kql) | **ACL Modification Timeline on Sensitive AD Objects** — All 5136 events on AdminSDHolder, Domain root, DomainControllers OU, key groups. Ranked by sensitivity and annotated with attack technique. | 30d | Privilege escalation forensics |
| [HUNT-05](HuntingQueries/HUNT-05_AD-Delegation-Attack-Surface-90d.kql) | **Delegation Attack Surface Map** — All unconstrained, constrained, and RBCD delegation configurations with activity correlation. Flags non-DC unconstrained hosts and RBCD-enabled computer objects. | 90d | Attack surface review |
| [HUNT-06](HuntingQueries/HUNT-06_AD-ADCS-Vulnerable-Template-Audit-30d.kql) | **ADCS Certificate Template Enrollment Audit** — All certificate issuances (4886/4887) grouped by template, with SAN presence, requester vs. subject mismatch, and enrollment agent flag. ESC1/ESC3/ESC8 indicators. | 30d | PKI security review |
| [HUNT-07](HuntingQueries/HUNT-07_AD-Machine-Account-Creation-Audit-90d.kql) | **Machine Account Creation Full Audit** — All computer object creations (5137) with creator UPN, creator group membership, purpose (domain join vs. RBCD/noPac staging). Flags non-admin creators and rapid creation bursts. | 90d | RBCD/noPac exposure assessment |
| [HUNT-08](HuntingQueries/HUNT-08_AD-SIDHistory-Enabled-Accounts-90d.kql) | **SID History Enabled Account Full Audit** — All accounts with `sIDHistory` attribute populated. Crossrefs SID values against high-value group SIDs (DA, EA, BA). | 90d | Persistence audit |
| [HUNT-09](HuntingQueries/HUNT-09_AD-AdminSDHolder-ACL-Audit-90d.kql) | **AdminSDHolder ACL Backdoor History** — All 5136 modifications to AdminSDHolder object. Since SDProp propagates every 60min, any modification is a persistence signal. | 90d | Persistence forensics |
| [HUNT-10](HuntingQueries/HUNT-10_AD-PrivilegedAccount-LogonSource-Profile-30d.kql) | **Privileged Account Logon Source Profiling** — All Type 2/3/10 logons for DA/EA/SA members. New IP, new workstation, or off-hours logons for tier-0 accounts. | 30d | Compromised admin detection |
| [HUNT-11](HuntingQueries/HUNT-11_AD-PassTheHash-NTLM-Pattern-30d.kql) | **Pass-the-Hash NTLM Lateral Movement Pattern** — Type 3 NTLM logons without corresponding interactive logon on the same host. Ranked by lateral movement spread (unique targets per source). | 30d | Lateral movement forensics |
| [HUNT-12](HuntingQueries/HUNT-12_AD-GPO-Modification-Full-Audit-30d.kql) | **GPO Modification Full Audit** — All 5136 events on GPO objects including gPCFileSysPath, versionNumber, and Security Descriptor. SYSVOL file modifications correlated via WindowsEvent where available. | 30d | GPO backdoor detection |
| [HUNT-13](HuntingQueries/HUNT-13_AD-CrossWorkload-AttackChain-30d.kql) | **Cross-Workload AD Attack Chain Correlation** — Joins SecurityEvent Kerberos/NTLM patterns with SigninLogs risky sign-ins and OfficeActivity anomalies for the same UPN/IP to surface multi-stage attack chains. Set `TargetUser` for targeted investigation. | 30d | Full-chain incident investigation |
| [HUNT-14](HuntingQueries/HUNT-14_AD-NTDS-VSS-Dump-History-90d.kql) | **NTDS.dit / VSS Dump Attempt History** — All 4688 CommandLine events matching vssadmin, ntdsutil, esentutl, diskshadow, and secretsdump patterns. Deduplicates and ranks by actor. | 90d | Credential exfiltration forensics |
| [HUNT-15](HuntingQueries/HUNT-15_AD-ServiceAccount-Kerberos-Profile-30d.kql) | **Service Account Kerberos Ticket Profile** — Per service account: TGS request volume, requester diversity, RC4 vs AES ratio, and off-hours requests. Surfaces kerberoastable accounts and targeted roasting activity. | 30d | Credential access exposure |
| [HUNT-16](HuntingQueries/HUNT-16_AD-ADIDNS-Poisoning-Records-30d.kql) | **ADIDNS Poisoning and Time Bomb Record Audit** — All DNS record creations (5137 in DomainDnsZones NC) by non-admin users. Flags wildcard records, duplicate hostname registrations, and records pointing to external IPs. | 30d | DNS poisoning review |
| [HUNT-17](HuntingQueries/HUNT-17_AD-Forest-Trust-Abuse-Indicators-30d.kql) | **Forest Trust Abuse Indicator Sweep** — Logons crossing forest/domain trust boundaries with NTLM or unusual SID History in PAC. Correlates with 4662 DS-Replication from child domain accounts in parent domain. | 30d | Cross-forest attack review |
| [HUNT-18](HuntingQueries/HUNT-18_AD-SensitivePrivilege-Usage-Anomaly-30d.kql) | **Sensitive Privilege Usage Anomaly** — 4672 events with SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeTcbPrivilege outside of known admin accounts and workspaces. New account + rare host = escalated risk. | 30d | Privilege escalation detection |
| [HUNT-19](HuntingQueries/HUNT-19_AD-Pre2k-MachineAccount-Risk-90d.kql) | **Pre-Windows 2000 Machine Account Risk Assessment** — Computer accounts where `pwdLastSet` equals `whenCreated` (predictable password never rotated). Groups by OU, annotates with recent auth activity (4768/4624), and computes exploitability score. | 90d | Pre-Windows 2000 attack surface |
| [HUNT-20](HuntingQueries/HUNT-20_AD-Certificate-Enrollment-Anomaly-30d.kql) | **Certificate Enrollment Anomaly — ESC Pattern Detection** — All 4887 (cert issued) events grouped by template, with SAN mismatch detection, enrollment agent use, bulk enrollment rate, and non-standard requester flags (guest, service account). | 30d | ADCS attack surface review |
| [HUNT-21](HuntingQueries/HUNT-21_AD-Coercion-Attack-Indicators-30d.kql) | **Coercion Attack Indicators (PetitPotam, PrinterBug, DFSCoerce)** — DC-sourced Type 3 Kerberos logons to unexpected targets during the coercion window, combined with 4769 TGS requests from the coerced host's machine account. Surfaces TGT capture attempts. | 30d | Coercion attack forensics |
| [HUNT-22](HuntingQueries/HUNT-22_AD-LSASS-Access-Attempts-30d.kql) | **LSASS Access and Memory Read Attempts** — 4688 CommandLine patterns and `DeviceEvents` LSASS access events. Tracks unique processes, users, and hosts targeting LSASS over time. | 30d | Credential dumping detection |
| [HUNT-23](HuntingQueries/HUNT-23_AD-ScheduledTask-Suspicious-Encoding-30d.kql) | **Scheduled Task — Suspicious Encoding and Commands** — Event 4698 (scheduled task created) with encoded commands (`-enc`, `-encodedcommand`), downloads (`Invoke-WebRequest`, `certutil -urlcache`), or LOLBAs patterns. Correlates creator account risk. | 30d | Persistence and execution detection |
| [HUNT-24](HuntingQueries/HUNT-24_AD-Service-Creation-Modification-Audit-30d.kql) | **Service Creation and Modification Audit** — Event 7045 (new service) and 7040 (service config change) with ServiceFileName patterns for reverse shells, LOLBAs, and known lateral movement tools (PsExec, SCShell). | 30d | Lateral movement and persistence |
| [HUNT-25](HuntingQueries/HUNT-25_AD-LocalPrivEsc-Path-Analysis-30d.kql) | **Local Privilege Escalation Path Analysis** — Chains low-priv user 4624 (interactive) with subsequent 4672 (special privilege) and process creation events suggesting SeImpersonatePrivilege or token impersonation escalation. | 30d | Local privilege escalation review |
| [HUNT-26](HuntingQueries/HUNT-26_AD-WSUS-Attack-Surface-90d.kql) | **WSUS Attack Surface Assessment** — Identifies WSUS server via LDAP data in 5137/SecurityEvent, then flags any 4688 CommandLine events on the WSUS host matching SharpWSUS or database modification patterns. | 90d | WSUS compromise risk assessment |
| [HUNT-27](HuntingQueries/HUNT-27_AD-NTLMv1-Downgrade-HashCoercion-30d.kql) | **NTLMv1 Downgrade and Hash Coercion Indicators** - EventID 4624 with LmPackageName=NTLM V1, document-triggered SMB auth (ntlm_theft/Bad-Pdf), and machine account NTLMv1 (Silver Ticket risk). | 30d | NTLMv1 downgrade and relay detection |
| [HUNT-28](HuntingQueries/HUNT-28_AD-RDP-Session-Hijacking-30d.kql) | **RDP Session Hijacking (SharpRDPHijack)** - EventID 4778/4779 session handoff pattern (disconnect IP-A then reconnect IP-B within 5 min), tscon.exe execution, RDP lateral movement across 3+ hosts. | 30d | RDP session takeover forensics |
| [HUNT-29](HuntingQueries/HUNT-29_AD-Legacy-NTLM-Auth-Usage-30d.kql) | **Legacy NTLM Authentication Usage** - Comprehensive NTLMv1 logon hunt (LM / NTLM V1 / NTLM V1 with Client Challenge), pure-NTLM accounts with no Kerberos baseline, daily trend for remediation. Risk-scored by machine account, host spread, source IP diversity. | 30d | Legacy auth posture and remediation |
| [HUNT-30](HuntingQueries/HUNT-30_AD-RC4-DES-Kerberos-WeakEncryption-30d.kql) | **RC4 and DES Kerberos Weak Encryption** - Kerberoastable SPNs receiving RC4 TGS (4769), DES encryption events (always P1-Critical), per-account AES vs RC4 vs DES posture with P1/P2/P3 remediation priority, AS-REP Roastable candidates. | 30d | Weak Kerberos encryption posture and Kerberoasting exposure |

---

## MITRE ATT&CK Coverage Matrix

| Tactic | Techniques Covered |
|---|---|
| **Initial Access** | T1078.002 (Domain Accounts), T1078.004 (Cloud Accounts) |
| **Credential Access** | T1003.001 (LSASS Memory), T1003.003 (NTDS), T1003.004 (LSA Secrets), T1003.006 (DCSync), T1110.003 (Password Spray), T1552.004 (Private Keys/LAPS), T1555 (Credentials from Password Stores/GMSA), T1557.001 (LLMNR/NTLM Downgrade), T1558.001 (Golden Ticket), T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting), T1556.002 (WDigest), T1556.006 (Shadow Credentials), T1550.002 (Pass-the-Hash) |
| **Privilege Escalation** | T1098 (Account Manipulation), T1098.001 (Additional Cloud Credentials), T1134 (Access Token Manipulation), T1134.001 (Token Impersonation), T1134.005 (SID History), T1484.001 (GPO Modification), T1548 (Abuse Elevation Control), T1649 (Steal/Forge Authentication Certs) |
| **Defense Evasion** | T1207 (Rogue Domain Controller/DCShadow), T1553.004 (Install Root Certificate), T1556.001 (Skeleton Key), T1562.001 (Disable Security Tools), T1070 (Indicator Removal) |
| **Lateral Movement** | T1187 (Forced Authentication / Coercion), T1550.002 (Pass-the-Hash), T1550.003 (Pass-the-Ticket), T1558.003 (Kerberoasting for lateral), T1021.001 (RDP), T1021.006 (WinRM), T1563.002 (RDP Session Hijacking) |
| **Persistence** | T1098 (Account Manipulation), T1136.001 (Create Local Account), T1543.003 (Windows Service), T1546.008 (Accessibility Features/IFEO Backdoor), T1547 (Boot/Logon Autostart), T1554 (Compromise Client Software Binary — NoPac) |
| **Impact** | T1484 (Domain Policy Modification) |
| **Discovery** | T1482 (Domain Trust Discovery), T1087.002 (Domain Account Discovery), T1615 (Group Policy Discovery) |

---

## Deployment Guide

### Option 1 — ARM Template (Recommended, deploys all 32 rules)

**Azure Portal:**
1. Go to `portal.azure.com/#create/Microsoft.Template`
2. Click **Build your own template in the editor**
3. Paste or upload `ARM-Template/ADSecurityEvents-Detections.json`
4. Set parameter `workspaceName` = your Sentinel workspace name (default: `xxxxx`)
5. Select the resource group hosting your Sentinel workspace
6. Click **Review + Create → Create**

**Azure CLI:**
```bash
az deployment group create \
  --resource-group <your-rg> \
  --template-file ARM-Template/ADSecurityEvents-Detections.json \
  --parameters workspaceName=<your-workspace>
```

### Option 2 — Individual KQL rules (manual import)

1. In **Microsoft Sentinel → Analytics**, click **+ Create → Scheduled query rule**
2. Copy the KQL content from `AnalyticRules/RULE-XX_*.kql`
3. Set the rule frequency and look-back period from the header comment in each file
4. Configure entity mappings: `Account` → SubjectUserName/TargetUserName · `Host` → Computer · `IP` → IpAddress

### Option 3 — Hunting Queries

1. In **Microsoft Sentinel → Hunting**, click **+ New query**
2. Paste the KQL content from `HuntingQueries/HUNT-XX_*.kql`
3. For `HUNT-13` (cross-workload chain), set the `TargetUser` variable at the top to the UPN under investigation

---

## Detection Design Principles

- **No built-in duplication:** All rules validated against Sentinel built-in templates. Rules that would duplicate (brute force 4625 volume, password spray, new account in admin group, explicit credential use) are intentionally excluded — those are covered upstream in the built-in library.
- **Attack-phase correlation:** Rules fire on multi-event sequences (e.g., RULE-17 NoPac: rename event → TGT request → rename back) rather than single events, dramatically reducing false positives.
- **Tiered severity model:** Each rule uses `case()` expressions to escalate within a single rule — eliminating duplicate rules per severity and keeping the rule count manageable.
- **Cross-table enrichment:** 6 rules join `SigninLogs` (risky sign-in context), `DeviceProcessEvents` (MDE endpoint), or `WindowsEvent` (System channel events). This enables the correlation patterns most relevant to nation-state TTPs (Cozy Bear, APT29, FIN7).
- **DC-context awareness:** Rules that involve machine account activity (RULE-03, RULE-21, RULE-18) maintain a dynamic DC list by querying known DC hostnames from 4768 authentication patterns, reducing false positives from legitimate DC-to-DC replication.
- **Entity mappings:** All ARM rules include `Account`, `Host`, `IP`, and `Process` entity mappings for automatic entity enrichment and graph population in Sentinel incidents.
- **Incident grouping:** All rules use `lookbackDuration` grouping on Account entity to cluster related alerts from the same user into single incidents.
