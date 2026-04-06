---
title: "Threat Intelligence Report: Iran Conflict Cyber Threat Escalation — Operation Epic Fury and Beyond"
date: "2026-04-03"
severity: "CRITICAL"
classification: "TLP:WHITE"
description: "Cross-source analysis of Iranian state-aligned cyber operations post-Operation Epic Fury, covering wiper attacks, hacktivist escalation, and identity weaponization."
tags:
  - iran
  - operation-epic-fury
  - wiper
  - handala
  - void-manticore
  - apt33
  - apt34
  - muddywater
  - cyberav3ngers
  - intune
  - identity-weaponization
  - hacktivist
  - critical-infrastructure
  - mois
  - irgc
sources_count: 12
author: "TI Mindmap HUB"
---

# 🛡️ Threat Intelligence Report: Iran Conflict Cyber Threat Escalation — Operation Epic Fury and Beyond

> **Report Date:** 2026-04-03  
> **Period Covered:** February 25, 2026 – April 3, 2026  
> **Classification:** TLP:WHITE  
> **Severity:** CRITICAL  
> **Platform:** TI Mindmap HUB — [ti-mindmap-hub.com](https://ti-mindmap-hub.com)

---

## 1. Table of Source Reports

| # | Title | Publication Date | Source | Platform Link |
|---|-------|-----------------|--------|---------------|
| 1 | SentinelOne Intelligence Brief: Iranian Cyber Activity Outlook | 2026-02-28 | SentinelOne | [sentinelone.com](https://www.sentinelone.com/blog/sentinelone-intelligence-brief-iranian-cyber-activity-outlook/) |
| 2 | Threat Brief: March 2026 Escalation of Cyber Risk Related to Iran (Updated March 26) | 2026-03-02 (updated 2026-03-26) | Palo Alto Networks Unit 42 | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/) |
| 3 | Threat Advisory: Iran-Aligned Cyber Actors Respond to Operation Epic Fury | 2026-03-03 | BeyondTrust | [beyondtrust.com](https://www.beyondtrust.com/blog/entry/threat-advisory-operation-epic-fury) |
| 4 | Insights: Increased Risk of Wiper Attacks (Handala Hack) | 2026-03-06 (updated 2026-03-23) | Palo Alto Networks Unit 42 | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/handala-hack-wiper-attacks/) |
| 5 | Special Report: Latest Iran Cyber Threat Analysis (Day 11 — Stryker) | 2026-03-11 | CyberWarrior76 / Multi-vendor compilation | [cyberwarrior76.substack.com](https://cyberwarrior76.substack.com/p/special-report-latest-iran-cyber) |
| 6 | Stryker Cyberattack: Iran-Linked Handala Claims Wiper Attack | 2026-03-11 | Cyberwarzone | [cyberwarzone.com](https://cyberwarzone.com/2026/03/11/stryker-handala-wiper-attack/) |
| 7 | Stryker Wiper Attack: When Iran Turned Microsoft Intune Into a Weapon | 2026-03-12 | BlackVeil Security | [blackveilsecurity.com](https://www.blackveilsecurity.com/blog/stryker-iran-wiper-attack-2026-03-12) |
| 8 | From Silence to Stryker: Iran's Cyber Retaliation Begins | 2026-03-12 | Moody's | [moodys.com](https://www.moodys.com/web/en/us/insights/insurance/from-silence-to-stryker-iran-cyber-retaliation-begins.html) |
| 9 | Unit 42 Threat Bulletin — March 2026 | 2026-03-15 | Palo Alto Networks Unit 42 | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/threat-bulletin/march-2026/) |
| 10 | Iranian Cyber Threat Evolution: From MBR Wipers to Identity Weaponization | 2026-03-20 | Palo Alto Networks Unit 42 | [unit42.paloaltonetworks.com](https://unit42.paloaltonetworks.com/evolution-of-iran-cyber-threats/) |
| 11 | Iran Conflict Cyber Threat Report — Critical Infrastructure Risk Analysis | 2026-03-20 | Fortress Information Security | [fortressinfosec.com](https://www.fortressinfosec.com/resources/reports/iran-conflict-cyber-threat-report-critical-infrastructure-risk-analysis) |
| 12 | Analyzing Iran-nexus TTP Evolution in 2026 | 2026-03-27 | Push Security | [pushsecurity.com](https://pushsecurity.com/blog/stryker-handala-report) |

---

## 2. Executive Summary

### 2.1 Overview

On February 28, 2026, the United States and Israel launched Operation Epic Fury (U.S.) / Operation Roaring Lion (Israel), a joint kinetic offensive against Iran. Within hours, Iranian internet connectivity collapsed to 1–4% of baseline, a state that has persisted for over 27 consecutive days. Despite this near-total blackout, Iranian state-aligned cyber actors—operating both domestically and via dispersed proxies—have escalated offensive cyber operations to the highest levels ever observed.

The cyber dimension of this conflict is defined by three converging dynamics: confirmed destructive wiper operations against Western critical infrastructure (the Stryker Corporation attack), a surge of 60+ hacktivist groups coordinating DDoS and defacement campaigns, and a fundamental shift in Iranian APT tradecraft from custom malware to identity and management-plane weaponization.

### 2.2 Diagram Overview of Attacks/Methods

```
┌───────────────────────────────────────────────────────────────────────┐
│               IRAN CYBER THREAT LANDSCAPE — MAR 2026                 │
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐   │
│  │  MOIS       │     │  IRGC-CEC        │     │  PROXY/          │   │
│  │  (APT34,    │     │  (APT33,         │     │  HACKTIVIST      │   │
│  │  MuddyWater,│     │  APT35, APT42,   │     │  (60+ groups)    │   │
│  │  Scarred    │     │  Cotton          │     │  (Dark Storm,    │   │
│  │  Manticore, │     │  Sandstorm,      │     │  RipperSec,      │   │
│  │  Void       │     │  CyberAv3ngers,  │     │  Russian Legion, │   │
│  │  Manticore/ │     │  Tortoiseshell)  │     │  NoName057,      │   │
│  │  Handala)   │     │                  │     │  FAD Team)       │   │
│  └──────┬──────┘     └────────┬─────────┘     └────────┬─────────┘   │
│         │                     │                         │             │
│         ▼                     ▼                         ▼             │
│  ┌─────────────┐     ┌──────────────────┐     ┌──────────────────┐   │
│  │ WIPER       │     │ ESPIONAGE &      │     │ DDoS &           │   │
│  │ ATTACKS     │     │ ICS/OT           │     │ DEFACEMENT       │   │
│  │ ─ Intune    │     │ ─ Credential     │     │ ─ 149 attacks    │   │
│  │   abuse     │     │   harvesting     │     │   in 72 hours    │   │
│  │ ─ 200K+     │     │ ─ SCADA/PLC      │     │ ─ 110 orgs in   │   │
│  │   devices   │     │   targeting      │     │   16 countries   │   │
│  │ ─ Identity  │     │ ─ AI-enhanced    │     │ ─ Hack-and-leak  │   │
│  │   weaponiz. │     │   spearphishing  │     │ ─ Vishing scams  │   │
│  └──────┬──────┘     └────────┬─────────┘     └────────┬─────────┘   │
│         │                     │                         │             │
│         └─────────────────────┼─────────────────────────┘             │
│                               ▼                                       │
│  ┌───────────────────────────────────────────────────────────────┐   │
│  │  TARGETS: U.S. Critical Infrastructure, Israel (Defense,     │   │
│  │  Healthcare, Energy), UAE, Jordan, Saudi Arabia, Kuwait,     │   │
│  │  Financial Services, Medical Devices, OT/ICS                 │   │
│  └───────────────────────────────────────────────────────────────┘   │
└───────────────────────────────────────────────────────────────────────┘
```

### 2.3 Attribution & Threat Actor Profiles

**MOIS-Directed Actors:**

- **Handala / Void Manticore (Storm-0842, Banished Kitten, Dune)** — The most prominent Iranian hacktivist persona active in this conflict. Linked to Iran's Ministry of Intelligence and Security (MOIS). Confirmed destructive capability: executed the Stryker Corporation wiper attack on March 11, 2026, wiping 80,000+ devices across 79 countries via compromised Microsoft Intune Global Admin credentials. Operates under a "faketivist" persona to obscure state-level attribution. Also operates under regional personas Karma and Homeland Justice. Employs a documented dual-actor handoff model where Scarred Manticore conducts initial espionage before passing targets to Handala for destruction.
- **APT34 (OilRig)** — Long-running MOIS espionage group targeting government, defense, financial services, and academic sectors across the Middle East and the U.S.
- **MuddyWater** — MOIS-linked group focused on telecommunications, academia, and government targets with phishing, LOLBins, and custom implants.
- **Scarred Manticore** — Stealthy long-dwell espionage operator; provides initial access to Void Manticore/Handala for destructive follow-on operations.

**IRGC-Directed Actors:**

- **CyberAv3ngers** — Assessed as the highest-priority state-directed cyber actor by BeyondTrust. Presents as a hacktivist collective, but the U.S. Treasury Department sanctioned six IRGC-CEC officials for directing its operations. Known for ICS/OT targeting, particularly U.S. water and wastewater facilities using the IOCONTROL ICS cyberweapon.
- **APT33 / Peach Sandstorm** — IRGC-aligned group that shifted decisively toward credential-based initial access from early 2023. Known for Tickler backdoor deployment and large-scale password spraying.
- **APT35 / Charming Kitten** — IRGC cyber espionage group focused on social engineering campaigns against political and academic targets.
- **APT42** — IRGC intelligence group specializing in individual surveillance, credential harvesting, and election interference operations.
- **Cotton Sandstorm** — IRGC-linked group known for influence operations and disruption campaigns.
- **Fox Kitten** — Known for exploiting public-facing VPN appliances for initial access.
- **UNC1549 / Tortoiseshell / Imperial Kitten** — IRGC-linked groups conducting targeted espionage against defense, energy, and aerospace sectors.

**Hacktivist Coalitions (60+ groups):**

- **Electronic Operations Room** — Coordination hub formed Feb 28, 2026, orchestrating multiple Iranian state-aligned hacktivist personas.
- **Dark Storm Team** — DDoS and defacement campaigns against Israeli and Western targets.
- **Cyber Islamic Resistance** — Umbrella collective coordinating RipperSec, Cyb3rDrag0nzz, and others for synchronized DDoS, data-wiping, and defacement.
- **Russian Legion, NoName057(16), Cardinal** — Pro-Russian collectives joining the Iran-aligned campaign against Israeli and U.S. targets.
- **FAD Team** — Claimed unauthorized access to SCADA/PLC systems in Israel.
- **APT Iran** — Pro-Iranian hack-and-leak collective targeting Jordan and Israeli critical infrastructure.

---

## 3. Geopolitical Implications

The cyber dimension of the Iran conflict carries several significant geopolitical implications derived from the analyzed reports:

**3.1 Degraded Iranian State Command but Persistent Threat.** Iran's near-total internet blackout (1–4% connectivity since Feb 28) has degraded centralized command-and-control for state-sponsored cyber operations. However, the Stryker attack demonstrates that dispersed MOIS-directed cells retain the capability to execute destructive operations from outside Iran, likely via Starlink IP ranges (as observed by Check Point Research for Handala operations during the January 2026 blackout).

**3.2 Iran's Internal Intelligence Crisis.** Reports indicate massive internal purges within Iranian intelligence services driven by suspicion of Israeli and U.S. intelligence penetration. This has forced a return to slower analog communication mechanisms, creating a disconnect between Tehran's interim government and the IRGC/military rank-and-file. The fear of appearing "moderate" reduces the scope for clandestine diplomacy through intelligence-led backchannels.

**3.3 Escalation Beyond the Middle East.** The Stryker attack marked a qualitative shift: the first confirmed destructive Iranian cyber operation against a Fortune 500 U.S. corporation. Targeting rationale was tied to Stryker's U.S. military supply contracts and its acquisition of an Israeli medical technology firm (Orthospace). This establishes a pattern where organizations with U.S. military contracts or Israeli business ties may become targets of opportunity.

**3.4 Multi-Domain Convergence.** The conflict represents a new paradigm where intelligence (HUMINT, SIGINT, AI-powered analysis), kinetic operations, and cyber operations are fused into a single operational continuum. LLMs and autonomous systems are reportedly being used for intelligence processing and, potentially, autonomous targeting decisions.

**3.5 Insurance and Financial Markets Impact.** Moody's and other risk assessors note that attacks by state-aligned groups operating under hacktivist personas raise complex questions about war exclusion wording in cyber insurance policies. Stryker's stock dropped approximately 4.5% following the March 11 attack.

---

## 4. Technical Details

### 4.1 Malware Analysis / Tools / Techniques

**Identity Weaponization — The Paradigm Shift:**

The defining technical innovation in this conflict is the weaponization of enterprise management infrastructure. In the Stryker attack, Handala did not deploy custom malware. Instead, the attackers compromised Microsoft Entra ID Global Administrator credentials, used Microsoft Intune (MDM platform) to issue legitimate remote-wipe commands to 80,000+ endpoints globally. This bypasses all traditional EDR/AV detection because the wipe commands are issued through a trusted, signed Microsoft service.

This represents a fundamental evolution from Iran's prior wiper tooling:
- **2012-era (Shamoon):** MBR-wiping via custom compiled malware
- **2023-2025 (BiBi, Hatef, Hamsa):** Cross-platform file-level destruction (.NET for Windows, Bash for Linux), overwriting files with 4096-byte random data blocks
- **2026 (Stryker/Handala):** No malware at all — abuse of legitimate enterprise management tools (Intune, Entra ID PIM) via compromised privileged identities

**Known Wiper Malware Families (Historical, still relevant):**
- **SHAMOON / Disttrack** — MBR-wiping malware (2012, 2016-17, 2018)
- **BiBi Wiper** — Cross-platform (Windows+Linux), file-level destructive malware
- **Hatef Wiper** — .NET-based Windows wiper
- **Hamsa Wiper** — Bash-based Linux wiper
- **DROPSHOT / SHAPESHIFT** — Destructive wiper family
- **No-Justice Wiper** — Partition table manipulation
- **Cl Wiper** — Uses EldoS RawDisk driver for disk-level destruction
- **IOCONTROL** — ICS cyberweapon targeting industrial control systems
- **RustyWater** — Rust-based implant introduced in early 2026

**Other Observed Tools:**
- **Tickler Backdoor** — Associated with APT33/Peach Sandstorm
- **Karma Shell** — Base64-with-XOR web shell used by Handala
- **ADRecon** — Active Directory enumeration tool
- **StealC Infostealer** — Deployed with incremental domain naming for evasion
- **Malicious RedAlert APK** — Trojanized version of Israel's Home Front Command application delivering mobile surveillance malware

### 4.2 Infrastructure Analysis

**Phishing Infrastructure:**
Unit 42 identified 7,381 conflict-themed phishing URLs across 1,881 unique hostnames. Evasion tactics include TLD rotation, subdomain chaining, and purpose-built infrastructure mimicking corporate portals and government payment workflows. Specific campaigns include:
- UAE-targeted campaigns exploiting Emirates-branded financial services
- Dubai-themed real estate and luxury lifestyle lures
- Iranian bank impersonation campaigns
- StealC infostealer infrastructure using incremental domain naming

**Hacktivist Coordination:**
The "Electronic Operations Room," established Feb 28, 2026, serves as a command-coordination point for multiple hacktivist groups on Telegram. A coalition of 12+ hacktivist groups executed 149 DDoS attacks against 110 organizations across 16 countries within the first 72 hours.

**Key Operational Note:**
Check Point Research observed Handala campaigns originating from Starlink IP ranges during Iran's blackout, indicating dispersed operational cells with independent internet connectivity. MOIS and IRGC cyber units are assessed to operate with sufficient autonomy to continue operations even under degraded centralized coordination.

### 4.3 Incident Response — Stryker Case Study

**Timeline:**
- ~03:30 AM EDT, March 11, 2026: Handala initiates coordinated wipe via compromised Intune admin credentials
- Morning of March 11: Employees across 79 countries discover wiped devices; BYOD phones factory-reset (losing photos, banking apps, authenticator tokens)
- March 11: Handala claims responsibility via Telegram; Stryker files 8-K with SEC confirming "global network disruption to our Microsoft environment"
- March 11: Stryker closes Michigan HQ; 4,100+ employees idled at Cork, Ireland facility alone
- Post-incident: Stryker observed performing active SPF flattening (DNS lookups dropped from 9/10 to 1/10), indicating email hardening as part of remediation

**Key Finding:** Prior to the Handala attack, a separate threat actor "0APT" had allegedly claimed a breach of stryker.com on February 5, 2026 — over a month before the wiper event. This is unverified but consistent with Stryker becoming a high-profile target.

---

## 5. Detection Opportunities

**5.1 Identity and Privilege Monitoring (HIGHEST PRIORITY):**
- Monitor Entra ID sign-in logs for anomalous Global Administrator authentication (especially from non-corporate IP ranges, Starlink ranges, commercial VPN endpoints)
- Alert on mass device wipe/factory reset commands issued through Microsoft Intune (RemoteWipe, FactoryReset actions)
- Implement Just-In-Time (JIT) access for all administrative roles; use Microsoft Entra PIM for eligible role assignments
- Configure Conditional Access policies to block privileged role access from non-compliant or unmanaged devices
- Alert on bulk changes to device compliance policies or configuration profiles

**5.2 Wiper Precursor Detection:**
- Monitor for ADRecon execution and large-scale Active Directory enumeration
- Detect LSASS credential dumping via comsvcs.dll
- Alert on anomalous GPO modifications, particularly logon script changes
- Monitor for EldoS RawDisk driver loading
- Detect MBR/GPT manipulation attempts
- Alert on recursive file operations across multiple directories at high velocity

**5.3 Phishing and Social Engineering:**
- Block known conflict-themed phishing domains (see IoC list)
- Monitor for newly registered domains impersonating telecommunications providers, airlines, law enforcement, and energy companies
- Flag subdomain chaining patterns and rapid TLD rotation
- Alert on malicious APK distribution (particularly RedAlert clones)

**5.4 Network and Infrastructure:**
- Ingest audit logs from device management tools (Intune, JAMF, etc.) into SIEM/XDR platform
- Configure DDoS mitigation playbooks and validate response procedures
- Remove or restrict non-critical internet-facing services, especially those lacking MFA
- Monitor for abnormal outbound data transfer volumes from storage accounts

**5.5 SIGMA Rule Concepts:**

```yaml
# Detect Mass Intune Wipe Commands
title: Mass Microsoft Intune Device Wipe Detection
status: experimental
description: Detects potential abuse of Intune remote wipe for destructive operations
logsource:
  product: azure
  service: auditlogs
detection:
  selection:
    Activity|contains:
      - 'RemoteWipe'
      - 'FactoryReset'
      - 'wipeManagedAppRegistrationsByDeviceTag'
  timeframe: 1h
  condition: selection | count() > 10
level: critical
tags:
  - attack.impact
  - attack.t1485
  - attack.t1561
```

---

## 6. Conclusion

The Iran conflict cyber escalation represents a qualitative shift in state-sponsored destructive operations. The Handala/Stryker attack demonstrates that Iranian-linked groups have evolved beyond custom malware toward the weaponization of enterprise identity and management infrastructure — an approach that renders traditional signature-based and behavior-based detection largely ineffective.

The key takeaway for defenders is that the most dangerous Iranian cyber capability is no longer a novel wiper binary, but a compromised Global Administrator credential paired with legitimate cloud management tools. Organizations with U.S. military contracts, Israeli business ties, or defense-adjacent operations should treat the current period as the highest-risk window and prioritize identity hardening, JIT administrative access, and monitoring of MDM/MAM platforms.

The next 30–90 days represent a critical watch period. As Iranian cyber units reconstitute following the blackout and leadership degradation, a transition from opportunistic hacktivist-style attacks to more deliberate, coordinated state-sponsored campaigns is expected.

---

## 7. Indicators of Compromise (IoC List)

> **Note:** Many IoCs from the Stryker/Handala attack are pending release by investigating authorities (NCSC Ireland, Stryker corporate security, CrowdStrike, Mandiant). The following are derived from public reporting across the analyzed sources.

### 7.1 Domains — Phishing Infrastructure (Conflict-Themed)

| IoC | Type | Context |
|-----|------|---------|
| `hyperfilevault1[.]xyz` | Domain | Conflict-themed scam domain (Unit 42) |

> Unit 42 identified 7,381 phishing URLs across 1,881 hostnames. Full IoC feeds are available via Palo Alto Networks threat intelligence feeds and the Unit 42 Threat Brief.

### 7.2 Malware Indicators

| IoC | Type | Context |
|-----|------|---------|
| Handala logo displayed on wiped device login screens | Behavioral | Defacement indicator post-wipe (Stryker attack) |
| Exploitation of Microsoft Intune MDM RemoteWipe/FactoryReset | TTP | Primary destructive vector (Stryker attack) |
| Trojanized RedAlert APK (Israeli Home Front Command replica) | Android Malware | Mobile surveillance and data-exfiltrating malware |
| StealC infostealer infrastructure with incremental domain naming | Malware Infrastructure | Evasion tactic observed by Unit 42 |

### 7.3 Network Indicators

| IoC | Type | Context |
|-----|------|---------|
| Starlink IP ranges | Network | Handala operations during Iran blackout (Check Point) |
| Commercial VPN node IPs (hundreds of logon attempts) | Network | Handala initial access via VPN credential brute-force |

### 7.4 Tools and Artifacts

| IoC | Type | Context |
|-----|------|---------|
| `comsvcs.dll` (LSASS dump) | Tool Abuse | Credential dumping technique (Handala historical) |
| ADRecon | Enumeration Tool | Active Directory reconnaissance (Handala historical) |
| EldoS RawDisk driver | Driver | Disk-level destruction driver (Cl Wiper) |

> **Recommended Action:** Subscribe to Palo Alto Networks, SentinelOne, and CISA threat intelligence feeds for real-time IoC updates as the situation evolves. Monitor NCSC Ireland, Stryker corporate communications, and major vendor (CrowdStrike, Mandiant, Microsoft MSTIC) publications for Stryker-specific IoCs.

---

## 8. MITRE ATT&CK Techniques List

| Technique ID | Name | Tactic | Description |
|-------------|------|--------|-------------|
| T1078 | Valid Accounts | Initial Access, Persistence, Privilege Escalation, Defense Evasion | Handala compromised Microsoft Entra ID Global Administrator credentials to access and weaponize Intune management plane |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | Compromised cloud administrator credentials used to issue remote wipe commands via Microsoft Intune |
| T1566 | Phishing | Initial Access | AI-enhanced spearphishing campaigns targeting credentials; 7,381+ conflict-themed phishing URLs identified |
| T1566.001 | Phishing: Spearphishing Attachment | Initial Access | Malicious RedAlert APK delivered via SMS phishing for mobile surveillance |
| T1110 | Brute Force | Credential Access | Handala's documented use of VPN credential brute-force (hundreds of logon attempts from commercial VPN nodes) |
| T1003 | OS Credential Dumping | Credential Access | LSASS credential dumping via comsvcs.dll (Handala historical TTP) |
| T1003.001 | LSASS Memory | Credential Access | Specific sub-technique for memory-based credential extraction |
| T1087 | Account Discovery | Discovery | ADRecon tool usage for Active Directory enumeration |
| T1021.001 | Remote Desktop Protocol | Lateral Movement | RDP as primary lateral movement method (Handala historical) |
| T1072 | Software Deployment Tools | Execution, Lateral Movement | Abuse of Microsoft Intune (MDM) as a destructive payload delivery mechanism |
| T1485 | Data Destruction | Impact | Wiper malware families (BiBi, Hatef, Hamsa, Shamoon) and Intune-based mass device wipe |
| T1561 | Disk Wipe | Impact | MBR/partition-level wiping (historical: Shamoon, No-Justice) |
| T1561.001 | Disk Content Wipe | Impact | Overwriting file content with random data (BiBi, Hatef — 4096-byte blocks) |
| T1561.002 | Disk Structure Wipe | Impact | MBR/GPT manipulation (Shamoon, No-Justice) |
| T1491 | Defacement | Impact | Handala logo displayed on wiped devices; website defacement campaigns |
| T1491.001 | Internal Defacement | Impact | Login screen replacement with Handala branding post-wipe |
| T1498 | Network Denial of Service | Impact | 149 DDoS attacks against 110 organizations in 16 countries within 72 hours |
| T1499 | Endpoint Denial of Service | Impact | Mass device wipe causing global operational disruption |
| T1005 | Data from Local System | Collection | Data exfiltration (50TB claimed from Stryker; Handala data theft operations) |
| T1567 | Exfiltration Over Web Service | Exfiltration | Data exfiltration via cloud services |
| T1199 | Trusted Relationship | Initial Access | Supply chain compromise via managed service providers (Handala historical TTP) |
| T1484 | Domain Policy Modification | Defense Evasion, Privilege Escalation | GPO logon script modification for wiper distribution |
| T1484.001 | Group Policy Modification | Defense Evasion | Specific sub-technique for GPO manipulation |
| T1059 | Command and Scripting Interpreter | Execution | Use of LOLBins and scheduled tasks for wiper execution |
| T1218 | System Binary Proxy Execution | Defense Evasion | Living-off-the-land binaries for stealth execution |
| T1583 | Acquire Infrastructure | Resource Development | Purpose-built phishing infrastructure with TLD rotation and subdomain chaining |
| T1583.001 | Domains | Resource Development | 1,881 unique hostnames registered for conflict-themed phishing |
| T1656 | Impersonation | Defense Evasion | Impersonation of telecommunications providers, airlines, law enforcement, and energy corporations |
| T1592 | Gather Victim Host Information | Reconnaissance | AI-assisted reconnaissance against exposed ICS/OT systems |

---

*This report is for informational purposes only. It is derived exclusively from publicly available open-source intelligence (OSINT). TI Mindmap HUB does not generate, fabricate, or independently verify threat claims — it processes and structures information already in the public domain. All findings reflect information available as of the reporting date.*

*For STIX 2.1 bundles, IOC feeds, and interactive threat mindmaps, visit [ti-mindmap-hub.com](https://ti-mindmap-hub.com).*
