---
title: "14-Day Threat Intelligence Briefing — Sector-Focused Assessment"
date: "2026-04-06"
period: "2026-03-23 to 2026-04-06"
severity: "CRITICAL"
classification: "TLP:WHITE"
sectors:
  - financial
  - insurance
  - retail
  - iran-threat-actors
  - spain
author: "TI Mindmap HUB Research"
---

# 🛡️ 14-Day Threat Intelligence Briefing

> **Report Date:** 2026-04-06  
> **Period Covered:** March 23 – April 6, 2026  
> **Classification:** TLP:WHITE  
> **Overall Threat Level:** CRITICAL  

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Financial Sector](#2-financial-sector)
3. [Insurance Sector](#3-insurance-sector)
4. [Retail Sector](#4-retail-sector)
5. [Iran Threat Actors](#5-iran-threat-actors)
6. [Spain Focus](#6-spain-focus)
7. [Cross-Sector: Supply Chain Threats](#7-cross-sector-supply-chain-threats)
8. [Weekly Briefing Context](#8-weekly-briefing-context)
9. [Consolidated IOC List](#9-consolidated-ioc-list)
10. [Consolidated MITRE ATT&CK Matrix](#10-consolidated-mitre-attck-matrix)

---

## 1. Executive Summary

The last 14 days (March 23 – April 6, 2026) have been defined by three converging crisis vectors:

1. **Supply chain compromise at unprecedented scale**: TeamPCP compromised five major vendor ecosystems (Trivy, Checkmarx KICS, LiteLLM, Telnyx, multiple npm packages) and the UNC1069 (North Korea) group compromised the Axios npm package (100M+ weekly downloads). These attacks affect ALL sectors including financial, insurance, and retail.

2. **Iran-aligned destructive cyber operations**: Post-Operation Epic Fury, Iranian state-aligned actors have escalated to the highest levels ever observed. The Stryker Corporation wiper attack (80,000+ devices across 79 countries) demonstrated a paradigm shift to identity weaponization using Microsoft Intune. 60+ hacktivist groups are coordinating attacks.

3. **Critical vulnerability exploitation**: Active exploitation of FortiClient EMS (CVE-2026-35616), BeyondTrust (CVE-2026-1731), Ivanti EPMM (CVE-2026-1281/CVE-2026-1340), React2Shell/Next.js (CVE-2025-55182), F5 BIG-IP APM RCE, and device code phishing attacks surging 37x.

**Impact Assessment by Sector:**

| Sector | Threat Level | Primary Risk |
|--------|-------------|-------------|
| Financial | 🔴 CRITICAL | Supply chain compromise (Axios/LiteLLM in payment APIs), credential theft, DPRK-nexus heists |
| Insurance | 🟠 HIGH | War exclusion complexity (Iran wipers), Stryker-class claims, identity weaponization |
| Retail | 🔴 CRITICAL | Axios supply chain (e-commerce), Agentic AI fraud, credential harvesting |
| Iran Actors | 🔴 CRITICAL | Wiper escalation, ICS/OT targeting, identity weaponization |
| Spain | 🟡 ELEVATED | EU data breach (TeamPCP/CERT-EU), Iran hacktivist spillover, phishing |

---

## 2. Financial Sector

### 2.1 Report Summary

The financial sector faces a CRITICAL threat level driven by three primary vectors:

**A. Supply Chain Compromise — Direct Financial Impact**

- **Axios npm compromise (March 31)**: Axios powers ~80% of cloud and code environments, including banking APIs, fintech platforms, and payment processing systems. The WAVESHAPER.V2 RAT deployed by UNC1069 (DPRK) targets credential theft and has PE injection capabilities. Any financial institution running Node.js-based payment APIs, trading platforms, or mobile banking backends that auto-updated to `axios@1.14.1` or `axios@0.30.4` during the 169-minute exposure window is potentially compromised.

- **LiteLLM PyPI compromise (March 24-25)**: LiteLLM is widely used in fintech for AI-powered fraud detection, customer service, and risk analysis. Trojanized versions harvested cloud credentials including AWS/Azure/GCP tokens — potentially exposing financial infrastructure credentials.

- **Drift Protocol heist (April 2)**: North Korean hackers stole $280M from the Drift DeFi protocol by seizing Security Council administrative powers. This follows the pattern of DPRK targeting financial platforms for state revenue generation.

**B. Device Code Phishing Surge (37x increase)**

OAuth 2.0 Device Authorization Grant abuse is surging and directly threatens financial services that use Azure AD/Entra ID for authentication. Financial institutions using Microsoft 365 are primary targets.

**C. Critical Vulnerabilities Affecting Financial Infrastructure**

| CVE | Product | Severity | EPSS Score (Est.) | Financial Sector Relevance |
|-----|---------|----------|-------------------|---------------------------|
| CVE-2026-35616 | FortiClient EMS | CRITICAL | 0.92 | Widely deployed in banking endpoint management |
| CVE-2026-1731 | BeyondTrust PRA/RS | CRITICAL | 0.87 | PAM solution used by financial institutions; VShell/SparkRAT exploitation observed |
| CVE-2026-1281 | Ivanti EPMM | CRITICAL | 0.81 | Mobile device management for banking/fintech |
| CVE-2026-1340 | Ivanti EPMM | CRITICAL | 0.78 | Chained with CVE-2026-1281 |
| CVE-2025-55182 | Next.js (React2Shell) | HIGH | 0.73 | Financial web applications, customer portals |

### 2.2 Threat Actors Involved

| Actor | Nexus | Targeting Financial Sector For |
|-------|-------|-------------------------------|
| **UNC1069** | DPRK (North Korea) | Revenue generation via supply chain compromise; stole $280M from Drift |
| **TeamPCP** | Cybercrime | Credential theft at scale; Vect ransomware partnership; EU Commission data breach |
| **Handala / Void Manticore** | Iran (MOIS) | Financial disruption via identity weaponization |
| **CyberAv3ngers** | Iran (IRGC) | Financial infrastructure ICS/OT targeting |
| **Scattered Spider / Muddled Libra** | Cybercrime | Social engineering targeting financial sector; operational playbook updated Feb 2026 |

### 2.3 MITRE ATT&CK Techniques (Financial Focus)

| Technique | ID | Context |
|-----------|----|---------|
| Supply Chain Compromise | T1195.002 | Axios, LiteLLM poisoning in financial software supply chains |
| Valid Accounts: Cloud | T1078.004 | Device code phishing, stolen cloud tokens from supply chain |
| Credential Dumping | T1003 | WAVESHAPER.V2 credential theft capabilities |
| PE Injection | T1055.002 | In-memory payload execution to evade banking EDR |
| Software Deployment Tools | T1072 | Intune weaponization affecting financial endpoints |
| Data Encrypted for Impact | T1486 | Vect ransomware targeting via stolen credentials |

### 2.4 Financial Sector IOCs

| Type | Value | Context |
|------|-------|---------|
| Domain | `sfrclak[.]com` | UNC1069 WAVESHAPER.V2 C2 (Axios attack) |
| IPv4 | `142.11.206[.]73` | Primary C2 for financial credential theft |
| IPv4 | `23.254.167[.]216` | Secondary UNC1069 infrastructure |
| SHA256 | `5bb67e88846096f1f8d42a0f0350c9c46260591567612ff9af46f98d1b7571cd` | Malicious axios-1.14.1.tgz |
| SHA256 | `59336a964f110c25c112bcc5adca7090296b54ab33fa95c0744b94f8a0d80c0f` | Malicious axios-0.30.4.tgz |
| SHA256 | `58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668` | plain-crypto-js-4.2.1.tgz |
| Email | `ifstap@proton[.]me` | Attacker email used for npm account takeover |
| Package | `axios@1.14.1`, `axios@0.30.4` | Compromised npm packages |
| Package | `litellm==1.82.7`, `litellm==1.82.8` | Compromised PyPI packages |

### 2.5 Recommended Financial Sector Actions

1. **IMMEDIATE**: Audit all Node.js environments for `axios@1.14.1`, `axios@0.30.4`, `plain-crypto-js@4.2.1`
2. **IMMEDIATE**: Audit all Python environments for `litellm==1.82.7`, `litellm==1.82.8`
3. Rotate ALL credentials on systems that executed compromised packages
4. Review Conditional Access policies — block device code authentication flows
5. Implement FortiClient EMS emergency patch for CVE-2026-35616
6. Monitor for WAVESHAPER.V2 C2 indicators (IE8/WinXP User-Agent on port 8000)

---

## 3. Insurance Sector

### 3.1 Report Summary

The insurance sector faces unique and compounding risks from this threat cycle:

**A. War Exclusion Complexity — The Stryker Precedent**

The Stryker Corporation wiper attack (March 11, 2026) by Iran-linked Handala presents a landmark challenge for cyber insurance:

- Handala claims hacktivist identity but is confirmed MOIS-directed (state sponsor)
- 80,000+ devices wiped across 79 countries via Microsoft Intune abuse
- Stryker stock dropped ~4.5% post-attack
- 4,100+ employees idled at Cork, Ireland facility alone
- Targets identified by US military contracts and Israeli business ties (Orthospace acquisition)

**Moody's explicitly flagged** that attacks by state-aligned groups operating under hacktivist personas raise complex questions about **war exclusion wording** in cyber insurance policies. This creates a direct underwriting risk for:
- Policies covering defense contractors
- Companies with Israeli business ties
- US critical infrastructure operators
- Medical device/healthcare companies

**B. Claims Systems Exposure via Supply Chain**

Insurance claims processing platforms commonly use:
- Axios (via web portals) — compromised
- LiteLLM (via AI-powered claim analysis) — compromised
- FortiClient EMS (endpoint management) — actively exploited CVE

**C. Identity Weaponization as Emerging Claims Category**

The Stryker attack demonstrates that **no malware deployment** was needed — legitimate Microsoft Intune commands wiped devices. This challenges traditional cyber insurance claims processes that rely on malware evidence for attribution and coverage determination.

### 3.2 Threat Actors Targeting Insurance Interests

| Actor | Risk to Insurance Sector |
|-------|-------------------------|
| **Handala / Void Manticore** | Precedent-setting wiper attacks with war exclusion ambiguity |
| **TeamPCP + Vect RaaS** | 300,000+ potential BreachForums operators with stolen credentials; mass ransomware claims risk |
| **Qilin Ransomware** | Active in Europe (Die Linke attack April 3); confirmed data exfiltration for double extortion |

### 3.3 TTPs Relevant to Insurance Underwriting Models

| TTP | Insurance Impact |
|-----|-----------------|
| Identity Weaponization (T1078 + T1072) | No malware artifacts = harder claims evidence |
| Supply Chain Compromise (T1195) | Cascading multi-policy claims from single incident |
| Mass Device Wipe via MDM (T1485) | Catastrophic business interruption, BYOD personal data loss |
| Ransomware-as-a-Service (T1486) | Democratized access = more frequent claims |
| Credential Theft at Scale | Aggregate exposure across multiple policyholders |

### 3.4 Insurance Sector Recommendations

1. **Review war exclusion clause language** in context of state-aligned hacktivist operations
2. **Assess aggregate exposure** to supply chain incidents (Axios affects 80% of cloud environments)
3. **Require policyholders** to demonstrate MAM/MDM hardening (JIT admin access, Conditional Access)
4. **Model catastrophic scenarios** where legitimate management tools are weaponized
5. **Update claims evidence requirements** to account for "no malware" destructive operations

---

## 4. Retail Sector

### 4.1 Report Summary

Retail faces CRITICAL risk from converging threats:

**A. Axios Supply Chain — E-Commerce Impact**

Axios is the backbone HTTP client for nearly all modern e-commerce platforms. The compromise directly affects:
- Online payment processing APIs
- Customer account management systems
- Inventory and order management systems
- Third-party marketplace integrations

The WAVESHAPER.V2 RAT deployed has full credential theft capabilities, meaning customer payment data, session tokens, and PII could be exfiltrated from compromised retail systems.

**B. Agentic AI Retail Fraud (Unit 42 Research)**

Unit 42 published research specifically on **"Retail Fraud in the Age of Agentic AI"** — autonomous AI agents performing:
- Automated account creation and credential stuffing at scale
- Product hoarding and price manipulation via bot armies
- Returns fraud automation
- Gift card and loyalty program exploitation
- Bypassing CAPTCHA and behavioral analysis via AI-powered browser automation

**C. React2Shell (CVE-2025-55182) — Automated Credential Theft**

Active large-scale exploitation of Next.js applications, which power a massive number of retail e-commerce frontends. Hackers are running automated credential theft campaigns against vulnerable Next.js apps.

**D. Device Code Phishing (37x Surge)**

Retail corporate environments using Microsoft 365 are targeted. Compromised employee accounts can pivot to POS management systems, inventory databases, and customer data stores.

### 4.2 Threat Actors Targeting Retail

| Actor | Nexus | Retail Targeting |
|-------|-------|-----------------|
| **UNC1069** | DPRK | Axios compromise affects e-commerce payment systems |
| **TeamPCP** | Cybercrime | CanisterWorm propagation into retail npm dependencies |
| **CrystalRAT (MaaS)** | Cybercrime | New RAT-as-a-service with keylogging, clipboard hijack for POS/payment theft |
| Phishing operators | Cybercrime | QR code-based scams mimicking courts/fines targeting retail customers |

### 4.3 CVEs Affecting Retail Infrastructure

| CVE | Product | EPSS (Est.) | Retail Context |
|-----|---------|-------------|----------------|
| CVE-2025-55182 | Next.js (React2Shell) | 0.73 | E-commerce frontends, credential theft from storefronts |
| CVE-2026-35616 | FortiClient EMS | 0.92 | Retail corporate endpoint management |
| CVE-2026-1731 | BeyondTrust | 0.87 | POS system PAM infrastructure |
| Progress ShareFile vulns | ShareFile | 0.65 | Pre-auth RCE; retail document exchange platforms |

### 4.4 Retail IOCs

All IOCs from Section 2.4 (Financial) apply to retail. Additional retail-specific:

| Type | Value | Context |
|------|-------|---------|
| Package | `@shadanai/openclaw` | Downstream Axios propagation in npm |
| Package | `@qqbrowser/openclaw-qbot@0.0.130` | Downstream Axios propagation |
| SHA256 | `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09` | SILKBELL dropper (setup.js) targeting npm installs |
| SHA256 | `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101` | WAVESHAPER.V2 Windows RAT (retail POS risk) |
| Registry | `HKCU\...\Run\MicrosoftUpdate` | Windows persistence indicator |
| Path (macOS) | `/Library/Caches/com.apple.act.mond` | macOS RAT binary |
| Path (Windows) | `%PROGRAMDATA%\wt.exe` | Renamed PowerShell for EDR evasion |

### 4.5 MITRE ATT&CK — Retail Relevant

| Technique | ID | Retail Context |
|-----------|----|----------------|
| Supply Chain Compromise | T1195 | Axios poisoning in e-commerce stacks |
| User Execution: Malicious File | T1204.002 | Auto-executes via `npm install` in CI/CD |
| Credentials in Files | T1552.001 | .env file sweep for payment API keys |
| Cloud Instance Metadata API | T1552.005 | Cloud-hosted retail platform credential theft |
| Ingress Tool Transfer | T1105 | RAT download to retail servers |
| Boot/Logon Autostart Execution | T1547.001 | Persistence on retail Windows terminals |

### 4.6 Retail Recommendations

1. **IMMEDIATE**: Full npm/Node.js audit across all e-commerce and POS backend systems
2. Patch or mitigate Next.js applications against React2Shell (CVE-2025-55182)
3. Deploy Agentic AI fraud detection countermeasures (behavioral analysis, device fingerprinting)
4. Review all npm `postinstall` hooks in production dependencies
5. Implement SRI (Subresource Integrity) and CSP headers on customer-facing storefronts

---

## 5. Iran Threat Actors

### 5.1 Report Summary

**This is the most operationally significant section of the briefing.** Following Operation Epic Fury/Roaring Lion (Feb 28, 2026), Iranian state-aligned cyber operations have escalated to the highest levels ever observed. Iran's internet has been at 1-4% connectivity for 27+ consecutive days, yet dispersed attack cells continue operating.

### 5.2 Active Iranian APT Groups & Operations

#### APT33 / Peach Sandstorm (IRGC)
- **Status**: ACTIVE
- **Shift**: Decisive move to credential-based initial access since 2023
- **Tools**: Tickler Backdoor, large-scale password spraying
- **Targets**: Defense, energy, financial services
- **Recent Activity**: Active password spraying campaigns against critical infrastructure

#### APT34 / OilRig (MOIS)
- **Status**: ACTIVE
- **Targets**: Government, defense, financial services, academic sectors — Middle East and US
- **TTPs**: Custom implants, DNS tunneling, credential harvesting

#### APT35 / Charming Kitten (IRGC)
- **Status**: ACTIVE
- **Focus**: Social engineering campaigns against political and academic targets
- **Recent**: AI-enhanced spearphishing capabilities

#### MuddyWater (MOIS)
- **Status**: ACTIVE
- **Targets**: Telecommunications, academia, government
- **TTPs**: Phishing, LOLBins, custom implants

#### CyberAv3ngers (IRGC-CEC)
- **Status**: HIGHEST PRIORITY (per BeyondTrust assessment)
- **Profile**: State-directed but presents as hacktivist collective
- **Sanctions**: 6 IRGC-CEC officials sanctioned by US Treasury
- **Capability**: IOCONTROL ICS cyberweapon targeting water/wastewater facilities
- **Critical**: Direct ICS/OT targeting capability

#### Handala / Void Manticore (MOIS / Storm-0842)
- **Status**: MOST ACTIVE — Confirmed destructive operations
- **Key Attack**: Stryker Corporation wiper — March 11, 2026
  - 80,000+ devices wiped in 79 countries
  - Weaponized Microsoft Intune Global Admin credentials
  - No malware deployed — legitimate MDM commands used
  - Operated from Starlink IP ranges during Iran blackout
- **Also Known As**: Karma, Homeland Justice, Banished Kitten, Dune
- **Dual-Actor Model**: Scarred Manticore conducts espionage → Handala executes destruction

### 5.3 The Paradigm Shift: Identity Weaponization

**This is the defining technical evolution of the conflict:**

```
EVOLUTION OF IRANIAN DESTRUCTIVE CAPABILITY:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
2012: Shamoon         → MBR wipe via custom malware
2023: BiBi/Hatef      → File-level destruction (.NET/Bash)
2026: Stryker/Handala → NO MALWARE — Intune remote wipe via 
                        compromised Global Admin credentials
```

The Stryker attack bypasses ALL traditional EDR/AV detection because wipe commands come from a trusted, signed Microsoft service.

### 5.4 Hacktivist Coalition (60+ Groups)

The **Electronic Operations Room** (formed Feb 28, 2026) coordinates multiple hacktivist groups:

| Group | Activities |
|-------|-----------|
| Dark Storm Team | DDoS + defacement vs Israel/Western targets |
| Cyber Islamic Resistance | Coordinates RipperSec, Cyb3rDrag0nzz |
| Russian Legion / NoName057(16) | Pro-Russian groups joining Iran-aligned campaign |
| FAD Team | Claims SCADA/PLC access in Israel |
| APT Iran | Hack-and-leak vs Jordan/Israeli critical infrastructure |

**First 72 hours**: 149 DDoS attacks against 110 organizations in 16 countries.

### 5.5 STIX Bundle Highlights — Iran Threat Actors

```json
{
  "type": "bundle",
  "id": "bundle--iran-conflict-2026-04-06",
  "objects": [
    {
      "type": "threat-actor",
      "id": "threat-actor--handala-void-manticore",
      "name": "Handala / Void Manticore",
      "aliases": ["Storm-0842", "Banished Kitten", "Dune", "Karma", "Homeland Justice"],
      "threat_actor_types": ["state-sponsored"],
      "roles": ["agent"],
      "sophistication": "expert",
      "resource_level": "government",
      "primary_motivation": "ideology",
      "secondary_motivations": ["dominance"],
      "description": "MOIS-directed destructive actor. Executed Stryker wiper via Intune weaponization."
    },
    {
      "type": "threat-actor",
      "id": "threat-actor--cyberav3ngers",
      "name": "CyberAv3ngers",
      "aliases": [],
      "threat_actor_types": ["state-sponsored"],
      "sophistication": "expert",
      "resource_level": "government",
      "primary_motivation": "ideology",
      "description": "IRGC-CEC directed. 6 officials sanctioned by US Treasury. Deploys IOCONTROL ICS cyberweapon."
    },
    {
      "type": "threat-actor",
      "id": "threat-actor--apt33",
      "name": "APT33 / Peach Sandstorm",
      "aliases": ["Elfin", "Refined Kitten", "Magnallium", "Holmium"],
      "threat_actor_types": ["state-sponsored"],
      "sophistication": "expert",
      "resource_level": "government",
      "primary_motivation": "organizational-gain",
      "description": "IRGC-aligned. Shifted to credential-based initial access. Deploys Tickler backdoor."
    },
    {
      "type": "threat-actor",
      "id": "threat-actor--apt34",
      "name": "APT34 / OilRig",
      "aliases": ["Helix Kitten", "Crambus", "Cobalt Gypsy"],
      "threat_actor_types": ["state-sponsored"],
      "sophistication": "expert",
      "resource_level": "government",
      "primary_motivation": "organizational-gain",
      "description": "MOIS espionage group. Financial services, government, defense targeting."
    },
    {
      "type": "threat-actor",
      "id": "threat-actor--muddywater",
      "name": "MuddyWater",
      "aliases": ["Mercury", "Seedworm", "Static Kitten", "Mango Sandstorm"],
      "threat_actor_types": ["state-sponsored"],
      "sophistication": "expert",
      "resource_level": "government",
      "primary_motivation": "organizational-gain",
      "description": "MOIS-linked. Telecom, academia, government targets. LOLBins and phishing."
    },
    {
      "type": "malware",
      "id": "malware--iocontrol",
      "name": "IOCONTROL",
      "malware_types": ["backdoor", "remote-access-trojan"],
      "is_family": true,
      "description": "ICS cyberweapon targeting industrial control systems, specifically water/wastewater SCADA/PLC."
    },
    {
      "type": "malware",
      "id": "malware--bibi-wiper",
      "name": "BiBi Wiper",
      "malware_types": ["wiper"],
      "is_family": true,
      "description": "Cross-platform wiper (Windows+Linux). Overwrites files with 4096-byte random data blocks."
    },
    {
      "type": "malware",
      "id": "malware--tickler",
      "name": "Tickler Backdoor",
      "malware_types": ["backdoor"],
      "is_family": true,
      "description": "Associated with APT33/Peach Sandstorm. Deployed after credential-based initial access."
    },
    {
      "type": "malware",
      "id": "malware--rustywater",
      "name": "RustyWater",
      "malware_types": ["backdoor"],
      "is_family": true,
      "description": "Rust-based implant introduced in early 2026 by Iranian aligned actors."
    },
    {
      "type": "malware",
      "id": "malware--stealc",
      "name": "StealC",
      "malware_types": ["information-stealer"],
      "is_family": true,
      "description": "Deployed with incremental domain naming for evasion in Iran-conflict phishing campaigns."
    },
    {
      "type": "attack-pattern",
      "id": "attack-pattern--identity-weaponization",
      "name": "Identity Weaponization via MDM",
      "description": "Compromise of Entra ID Global Admin → Intune RemoteWipe/FactoryReset of managed devices"
    },
    {
      "type": "indicator",
      "id": "indicator--hyperfilevault",
      "pattern": "[domain-name:value = 'hyperfilevault1.xyz']",
      "pattern_type": "stix",
      "indicator_types": ["malicious-activity"],
      "description": "Conflict-themed phishing domain"
    }
  ]
}
```

### 5.6 Full Iran IOC List

| Type | Value | Context |
|------|-------|---------|
| Domain | `hyperfilevault1[.]xyz` | Conflict-themed phishing (Unit 42) |
| Behavioral | Handala logo on wiped device login screens | Post-wipe defacement indicator |
| TTP | Microsoft Intune RemoteWipe/FactoryReset | Primary destructive vector |
| Malware | Trojanized RedAlert APK | Mobile surveillance malware impersonating Israeli civil defense app |
| Infrastructure | Starlink IP ranges | Handala operational cells during Iran blackout |
| Infrastructure | Commercial VPN node IPs | Credential brute-force for Handala initial access |
| Tool | `comsvcs.dll` (LSASS dump) | Credential dumping technique |
| Tool | ADRecon | Active Directory enumeration |
| Tool | EldoS RawDisk driver | Historical disk-level destruction |
| Malware | StealC infostealers | Incremental domain naming infrastructure |

**Note:** Unit 42 identified **7,381 phishing URLs** across **1,881 unique hostnames** — full IoC feeds available via Palo Alto Networks threat intelligence.

### 5.7 Iran MITRE ATT&CK Techniques

| ID | Technique | Tactic | Actor/Campaign |
|----|-----------|--------|---------------|
| T1078 | Valid Accounts | Initial Access | Handala — Entra ID Global Admin compromise |
| T1078.004 | Cloud Accounts | Initial Access | Intune admin credentials for mass wipe |
| T1566 | Phishing | Initial Access | 7,381+ conflict-themed URLs; AI-enhanced |
| T1566.001 | Spearphishing Attachment | Initial Access | Trojanized RedAlert APK |
| T1110 | Brute Force | Credential Access | Handala VPN credential brute-force |
| T1003 | OS Credential Dumping | Credential Access | comsvcs.dll LSASS dump |
| T1072 | Software Deployment Tools | Execution | Microsoft Intune weaponization |
| T1485 | Data Destruction | Impact | Wiper families (BiBi, Hatef, Hamsa, Shamoon) + Intune wipe |
| T1561 | Disk Wipe | Impact | MBR/partition wipe (historical) |
| T1491 | Defacement | Impact | Handala logo, website defacement |
| T1498 | Network DoS | Impact | 149 DDoS in 72 hours |
| T1484 | Domain Policy Modification | Defense Evasion | GPO manipulation for wiper deployment |
| T1059 | Command and Scripting Interpreter | Execution | LOLBins for stealth |
| T1583.001 | Domains | Resource Development | 1,881 hostnames for phishing infrastructure |
| T1656 | Impersonation | Defense Evasion | Telecom, airline, law enforcement impersonation |
| T1592 | Gather Victim Host Information | Reconnaissance | AI-assisted ICS/OT recon |

---

## 6. Spain Focus

### 6.1 Direct Spain-Related Threats

**A. European Commission Data Breach — CERT-EU Attribution to TeamPCP (April 3)**

CERT-EU attributed a major data breach at the European Commission to the TeamPCP hacking group. The breach exposed data from **30 EU entities**. Spain, as an EU member state with government representatives and agencies in EU institutions, is directly exposed. Spanish nationals, Permanent Representation staff, and Spanish government data shared with EU systems may have been compromised.

**B. Iran Hacktivist Spillover Risk**

The 60+ hacktivist groups operating under the Electronic Operations Room have targeted organizations across **16 countries** within the first 72 hours. While Spain is not a primary target, the following risk factors apply:
- Spanish military facilities host NATO and US military assets
- Spain's Rota Naval Base is a US Navy installation
- Spanish companies with Israeli business ties face Handala-class targeting risk
- Spanish banks with Middle East operations are within the threat surface

**C. Phishing Infrastructure Targeting EU/Spanish Organizations**

Unit 42's identification of 7,381 conflict-themed phishing URLs included campaigns targeting:
- UAE-branded financial services (relevant to Spanish banks with Gulf operations like BBVA, Santander)
- Government payment workflow impersonation (applicable to all EU governments)
- StealC infostealer deployment across European targets

**D. Supply Chain Exposure**

Spanish organizations are equally exposed to:
- Axios npm supply chain compromise (affects all Spanish fintech/e-commerce)
- LiteLLM PyPI compromise (affects AI-adopting Spanish enterprises)
- FortiClient EMS vulnerability (widely deployed in Spanish enterprise)

### 6.2 Spain-Specific Recommendations

1. **Government entities**: Verify exposure to EU Commission data breach via CERT-EU coordination
2. **Defense-adjacent organizations**: Apply Stryker-class identity hardening (JIT admin, Intune monitoring)
3. **Financial institutions (BBVA, Santander, CaixaBank)**: Heightened monitoring for Iran-conflict phishing targeting Gulf operations
4. **Critical infrastructure (CNI)**: Monitor for Iran-aligned hacktivist reconnaissance per CCN-CERT advisories
5. **All sectors**: Apply supply chain audit procedures for Axios and LiteLLM

---

## 7. Cross-Sector: Supply Chain Threats

### 7.1 TeamPCP Campaign (March 23 – April 3)

**The single most impactful campaign of the period.** From a single unrevoked CI credential, TeamPCP cascaded across five vendor ecosystems:

| Wave | Target | Method | Impact |
|------|--------|--------|--------|
| 1 | Aqua Security Trivy | `pull_request_target` GitHub Actions abuse | Credential exfiltration, 44 repos exposed |
| 2 | Checkmarx KICS | Stolen GitHub PATs | Credential theft, malicious VS Code extensions |
| 3 | LiteLLM (PyPI) | Stolen PyPI tokens | `.pth` persistence, cloud credential harvest |
| 4 | Telnyx SDK | Stolen PyPI credentials | WAV steganography, multi-platform RAT |
| 5 | npm / CanisterWorm | Automated propagation | ICP canister C2, Iran-targeted K8s wiper |
| 6 | Vect Ransomware | Partnership | 300K+ BreachForums operators with stolen creds |
| — | EU Commission | Cloud breach | 30 EU entities data exposed (CERT-EU) |

**Credential Exposure**: 300+ GB compressed; ~500,000+ infected machines/CI runners.

### 7.2 Axios/UNC1069 Campaign (March 31)

| Attribute | Detail |
|-----------|--------|
| Package | axios (100M+ weekly downloads) |
| Exposure Window | 169 minutes (00:21–03:20 UTC, March 31) |
| Affected Versions | `1.14.1`, `0.30.4` |
| Malware | WAVESHAPER.V2 (cross-platform RAT) |
| Attribution | UNC1069 (DPRK) per Google GTIG/Mandiant |
| Confirmed Impact | ~3% of monitored environments executed code |

### 7.3 Supply Chain IOCs (Complete)

**TeamPCP C2 Infrastructure:**

| Type | Value |
|------|-------|
| IPv4 | `23.142.184[.]129` |
| IPv4 | `45.148.10[.]212` |
| IPv4 | `63.251.162[.]11` |
| IPv4 | `83.142.209[.]11` |
| IPv4 | `83.142.209[.]203` |
| IPv4 | `195.5.171[.]242` |
| IPv4 | `209.34.235[.]18` |
| IPv4 | `212.71.124[.]188` |
| Domain | `scan.aquasecurtiy[.]org` |
| Domain | `checkmarx[.]zone` |
| Domain | `models.litellm[.]cloud` |
| Domain | `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0[.]io` |
| Domain | `championships-peoples-point-cassette.trycloudflare[.]com` |
| Domain | `create-sensitivity-grad-sequence.trycloudflare[.]com` |
| Domain | `investigation-launches-hearings-copying.trycloudflare[.]com` |
| Domain | `plug-tab-protective-relay.trycloudflare[.]com` |
| Domain | `souls-entire-defined-routes.trycloudflare[.]com` |

**UNC1069/Axios C2:**

| Type | Value |
|------|-------|
| Domain | `sfrclak[.]com` |
| IPv4 | `142.11.206[.]73` |
| IPv4 | `23.254.167[.]216` |
| URL | `http://sfrclak[.]com:8000/6202033` |

---

## 8. Weekly Briefing Context

### 8.1 Threat Landscape Summary (Week of March 30 – April 6, 2026)

The overarching themes for this period include:

1. **Supply chain attacks at scale are now the primary vector** — Two separate, unrelated campaigns (TeamPCP and UNC1069/Axios) weaponized the open-source software supply chain within the same week, affecting millions of downstream consumers globally.

2. **State-sponsored operations are escalating** — North Korea (UNC1069) targeting financial platforms ($280M Drift heist + Axios compromise), Iran (multiple APTs + 60+ hacktivist groups) executing destructive operations, Russia (revisiting old breaches in Ukraine).

3. **Identity is the new perimeter** — The Stryker/Handala attack and device code phishing 37x surge confirm that credential compromise + management plane abuse is the most effective attack pattern of 2026.

4. **AI is force-multiplying both attack and defense** — Iranian actors using AI-enhanced spearphishing; retail facing Agentic AI fraud; Claude Code leak being weaponized for infostealer distribution.

5. **Critical vulnerability window** — CVE-2026-35616 (FortiClient EMS), CVE-2026-1731 (BeyondTrust), and CVE-2025-55182 (React2Shell/Next.js) are all under active exploitation.

### 8.2 Key Events Timeline

```
Mar 23 │ TeamPCP compromises Trivy GitHub Actions (Wave 1)
Mar 24 │ TeamPCP pivots to Checkmarx KICS (Wave 2) + LiteLLM PyPI (Wave 3)
Mar 25 │ CanisterWorm deployed on npm; Iran-targeted K8s wiper integrated
Mar 26 │ TeamPCP partners with Vect ransomware; Microsoft guidance published
Mar 27 │ TeamPCP retrospective published; KICS compromise details emerge
Mar 28 │ Telnyx SDK compromise (Wave 4) — WAV steganography payload
Mar 30 │ PureHVNC RAT suspected TeamPCP pivot; Telnyx Windows analysis
Mar 31 │ Axios npm compromise (UNC1069/DPRK) — 169-minute window
       │ GCP Vertex AI security research (Unit 42)
Apr 01 │ Google GTIG attributes Axios to UNC1069; Hasbro systems offline
       │ Mercor confirms LiteLLM supply chain incident
Apr 02 │ Drift Protocol: $280M stolen (DPRK); Stryker fully operational post-wipe
       │ Progress ShareFile pre-auth RCE vulnerabilities
Apr 03 │ Iran Conflict Cyber Threat Escalation report compiled (12 sources)
       │ CERT-EU attributes EU Commission breach to TeamPCP (30 entities)
       │ Die Linke (Germany) hit by Qilin ransomware
       │ Massachusetts emergency communications attacked
Apr 04 │ Axios post-mortem: fake Teams error fix social engineering revealed
       │ Device code phishing attacks surge 37x
Apr 05 │ FortiClient EMS CVE-2026-35616 emergency patch (active exploitation)
       │ React2Shell automated credential theft campaigns
Apr 06 │ This Briefing
```

---

## 9. Consolidated IOC List

### 9.1 All IP Addresses

| IP | Attribution | Context |
|----|------------|---------|
| `23.142.184[.]129` | TeamPCP | C2 server |
| `45.148.10[.]212` | TeamPCP | Data exfiltration |
| `63.251.162[.]11` | TeamPCP | C2 server |
| `83.142.209[.]11` | TeamPCP | C2 server |
| `83.142.209[.]203` | TeamPCP | C2 server |
| `195.5.171[.]242` | TeamPCP | C2 server |
| `209.34.235[.]18` | TeamPCP | C2 server |
| `212.71.124[.]188` | TeamPCP | C2 server |
| `142.11.206[.]73` | UNC1069 | WAVESHAPER.V2 C2 (Axios) |
| `23.254.167[.]216` | UNC1069 | Secondary infrastructure |

### 9.2 All Domains

| Domain | Attribution |
|--------|------------|
| `sfrclak[.]com` | UNC1069 (Axios C2) |
| `scan.aquasecurtiy[.]org` | TeamPCP (Trivy exfil) |
| `checkmarx[.]zone` | TeamPCP (KICS exfil) |
| `models.litellm[.]cloud` | TeamPCP (LiteLLM exfil) |
| `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0[.]io` | TeamPCP (ICP canister C2) |
| `championships-peoples-point-cassette.trycloudflare[.]com` | TeamPCP |
| `create-sensitivity-grad-sequence.trycloudflare[.]com` | TeamPCP |
| `investigation-launches-hearings-copying.trycloudflare[.]com` | TeamPCP |
| `plug-tab-protective-relay.trycloudflare[.]com` | TeamPCP |
| `souls-entire-defined-routes.trycloudflare[.]com` | TeamPCP |
| `hyperfilevault1[.]xyz` | Iran-conflict phishing |

### 9.3 All File Hashes (SHA256)

| Hash | Description |
|------|-------------|
| `0880819ef821cff918960a39c1c1aada55a5593c61c608ea9215da858a86e349` | kamikaze.sh (TeamPCP) |
| `5bb67e88846096f1f8d42a0f0350c9c46260591567612ff9af46f98d1b7571cd` | axios-1.14.1.tgz |
| `59336a964f110c25c112bcc5adca7090296b54ab33fa95c0744b94f8a0d80c0f` | axios-0.30.4.tgz |
| `58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668` | plain-crypto-js-4.2.1.tgz |
| `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09` | SILKBELL dropper (setup.js) |
| `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a` | WAVESHAPER.V2 macOS RAT |
| `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101` | WAVESHAPER.V2 Windows RAT |
| `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf` | WAVESHAPER.V2 Linux RAT |
| `ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c` | WAVESHAPER.V2 variant |
| `f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd` | system.bat persistence |
| `30015dd1e2cf4dbd49fff9ddef2ad4622da2e60e5c0b6228595325532e948f14` | TeamPCP self-signed cert (Wave 1) |
| `41c4f2f37c0b257d1e20fe167f2098da9d2e0a939b09ed3f63bc4fe010f8365c` | TeamPCP self-signed cert (Wave 2) |
| `d8caf4581c9f0000c7568d78fb7d2e595ab36134e2346297d78615942cbbd727` | TeamPCP self-signed cert (Wave 3) |
| `0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a` | TeamPCP payload |
| `0c6a3555c4eb49f240d7e0e3edbfbb3c900f123033b4f6e99ac3724b9b76278f` | TeamPCP payload |
| `18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a` | TeamPCP payload |
| `1e559c51f19972e96fcc5a92d710732159cdae72f407864607a513b20729decb` | TeamPCP payload |
| `5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956` | TeamPCP payload |
| `61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba` | TeamPCP payload |
| `6328a34b26a63423b555a61f89a6a0525a534e9c88584c815d937910f1ddd538` | TeamPCP payload |
| `7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9` | TeamPCP payload |
| `7b5cc85e82249b0c452c66563edca498ce9d0c70badef04ab2c52acef4d629ca` | TeamPCP payload |
| `7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7` | TeamPCP payload |
| `822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0` | TeamPCP payload |
| `887e1f5b5b50162a60bd03b66269e0ae545d0aef0583c1c5b00972152ad7e073` | TeamPCP payload |
| `bef7e2c5a92c4fa4af17791efc1e46311c0f304796f1172fce192f5efc40f5d7` | TeamPCP payload |
| `c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926` | TeamPCP payload |
| `cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3` | TeamPCP payload |
| `d5edd791021b966fb6af0ace09319ace7b97d6642363ef27b3d5056ca654a94c` | TeamPCP payload |
| `e4edd126e139493d2721d50c3a8c49d3a23ad7766d0b90bc45979ba675f35fea` | TeamPCP payload |
| `e6310d8a003d7ac101a6b1cd39ff6c6a88ee454b767c1bdce143e04bc1113243` | TeamPCP payload |
| `e64e152afe2c722d750f10259626f357cdea40420c5eedae37969fbf13abbecf` | TeamPCP payload |
| `e87a55d3ba1c47e84207678b88cacb631a32d0cb3798610e7ef2d15307303c49` | TeamPCP payload |
| `e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b` | TeamPCP payload |
| `ecce7ae5ffc9f57bb70efd3ea136a2923f701334a8cd47d4fbf01a97fd22859c` | TeamPCP payload |
| `f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152` | TeamPCP payload |
| `f7084b0229dce605ccc5506b14acd4d954a496da4b6134a294844ca8d601970d` | TeamPCP payload |

### 9.4 All Compromised Packages

| Package | Registry | Versions | Attribution |
|---------|----------|----------|------------|
| axios | npm | 1.14.1, 0.30.4 | UNC1069 |
| plain-crypto-js | npm | 4.2.1 | UNC1069 |
| @shadanai/openclaw | npm | various | Downstream (UNC1069) |
| @qqbrowser/openclaw-qbot | npm | 0.0.130 | Downstream (UNC1069) |
| LiteLLM | PyPI | 1.82.7, 1.82.8 | TeamPCP |
| Telnyx SDK | PyPI | compromised | TeamPCP |
| ast-results | OpenVSX | 2.53.0 | TeamPCP |
| cx-dev-assist | OpenVSX | 1.7.0 | TeamPCP |

---

## 10. Consolidated MITRE ATT&CK Matrix

### Tactics Heatmap

| Tactic | Technique Count | Severity |
|--------|----------------|----------|
| Initial Access | 8 techniques | 🔴 CRITICAL |
| Execution | 9 techniques | 🔴 CRITICAL |
| Persistence | 4 techniques | 🟠 HIGH |
| Defense Evasion | 8 techniques | 🔴 CRITICAL |
| Credential Access | 6 techniques | 🔴 CRITICAL |
| Discovery | 4 techniques | 🟡 MEDIUM |
| Lateral Movement | 3 techniques | 🟠 HIGH |
| Collection | 2 techniques | 🟠 HIGH |
| Command and Control | 5 techniques | 🔴 CRITICAL |
| Exfiltration | 2 techniques | 🟠 HIGH |
| Impact | 6 techniques | 🔴 CRITICAL |
| Resource Development | 2 techniques | 🟡 MEDIUM |

### Top Priority Detections

1. **T1078.004** — Valid Accounts: Cloud Accounts (Intune weaponization + device code phishing)
2. **T1195.002** — Compromise Software Dependencies (Axios, LiteLLM, Trivy, CanisterWorm)
3. **T1485** — Data Destruction (Wiper attacks)
4. **T1072** — Software Deployment Tools (MDM abuse)
5. **T1055.002** — PE Injection (WAVESHAPER.V2 fileless execution)

---

*This briefing was compiled from 44+ source reports, 3 workspace intelligence reports, and real-time threat feeds. All intelligence is derived from publicly available OSINT. TI Mindmap HUB does not generate, fabricate, or independently verify threat claims.*

*For STIX 2.1 bundles, IOC feeds, and interactive threat mindmaps, visit [ti-mindmap-hub.com](https://ti-mindmap-hub.com).*

*Next briefing scheduled: 2026-04-13*
