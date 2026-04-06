---
title: "Threat Intelligence Report: Axios npm Supply Chain Attack"
date: "2026-03-31"
severity: "CRITICAL"
classification: "TLP:WHITE"
description: "Cross-source analysis of the Axios npm supply chain attack delivering cross-platform RATs via compromised maintainer credentials."
tags:
  - supply-chain
  - npm
  - axios
  - rat
  - credential-theft
  - waveshaper
  - unc1069
  - north-korea
sources_count: 12
author: "TI Mindmap HUB"
---

# 🛡️ Threat Intelligence Report: Axios npm Supply Chain Attack

## 1. Reports Summary Table

| # | Title | Publication Date | Source | Platform Link |
|---|-------|-----------------|--------|---------------|
| 1 | Supply Chain Attack on Axios Pulls Malicious Dependency from npm | 2026-03-31 | socket.dev | [View Report](https://ti-mindmap-hub.com/report/bade1989-8d07-4b35-b573-9bdc8d4b7dc5) |
| 2 | One of the most popular JavaScript packages on earth Axios has been compromised | 2026-03-31 | opensourcemalware.com | [View Report](https://ti-mindmap-hub.com/report/a83ab645-a5cb-4c77-945d-2a085f9b7bcb) |
| 3 | Axios npm compromise: XOR dropper to cross-platform RAT | 2026-03-31 | derp.ca | [View Report](https://ti-mindmap-hub.com/report/c7be730d-e165-4425-928b-c746fa3d72fc) |
| 4 | Axios NPM Distribution Compromised in Supply Chain Attack | 2026-03-31 | wiz.io | [View Report](https://ti-mindmap-hub.com/report/2aa15683-2d92-4d69-b583-071c4d0cfd24) |
| 5 | Supply-Chain Compromise of axios npm Package | 2026-03-31 | gist.github.com/joe-desimone | [View Report](https://ti-mindmap-hub.com/report/2a19352c-0d3b-41bd-a954-878887e3e61d) |
| 6 | axios Compromised on npm — Malicious Versions Drop Remote Access Trojan | 2026-03-31 | stepsecurity.io | [View Report](https://ti-mindmap-hub.com/report/2532c2c1-043f-46b4-bfbb-0de55dd22ea8) |
| 7 | Axios npm Supply Chain Attack: Cross-Platform RAT Delivery via Compromised Maintainer Credentials (v1) | 2026-03-31 | picussecurity.com | [View Report](https://ti-mindmap-hub.com/report/c729ac02-ea2d-44b4-bc77-58584879a7ee) |
| 8 | Elastic releases detections for the Axios supply chain compromise | 2026-03-31 | elastic.co | [View Report](https://ti-mindmap-hub.com/report/4b217583-d0cc-4320-925a-d08d6d822a78) |
| 9 | Axios npm Supply Chain Attack: Cross-Platform RAT Delivery via Compromised Maintainer Credentials (v2) | 2026-03-31 | picussecurity.com | [View Report](https://ti-mindmap-hub.com/report/4e8c37fa-d703-4455-91c6-fd14afe6219a) |
| 10 | North Korea-Nexus Threat Actor Compromises Widely Used Axios NPM Package in Supply Chain Attack | 2026-04-01 | cloud.google.com (GTIG/Mandiant) | [View Report](https://ti-mindmap-hub.com/report/338b8d6c-d39f-466d-a159-b27a805a85cb) |
| 11 | Compromised axios npm package delivers cross-platform RAT | 2026-04-01 | securitylabs.datadoghq.com | [View Report](https://ti-mindmap-hub.com/report/e99c3025-0ea0-4e5d-9e60-2ffd50a6fe63) |
| 12 | Axios npm package compromised to deploy malware | 2026-04-01 | sophos.com | [View Report](https://ti-mindmap-hub.com/report/64a049b9-da9c-403a-9e2e-a1c424cf7c95) |

---

## 2. Executive Summary

### Overview

On March 31, 2026, a critical supply chain attack was executed against the Axios npm package — one of the most widely used JavaScript HTTP client libraries in the world, with over **100 million weekly downloads** and deployment in approximately **80% of cloud and code environments**. A threat actor compromised the npm maintainer credentials of the primary Axios maintainer and published two malicious versions: **1.14.1** and **0.30.4**. These versions introduced a single new dependency, `plain-crypto-js@4.2.1`, a typosquat of the legitimate `crypto-js` package, which served as a multi-stage dropper for a cross-platform Remote Access Trojan (RAT).

The exposure window lasted approximately **169 minutes** (from 00:21 to 03:20 UTC on March 31, 2026) before npm intervened and removed the compromised packages. During this window, an undetermined number of developer machines, CI/CD pipelines, and production environments installed the malicious code. Wiz reports that at least **3% of monitored environments** showed execution of the compromised packages.

Google's Threat Intelligence Group (GTIG) and Mandiant attributed this attack to **UNC1069**, a financially motivated North Korea-nexus threat actor. The malware deployed is tracked as **WAVESHAPER.V2**, a sophisticated RAT with reconnaissance, command execution, PE injection, and persistent C2 capabilities.

### Diagram: Attack Flow Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                     AXIOS SUPPLY CHAIN ATTACK FLOW                  │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. INITIAL ACCESS                                                  │
│  ┌──────────────────┐    ┌──────────────────────┐                   │
│  │ Stolen npm Token  │───▶│ Maintainer Account   │                   │
│  │ (classic token)   │    │ Takeover             │                   │
│  └──────────────────┘    └──────────┬───────────┘                   │
│                                     │                               │
│  2. DELIVERY                        ▼                               │
│  ┌──────────────────────────────────────────────────────┐           │
│  │ Publish axios@1.14.1 & axios@0.30.4 to npm           │           │
│  │ + dependency: plain-crypto-js@4.2.1 (typosquat)      │           │
│  └──────────────────────────┬───────────────────────────┘           │
│                             │                                       │
│  3. EXECUTION               ▼                                       │
│  ┌──────────────────────────────────────────────────────┐           │
│  │ postinstall hook → setup.js (XOR + Base64 obfuscated) │           │
│  │ Detects OS → Fetches platform-specific RAT from C2    │           │
│  │ Self-deletes + restores clean package.json             │           │
│  └──────┬──────────────────┬───────────────┬────────────┘           │
│         │                  │               │                        │
│         ▼                  ▼               ▼                        │
│  ┌────────────┐   ┌──────────────┐  ┌────────────┐                 │
│  │  Windows    │   │   macOS       │  │   Linux    │                 │
│  │ PowerShell  │   │  Mach-O RAT   │  │ Python RAT │                 │
│  │ RAT + Reg   │   │  + AppleScript│  │ /tmp/ld.py │                 │
│  │ Persistence │   │  + Codesign   │  │ No persist │                 │
│  └──────┬─────┘   └──────┬───────┘  └─────┬──────┘                 │
│         │                │               │                          │
│  4. COMMAND & CONTROL    ▼               ▼                          │
│  ┌──────────────────────────────────────────────────────┐           │
│  │ C2: sfrclak[.]com:8000 (142.11.206.73)               │           │
│  │ Protocol: HTTP POST, Base64 JSON, 60s beacon interval │           │
│  │ User-Agent: IE8/WinXP (static)                        │           │
│  │ Capabilities: exec, peinject, dir listing, recon      │           │
│  └──────────────────────────────────────────────────────┘           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Attribution & Threat Actor

**UNC1069** (per Google GTIG/Mandiant) is a North Korea-nexus financially motivated threat group. Key attribution indicators include:

- Infrastructure overlap with prior UNC1069 campaigns (domain `sfrclak[.]com`, IP `142.11.206.73`, secondary IP `23.254.167.216`).
- Use of the **WAVESHAPER.V2** backdoor family, a known UNC1069 tool.
- The **SILKBELL** dropper component (setup.js) matches previously observed UNC1069 tooling patterns.
- Attacker-controlled email `ifstap@proton.me` was used to take over the maintainer account.
- A secondary email `nrwise@proton.me` was also observed in connection with the compromised accounts.

**Note:** The Datadog report noted that attribution artifacts in the payloads did not match the recent TeamPCP supply chain campaign, suggesting UNC1069 operates as a separate cluster within the DPRK cyber operations ecosystem.

---

## 3. Technical Details

### 3.1 Malware Analysis

#### Stage 0: Account Compromise

The attack began with the theft of a **classic npm access token** (long-lived, non-2FA-protected) belonging to the primary Axios maintainer (`jasonsaayman`). The attacker changed the account email to `ifstap@proton.me` and gained publishing permissions that exceeded those of other maintainers. The attacker then bypassed the legitimate CI/CD pipeline and published directly from the hijacked account.

#### Stage 1: Malicious Dependency Injection

Two axios versions were published:
- `axios@1.14.1` (targeting latest users)
- `axios@0.30.4` (targeting users pinned to the 0.x branch)

Both versions were identical to their legitimate predecessors except for one change: the addition of `plain-crypto-js@4.2.1` as a dependency. This package had been staged with a clean version (4.2.0) minutes before the attack to avoid suspicion.

#### Stage 2: Obfuscated Dropper (`setup.js`)

The `plain-crypto-js` package contained an obfuscated JavaScript file (`setup.js`, ~4 KB) triggered via npm's `postinstall` hook. The dropper employed:

- **Two-layer encoding**: Reversed Base64 + custom XOR cipher (key: `OrDeR_7077`)
- **OS detection**: Branched execution to Windows, macOS, or Linux-specific routines
- **Anti-forensics**: Self-deleted `setup.js` and restored original `package.json` after payload delivery
- **Speed**: All dropper operations completed in under 2 seconds, before npm finished installing other dependencies
- **Campaign identifier**: `6202033` embedded throughout the tooling

#### Stage 3: Platform-Specific RAT Payloads (WAVESHAPER.V2)

**macOS:**
- Downloaded a universal Mach-O binary RAT to `/Library/Caches/com.apple.act.mond`
- Delivered via AppleScript, executed through `zsh`
- Ad-hoc codesigned to bypass Gatekeeper
- Masqueraded as a legitimate Apple process
- Most complete and functional payload (per Datadog analysis)
- No persistence mechanism implemented

**Windows:**
- Downloaded a PowerShell RAT via VBScript wrapper
- Copied legitimate `powershell.exe` to `%PROGRAMDATA%\wt.exe` to evade EDR
- Persistence via registry Run key (`MicrosoftUpdate` in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`) and hidden batch file (`%PROGRAMDATA%\system.bat`)
- Supported reflective .NET PE injection (fileless, in-memory)
- Per Datadog, the Windows script had a bug that prevented proper beaconing initiation

**Linux:**
- Downloaded Python script to `/tmp/ld.py` via curl
- No persistence mechanism
- Per Datadog, the Linux RAT crashed in most containerized environments due to improper user information retrieval
- Linux payload was never fully recovered by researchers (per derp.ca)

#### RAT Capabilities (All Platforms)

All WAVESHAPER.V2 variants shared a common C2 protocol and command set:

| Capability | Description |
|-----------|-------------|
| System Reconnaissance | Hostname, username, boot time, timezone, OS version, process lists |
| Directory Listing | Full file paths, sizes, creation/modification timestamps |
| Command Execution | Arbitrary shell commands |
| PE Injection | In-memory Portable Executable injection (Windows) |
| Script Execution | AppleScript execution (macOS), arbitrary code injection |
| File Download | Ingress tool transfer from C2 |
| Process Termination | Kill command for self-termination |

### 3.2 Infrastructure Analysis

| Component | Value | Notes |
|-----------|-------|-------|
| C2 Domain | `sfrclak[.]com` | Registered hours before the attack |
| C2 IP | `142.11.206.73` | Hosted by Hostwinds, Seattle (AS54290) |
| C2 Port | `8000` (HTTP) | Plain HTTP, no TLS |
| C2 URL | `http://sfrclak[.]com:8000/6202033` | Payload delivery and beacon endpoint |
| Secondary IP | `23.254.167.216` | Suspected additional UNC1069 infrastructure |
| Beacon Interval | 60 seconds | Consistent across all platforms |
| User-Agent | `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)` | Static, mimics IE8 on Windows XP |
| C2 Protocol | HTTP POST with Base64-encoded JSON | POST bodies mimic npm registry traffic (`packages.npm.org/product{0,1,2}`) |

The infrastructure was dismantled shortly after npm removed the compromised packages. No prior malicious activity was associated with the C2 infrastructure before this campaign.

### 3.3 Downstream Propagation

Two additional npm packages were found to have vendored or depended on the trojanized Axios, propagating the compromise further into the ecosystem:
- `@shadanai/openclaw`
- `@qqbrowser/openclaw-qbot` (v0.0.130)

These packages either bundled the trojanized dependency directly or pulled in the tampered Axios, demonstrating how a single poisoned package can rapidly contaminate downstream dependencies, especially in automated CI/CD pipelines.

---

## 4. Detection Opportunities

### 4.1 Behavioral Detections (per Elastic Security Labs)

Elastic's behavioral detection strategy proved highly effective. Recommended detection rules focus on:

- **Process ancestry monitoring**: Node.js processes spawning OS-native shells (sh, cscript, osascript) that then fetch and execute remote payloads
- **Network retrieval by interpreters**: PowerShell, Python, curl/wget downloading executables from non-standard ports
- **Background execution detachment**: Child processes detaching from parent node process tree
- **Renamed signed binaries**: Detection of `powershell.exe` copied to non-standard paths (e.g., `wt.exe`)

### 4.2 Network-Based Detections

- Monitor for HTTP POST traffic to port 8000 with IE8/Windows XP User-Agent strings
- Alert on POST body patterns containing `packages.npm.org/product` strings to non-npm infrastructure
- Block/alert on traffic to `sfrclak[.]com` and `142.11.206.73`

### 4.3 Host-Based Detections

- **macOS**: Presence of `/Library/Caches/com.apple.act.mond` (unsigned or ad-hoc signed Mach-O binary)
- **Windows**: Registry key `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\MicrosoftUpdate`, presence of `%PROGRAMDATA%\wt.exe` or `%PROGRAMDATA%\system.bat`
- **Linux**: Presence of `/tmp/ld.py`
- **All platforms**: npm audit for `axios@1.14.1`, `axios@0.30.4`, or `plain-crypto-js@4.2.1`

### 4.4 Sophos Detection Signatures

- `JS/Agent-BLYB` (JavaScript dropper)
- `Troj/PSAgent-CN` (PowerShell RAT)

### 4.5 Package Ecosystem Checks

- Audit for advisory IDs: `GHSA-fw8c-xr5c-95f9`, `MAL-2026-2306`
- Verify axios package publisher metadata (check for unexpected email changes)
- Monitor for npm packages with `postinstall` hooks pulling previously unknown dependencies

---

## 5. Conclusion

The Axios npm supply chain attack represents one of the most significant software supply chain compromises in recent memory. Key takeaways across all 12 analyzed sources:

1. **Scale of Impact**: With ~100M weekly downloads, the blast radius was enormous, though the 169-minute exposure window limited actual propagation. Wiz estimated 3% of monitored environments executed the compromised code.

2. **Sophistication**: The attack demonstrated advanced tradecraft — multi-layer obfuscation, cross-platform RAT delivery, anti-forensic cleanup, and C2 traffic masquerading as legitimate npm registry activity.

3. **Operational Weaknesses**: Despite the sophisticated initial compromise, the RAT payloads contained bugs: the Windows variant failed to beacon properly, and the Linux variant crashed in containers — suggesting possible rush to deployment or limited testing.

4. **Attribution**: Google GTIG/Mandiant attributed the attack to UNC1069, a North Korea-nexus threat actor, based on infrastructure and tooling overlaps with prior campaigns. Not all sources agreed on attribution; Datadog noted the attack did not match the TeamPCP campaign cluster.

5. **Systemic Risk**: This incident exposes fundamental weaknesses in the npm ecosystem: long-lived access tokens, lack of mandatory 2FA for critical packages, insufficient publishing provenance controls, and the transitive trust model that allows a single compromised dependency to cascade to millions of consumers.

**Recommended Immediate Actions:**
- Audit all environments for `axios@1.14.1`, `axios@0.30.4`, and `plain-crypto-js@4.2.1`
- Rotate all credentials potentially exposed on compromised systems
- Review CI/CD pipeline logs for anomalous npm install activity during the exposure window (March 31, 00:21–03:20 UTC)
- Monitor for C2 indicators and file artifacts listed below
- Pin and lock dependency versions; enable `npm audit` in CI pipelines

---

## 6. Indicators of Compromise (IoC List)

### 6.1 Network Indicators

| Type | Value | Description |
|------|-------|-------------|
| Domain | `sfrclak[.]com` | WAVESHAPER.V2 C2 domain |
| IPv4 | `142.11.206[.]73` | Primary C2 server (Hostwinds, Seattle, AS54290) |
| IPv4 | `23.254.167[.]216` | Suspected secondary UNC1069 infrastructure |
| URL | `http://sfrclak[.]com:8000/6202033` | Payload delivery and beacon endpoint |
| URL | `http://sfrclak[.]com:8000` | C2 base endpoint |
| User-Agent | `mozilla/4.0 (compatible; msie 8.0; windows nt 5.1; trident/4.0)` | Hardcoded RAT beacon User-Agent |
| Email | `ifstap@proton[.]me` | Attacker email used for account takeover |
| Email | `nrwise@proton[.]me` | Secondary attacker-associated email |

### 6.2 File Hashes — Malicious Packages

| Hash Type | Value | Description |
|-----------|-------|-------------|
| SHA256 | `5bb67e88846096f1f8d42a0f0350c9c46260591567612ff9af46f98d1b7571cd` | axios-1.14.1.tgz |
| SHA256 | `59336a964f110c25c112bcc5adca7090296b54ab33fa95c0744b94f8a0d80c0f` | axios-0.30.4.tgz |
| SHA256 | `58401c195fe0a6204b42f5f90995ece5fab74ce7c69c67a24c61a057325af668` | plain-crypto-js-4.2.1.tgz |
| SHA1 | `d6f3f62fd3b9f5432f5782b62d8cfd5247d5ee71` | axios-0.30.4 npm package |
| SHA1 | `07d889e2dadce6f3910dcbc253317d28ca61c766` | plain-crypto-js-4.2.1 npm package |

### 6.3 File Hashes — Payloads

| Hash Type | Value | Description |
|-----------|-------|-------------|
| SHA256 | `e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09` | SILKBELL dropper (setup.js) |
| SHA256 | `92ff08773995ebc8d55ec4b8e1a225d0d1e51efa4ef88b8849d0071230c9645a` | WAVESHAPER.V2 macOS Mach-O RAT |
| SHA256 | `617b67a8e1210e4fc87c92d1d1da45a2f311c08d26e89b12307cf583c900d101` | WAVESHAPER.V2 Windows PowerShell RAT |
| SHA256 | `fcb81618bb15edfdedfb638b4c08a2af9cac9ecfa551af135a8402bf980375cf` | WAVESHAPER.V2 Linux Python RAT |
| SHA256 | `ed8560c1ac7ceb6983ba995124d5917dc1a00288912387a6389296637d5f815c` | WAVESHAPER.V2 variant (platform unspecified) |
| SHA256 | `f7d335205b8d7b20208fb3ef93ee6dc817905dc3ae0c10a0b164f4e7d07121cd` | system.bat persistence stub (Windows) |

### 6.4 File System Artifacts

| Platform | Path | Description |
|----------|------|-------------|
| macOS | `/Library/Caches/com.apple.act.mond` | Mach-O RAT binary |
| Windows | `%PROGRAMDATA%\wt.exe` | Renamed PowerShell binary (EDR evasion) |
| Windows | `%PROGRAMDATA%\system.bat` | Persistence batch file |
| Windows | `%TEMP%\6202033.vbs` | VBScript dropper |
| Windows | `%TEMP%\6202033.ps1` | PowerShell payload |
| Linux | `/tmp/ld.py` | Python RAT payload |

### 6.5 Registry Indicators (Windows)

| Key | Value Name | Description |
|-----|-----------|-------------|
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` | `MicrosoftUpdate` | Boot persistence for system.bat |

### 6.6 Malicious npm Package Identifiers

| Package | Version | Status |
|---------|---------|--------|
| `axios` | `1.14.1` | Removed by npm |
| `axios` | `0.30.4` | Removed by npm |
| `plain-crypto-js` | `4.2.1` | Removed by npm |
| `@shadanai/openclaw` | various | Downstream propagation |
| `@qqbrowser/openclaw-qbot` | `0.0.130` | Downstream propagation |

### 6.7 Advisory IDs

| ID | Source |
|----|--------|
| GHSA-fw8c-xr5c-95f9 | GitHub Security Advisory |
| MAL-2026-2306 | npm Malware Advisory |

### 6.8 Obfuscation Artifacts

| Artifact | Value | Description |
|----------|-------|-------------|
| XOR Key | `OrDeR_7077` | Used in setup.js two-layer obfuscation |
| Campaign ID | `6202033` | Embedded in URLs, filenames, and payloads |

---

## 7. MITRE ATT&CK Techniques

| Technique ID | Technique Name | Tactic | Description |
|-------------|----------------|--------|-------------|
| T1195 | Supply Chain Compromise | Initial Access | Malicious dependency `plain-crypto-js@4.2.1` injected into trusted axios npm releases via compromised maintainer account. |
| T1078 | Valid Accounts | Initial Access | Stolen classic npm access token used to hijack the primary axios maintainer account; email changed to attacker-controlled address. |
| T1059.007 | Command and Scripting Interpreter: JavaScript | Execution | Postinstall hook in `package.json` triggered execution of obfuscated `setup.js` dropper during `npm install`. |
| T1059.001 | Command and Scripting Interpreter: PowerShell | Execution | Windows payload delivered and executed via PowerShell (renamed to `wt.exe` for evasion). |
| T1059.002 | Command and Scripting Interpreter: AppleScript | Execution | macOS payload loaded and executed via AppleScript and `zsh`. RAT supports `runscript` command for AppleScript execution. |
| T1059.004 | Command and Scripting Interpreter: Bash | Execution | macOS/Linux payloads downloaded using bash, curl, and executed in background. |
| T1059.006 | Command and Scripting Interpreter: Python | Execution | Linux RAT payload (`ld.py`) written in Python, downloaded and executed from `/tmp`. |
| T1204.002 | User Execution: Malicious File | Execution | Compromised axios package auto-executes dropper upon `npm install` without user interaction. |
| T1027 | Obfuscated Files or Information | Defense Evasion | Dropper uses reversed Base64 + custom XOR cipher (key: `OrDeR_7077`) for two-layer obfuscation. |
| T1027.002 | Software Packing | Defense Evasion | WAVESHAPER.V2 employs code packing to evade static detection. |
| T1036 | Masquerading | Defense Evasion | PowerShell copied to `wt.exe`; macOS RAT masquerades as Apple system process `com.apple.act.mond`. |
| T1070 | Indicator Removal on Host | Defense Evasion | `setup.js` self-deletes and restores clean `package.json` after payload delivery. |
| T1070.001 | Indicator Removal: Clear Artifacts | Defense Evasion | Script removes itself, downloaded scripts, and injected `package.json` modifications to destroy forensic evidence. |
| T1070.004 | File Deletion | Defense Evasion | Dropper and staging files deleted post-execution to minimize forensic footprint. |
| T1547.001 | Boot/Logon Autostart: Registry Run Keys | Persistence | Windows: `MicrosoftUpdate` registry Run key launches `system.bat` at logon for persistent RAT re-download. |
| T1037.001 | Logon Initialization Scripts | Persistence | Hidden batch file (`system.bat`) executes at Windows logon to re-fetch and launch RAT in memory. |
| T1105 | Ingress Tool Transfer | Command and Control | Dropper downloads platform-specific RAT payloads from C2 server over HTTP. |
| T1071.001 | Application Layer Protocol: Web Protocols | Command and Control | RAT beacons to C2 over HTTP port 8000 with Base64-encoded JSON; POST bodies mimic npm registry traffic. |
| T1001 | Data Obfuscation | Command and Control | C2 beacon data is Base64-encoded JSON with hardcoded User-Agent mimicking IE8. |
| T1568 | Dynamic Resolution | Command and Control | RAT variants accept C2 URL dynamically via command-line arguments. |
| T1082 | System Information Discovery | Discovery | Collects hostname, username, boot time, timezone, OS version, and running processes. |
| T1083 | File and Directory Discovery | Discovery | Retrieves detailed directory listings with file paths, sizes, and timestamps. |
| T1057 | Process Discovery | Discovery | Extracts running process lists as part of system telemetry sent to C2. |
| T1055.002 | Process Injection: PE Injection | Execution | Windows RAT supports in-memory Portable Executable injection for fileless payload execution. |

---

*Report generated by TI Mindmap HUB — Cross-source Threat Intelligence Analysis*
*Analysis date: 2026-04-01 | Sources analyzed: 12 | Classification: TLP:WHITE*
