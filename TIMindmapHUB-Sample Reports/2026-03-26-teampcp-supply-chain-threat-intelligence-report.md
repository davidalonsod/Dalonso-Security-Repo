---
title: "Threat Intelligence Report: TeamPCP Multi-Stage Supply Chain Campaign"
date: "2026-03-26"
severity: "CRITICAL"
classification: "TLP:WHITE"
description: "Cross-source analysis of TeamPCP's escalating supply chain attacks targeting OSS security tools, CI/CD pipelines, and cloud-native infrastructure."
tags:
  - supply-chain
  - teampcp
  - canisterworm
  - kubernetes
  - credential-theft
  - ransomware
  - wiper
  - ci-cd
  - github-actions
  - pypi
  - npm
  - trivy
  - litellm
  - checkmarx
  - telnyx
sources_count: 20
author: "TI Mindmap HUB"
---

# 🛡️ Threat Intelligence Report: TeamPCP Multi-Stage Supply Chain Campaign

## 1. Reports Summary Table

The following table lists all 20 TI Mindmap HUB reports analyzed for this assessment, ordered by publication date (newest first).

| # | Title | Publication Date | Source | Platform Link |
|---|-------|------------------|--------|---------------|
| 1 | Weaponizing the Protectors: TeamPCP's Multi-Stage Supply Chain Attack on Security Infrastructure | 2026-04-01 | unit42.paloaltonetworks.com | [View Report](https://ti-mindmap-hub.com/report/46e040f6-57b4-48f5-a474-f9e0efd7aabd) |
| 2 | Tracking TeamPCP: Investigating Post-Compromise Attacks Seen in the Wild | 2026-03-31 | www.wiz.io | [View Report](https://ti-mindmap-hub.com/report/903150b6-e82c-496f-b8c3-affbf8f62f63) |
| 3 | TeamPCP's Telnyx Windows Malware: Technical Analysis | 2026-03-30 | www.ox.security | [View Report](https://ti-mindmap-hub.com/report/17523abe-6cb7-4773-8701-65533fe9dc41) |
| 4 | Has TeamPCP Pivoted To Using The PureHVNC RAT? | 2026-03-30 | opensourcemalware.com | [View Report](https://ti-mindmap-hub.com/report/7e73cadd-6a2d-4efa-8063-b8c13e508425) |
| 5 | TeamPCP Compromises Telnyx Python SDK to Deliver Credential-Stealing Malware | 2026-03-28 | socket.dev | [View Report](https://ti-mindmap-hub.com/report/1b8756be-21dd-49af-807c-f6d4d8ab0a48) |
| 6 | TeamPCP Supply Chain Campaign: A March 2026 Retrospective | 2026-03-27 | opensourcemalware.com | [View Report](https://ti-mindmap-hub.com/report/255a85e7-f451-4ba3-b0b3-014377953cec) |
| 7 | TeamPCP expands: Supply chain compromise spreads from Trivy to Checkmarx GitHub Actions | 2026-03-27 | webflow.sysdig.com | [View Report](https://ti-mindmap-hub.com/report/d547ec11-bf3b-4f2e-8a9e-ddae394912b7) |
| 8 | TeamPCP Partners With Ransomware Group Vect to Target Open Source Supply Chains | 2026-03-26 | socket.dev | [View Report](https://ti-mindmap-hub.com/report/1224c23a-a93a-449e-9e3d-d78dc4150de7) |
| 9 | Guidance for detecting, investigating, and defending against the Trivy supply chain compromise | 2026-03-26 | www.microsoft.com | [View Report](https://ti-mindmap-hub.com/report/d6f976f1-1fa5-4121-a3bc-bc860705e5e1) |
| 10 | TeamPCP: Trivy Supply Chain Attack and Kubernetes Wiper | 2026-03-25 | labs.cloudsecurityalliance.org | [View Report](https://ti-mindmap-hub.com/report/5328f5c9-a47e-43ab-97f3-06f2510895f1) |
| 11 | TeamPCP's Five-Day Siege: How One Stolen Token Cascaded Across GitHub Actions, Checkmarx, VS Code Extensions, and npm | 2026-03-25 | phoenix.security | [View Report](https://ti-mindmap-hub.com/report/801813d3-1fc5-4ccd-8147-1ad16437e4b8) |
| 12 | TeamPCP deploys CanisterWorm on NPM following Trivy compromise | 2026-03-25 | www.aikido.dev | [View Report](https://ti-mindmap-hub.com/report/ac7ccf4c-116f-49de-9837-a2f5ea2ac338) |
| 13 | CanisterWorm Gets Teeth: TeamPCP's Kubernetes Wiper Targets Iran | 2026-03-25 | www.aikido.dev | [View Report](https://ti-mindmap-hub.com/report/94be2445-4688-4b19-96a1-75410edd5fff) |
| 14 | LiteLLM compromised on PyPI: Tracing the March 2026 TeamPCP supply chain campaign | 2026-03-25 | securitylabs.datadoghq.com | [View Report](https://ti-mindmap-hub.com/report/0864dc0f-a647-4d52-a644-c76c1d1aa619) |
| 15 | TeamPCP Hijacks LiteLLM's PyPI Package - Credential Stealer Hits 40k-Star Project | 2026-03-24 | opensourcemalware.com | [View Report](https://ti-mindmap-hub.com/report/98daf2c8-4a9b-4345-944d-817656c29b90) |
| 16 | Three's a Crowd: TeamPCP trojanizes LiteLLM in Continuation of Campaign | 2026-03-24 | www.wiz.io | [View Report](https://ti-mindmap-hub.com/report/23f7c1fe-9cfd-4c39-a0b9-5cd9c5175a52) |
| 17 | TeamPCP Is Systematically Targeting Security Tools Across the OSS Ecosystem | 2026-03-24 | socket.dev | [View Report](https://ti-mindmap-hub.com/report/2374ee78-b8c5-4ce0-9bdc-d97f61e9297c) |
| 18 | KICS GitHub Action Compromised: TeamPCP Strikes Again in Supply Chain Attack | 2026-03-24 | www.wiz.io | [View Report](https://ti-mindmap-hub.com/report/22edfab5-ea72-427d-8867-5690130a4898) |
| 19 | TeamPCP Defaces Aqua Security's Internal GitHub Org - 44 Repos Exposed | 2026-03-23 | opensourcemalware.com | [View Report](https://ti-mindmap-hub.com/report/182cce80-6055-4475-bb36-47bd0d1f2a8a) |
| 20 | Threat Alert: TeamPCP, An Emerging Force in the Cloud Native and Ransomware Landscape | 2026-02-06 | flare.io | [View Report](https://ti-mindmap-hub.com/report/09a72213-fc0e-4b6e-81ce-f7738ff4173a) |

---

## 2. Executive Summary

### Overview

TeamPCP (also tracked as PCPcat, ShellForce, DeadCatx3) is a rapidly escalating cloud-native cybercrime group that has executed one of the most impactful open-source supply chain campaigns observed to date. Between December 2025 and March 2026, the group evolved from opportunistic exploitation of exposed Docker and Kubernetes APIs into a coordinated, multi-stage supply chain operation that compromised five major vendor ecosystems in just five days during March 2026.

The campaign's defining characteristic is its cascading nature: a single unrevoked CI credential from Aqua Security's Trivy pipeline enabled TeamPCP to snowball access across GitHub Actions, npm, PyPI, OpenVSX extensions, and multiple high-trust security tools (Trivy, Checkmarx KICS, BerriAI LiteLLM, Telnyx SDK). The group exfiltrated over 300 GB of compressed credentials, including cloud tokens, SSH keys, and Kubernetes secrets, from an estimated 500,000+ infected machines and CI/CD runners.

TeamPCP's campaign is notable for three distinct escalation vectors: (1) the deployment of CanisterWorm, a self-propagating npm worm leveraging Internet Computer Protocol (ICP) canisters for decentralized, resilient C2; (2) the integration of a geopolitically targeted Kubernetes wiper aimed at Iranian infrastructure; and (3) a confirmed partnership with the Vect ransomware group, extending stolen credentials into large-scale ransomware deployment via the BreachForums affiliate network with 300,000+ potential operators.

### Diagram: Attack Overview

```
                         ┌──────────────────────────┐
                         │   INITIAL ACCESS         │
                         │ Unrevoked Trivy CI Token │
                         │ (pull_request_target abuse) │
                         └────────────┬─────────────┘
                                      │
                    ┌─────────────────┼──────────────────┐
                    ▼                 ▼                  ▼
          ┌─────────────────┐ ┌──────────────┐ ┌──────────────────┐
          │ WAVE 1: Trivy   │ │ WAVE 2: KICS │ │ WAVE 3: LiteLLM  │
          │ GitHub Actions  │ │ Checkmarx    │ │ PyPI Trojanize   │
          │ kamikaze.sh     │ │ GitHub Token │ │ .pth persistence │
          └───────┬─────────┘ └──────┬───────┘ └────────┬─────────┘
                  │                  │                  │
                  ▼                  ▼                  ▼
          ┌─────────────────────────────────────────────────────┐
          │          CREDENTIAL HARVESTING (300 GB+)           │
          │  Cloud tokens · SSH keys · K8s secrets · .env vars │
          └──────────────────────┬──────────────────────────────┘
                                 │
            ┌────────────────────┼────────────────────┐
            ▼                    ▼                    ▼
   ┌────────────────┐  ┌──────────────────┐  ┌──────────────────┐
   │ WAVE 4: Telnyx │  │ CanisterWorm     │  │ Vect Ransomware  │
   │ SDK + WAV      │  │ npm worm + ICP   │  │ Partnership +    │
   │ Steganography  │  │ C2 + K8s Wiper   │  │ BreachForums RaaS│
   └────────────────┘  │ (Iran targeting) │  └──────────────────┘
                       └──────────────────┘
```

### Attribution & Threat Actor Profile

**Group Name:** TeamPCP  
**Known Aliases:** PCPcat, ShellForce, DeadCatx3  
**First Observed:** December 2025  
**Motivation:** Financial (credential theft, ransomware, cryptomining, extortion) + Destructive/Geopolitical (Iran-targeted wipers)  
**Affiliation:** Confirmed coordination with LAPSUS$; operational partnership with Vect ransomware group  
**Communication Channels:** Telegram (dedicated channels for leaked data), BreachForums, dark web  
**Primary Targets:** Open-source security tools, CI/CD pipelines, cloud-native infrastructure (Docker, Kubernetes, Ray, Redis)  
**Victim Geography:** Global, with specific destructive operations targeting Iran  
**Victim Sectors:** Enterprise (all sectors), with particular impact on organizations using Trivy, Checkmarx, LiteLLM, or Telnyx in their software supply chain

TeamPCP distinguishes itself from traditional APT groups by functioning as a cloud-native cybercrime platform rather than a single-purpose malware group. The group industrializes well-known attack techniques against modern cloud infrastructure and has demonstrated the ability to rapidly pivot between financial (credential theft, RaaS) and destructive (wiper) operations, suggesting dual financial and political motivations.

---

## 3. Technical Details

### 3.1 Malware Analysis & Tooling

TeamPCP developed and deployed an evolving malware toolkit across the campaign:

**kamikaze.sh**: The initial credential harvester delivered via compromised Trivy GitHub Actions. This shell script evolved through three versions: v1 performed basic credential exfiltration; v2 added GitHub runner process memory scraping by reading `/proc/<pid>/mem` to bypass GitHub secret masking and extract plaintext tokens; v3 introduced a pull method to download secondary payloads. All versions exfiltrated data to typosquatted domains using HTTP POST with AES-256-CBC encryption wrapped in a 4096-bit RSA public key.

**kube.py**: A Python-based worm and wiper component representing a major escalation. This payload performs environment fingerprinting to identify Kubernetes clusters and deploys privileged DaemonSets. In Iranian environments, detected via timezone and locale, it deploys the `host-provisioner-iran` DaemonSet with a `kamikaze` container that mounts the host root filesystem and wipes all top-level directories before forcing a reboot. On non-Iranian Kubernetes clusters, it deploys `host-provisioner-std` with the CanisterWorm backdoor as a persistent systemd service. On non-containerized Iranian hosts, it executes `rm -rf / --no-preserve-root`.

**CanisterWorm**: A self-propagating npm worm that uses Internet Computer Protocol (ICP) canisters for decentralized, takedown-resistant C2. Each infected npm package acts as a telemetry node, harvesting developer tokens (npm auth, GitHub PATs) and using them to publish additional trojanized packages, creating exponential propagation. Fallback C2 uses Cloudflare tunnel domains and victim-owned GitHub repositories created using stolen `GITHUB_TOKEN` values.

**LiteLLM Credential Stealer**: Deployed via trojanized PyPI packages (`litellm==1.82.7`, `1.82.8`), this Python infostealer leverages `.pth` file abuse to execute automatically whenever any Python process initializes on the host. The payload consists of double Base64-encoded scripts that sweep environment variables, `.env` files, AWS/Azure/GCP configuration directories, and cloud instance metadata (IMDS) for credential harvesting.

**Telnyx SDK Malware**: The most technically sophisticated payload in the campaign. It uses WAV audio file steganography to conceal encrypted second-stage payloads within valid audio files, bypassing network inspection and static analysis. The second stage performs dynamic API resolution on Windows and establishes a full remote access toolkit with data exfiltration capabilities across Windows, Linux, and macOS systems.

**Supporting Infrastructure Tools**: Sliver C2 framework for persistent command-and-control, FRPS and gost for proxying and tunneling, and XMRig for cryptomining monetization.

### 3.2 Techniques & Attack Phases

The campaign unfolded in a structured, cascading sequence:

**Phase 1 - Trivy Compromise (March 23):** TeamPCP exploited a known-dangerous `pull_request_target` GitHub Actions workflow in Aqua Security's Trivy repository. An autonomous bot exfiltrated a high-privilege Personal Access Token (PAT) from the aqua-bot service account. Despite Aqua Security's partial credential rotation, TeamPCP retained access due to incomplete revocation. The attackers defaced Aqua Security's internal GitHub organization (44 repositories exposed) and injected `kamikaze.sh` into trusted CI/CD workflows.

**Phase 2 - Checkmarx KICS Compromise (March 24):** Using stolen GitHub PATs harvested from the Trivy breach, TeamPCP poisoned Checkmarx's KICS GitHub Action with a behaviorally identical three-stage credential stealer. The payload exfiltrated to the typosquatted domain `checkmarx[.]zone`. Malicious OpenVSX extensions (`ast-results v2.53.0`, `cx-dev-assist v1.7.0`) were also published.

**Phase 3 - LiteLLM PyPI Compromise (March 24):** TeamPCP pivoted from GitHub PATs to PyPI publishing tokens. They trojanized the legitimate LiteLLM package (40k+ GitHub stars), publishing malicious versions `1.82.7` and `1.82.8` with a `.pth`-based persistence mechanism. The exfiltration endpoint used the domain `models.litellm[.]cloud`.

**Phase 4 - Telnyx SDK Compromise (March 28):** TeamPCP hijacked PyPI publishing credentials for the Telnyx Python SDK, injecting multi-stage credential-stealing malware that leveraged audio steganography for payload delivery. This represented a technique innovation focused on evading network-based detection.

**Phase 5 - CanisterWorm Deployment & Wiper Integration (March 25+):** TeamPCP deployed the CanisterWorm npm worm for automated ecosystem-wide propagation. Concurrently, the Iran-targeted Kubernetes wiper was integrated as a secondary payload, marking the convergence of financial and destructive operations. A third variant abandoned Kubernetes-only propagation and added SSH lateral movement by harvesting keys from SSH logs and exploiting the Docker API on port `2375`.

**Phase 6 - Vect Ransomware Partnership (March 26):** TeamPCP formalized a partnership with the Vect ransomware group to weaponize stolen credentials at scale. Vect offered automatic affiliate status and personalized affiliation keys to all 300,000+ BreachForums members, dramatically expanding the attack surface.

### 3.3 Infrastructure Analysis

TeamPCP employs a multi-layered, resilient infrastructure design:

**Primary C2 Domains (Typosquatted):** Each attack wave used a vendor-themed typosquatted domain for exfiltration, providing plausible-looking traffic patterns: `scan.aquasecurtiy[.]org` (Trivy), `checkmarx[.]zone` (KICS), and `models.litellm[.]cloud` (LiteLLM).

**Decentralized Fallback C2:** The ICP canister domain `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0[.]io` provides a blockchain-based, takedown-resistant C2 channel. This is used by CanisterWorm and the Kubernetes wiper/backdoor payloads.

**Cloudflare Tunnel Domains:** Multiple rotating Cloudflare tunnel domains provide ephemeral, difficult-to-block C2 channels: `championships-peoples-point-cassette.trycloudflare.com`, `create-sensitivity-grad-sequence.trycloudflare.com`, `investigation-launches-hearings-copying.trycloudflare.com`, `plug-tab-protective-relay.trycloudflare.com`, and `souls-entire-defined-routes.trycloudflare.com`.

**GitHub-Based Fallback:** If primary C2 fails, the malware uses the victim's own `GITHUB_TOKEN` to create hidden repositories with naming patterns such as `tpcp-docs-*` and `docs-tpcp` for fallback data exfiltration, making detection more challenging because the traffic originates from legitimate GitHub API endpoints.

**Dedicated IP Infrastructure:** Eight C2 IP addresses have been consistently observed across the campaign, listed below in the IoC section.

**Encryption:** Exfiltrated data is encrypted using AES-256-CBC session keys, further wrapped with a hard-coded 4096-bit RSA public key, ensuring data confidentiality even if C2 traffic is intercepted.

---

## 4. Detection Opportunities

### 4.1 CI/CD and Package Monitoring

**CI/CD Pipeline Monitoring:** Monitor for unexpected modifications to GitHub Actions workflows, especially those using `pull_request_target`. Alert on commits from unrecognized bot accounts. Validate SHA-pinned references for all GitHub Actions rather than relying on mutable version tags.

**Package Registry Monitoring:** Monitor for unexpected version publications of critical dependencies such as Trivy, LiteLLM, Checkmarx, and Telnyx. Implement SBOM verification and enforce allowlisted package versions. Alert on `.pth` file creation in Python `site-packages` directories.

### 4.2 Network and Kubernetes Detections

**Network Detection:** Block or alert on connections to the IoC domains and IPs listed below. Monitor for DNS resolution of `trycloudflare.com` subdomains from CI/CD runners. Detect HTTP POST requests with large encrypted payloads to unrecognized endpoints. Monitor for connections to ICP canister domains under `icp0.io`.

**Kubernetes Detection:** Alert on creation of unexpected DaemonSets in the `kube-system` namespace, especially `host-provisioner-iran` or `host-provisioner-std`. Detect containers named `kamikaze` or `provisioner` mounting host root filesystems. Monitor for privileged container creation via Docker API on port `2375`.

### 4.3 Host and Process Detections

**Host-Level Detection:** Monitor for creation of systemd services masquerading as PostgreSQL utilities such as `pgmon`, `pgmonitor`, `pglog`, `pg_state`, and `internal-monitor`. Detect file writes to `/var/lib/pgmon/`, `/var/lib/svc_internal/`, or `/host/root/.config/sysmon/`. Alert on SSH connections with `StrictHostKeyChecking=no` combined with lateral movement patterns. Monitor for WAV file downloads followed by process execution.

**Process-Level Detection:** Detect Python processes performing simultaneous AWS/Azure/GCP API calls and Kubernetes API interactions. Monitor for `/proc/<pid>/mem` reads by non-debugger processes. Alert on Base64 decoding operations followed by network connections.

---

## 5. Conclusion

The TeamPCP campaign represents a new paradigm in cloud-native threat activity: a fusion of industrial-scale automation, supply chain compromise expertise, and an evolving malware toolkit designed to attack the trust foundations of modern software development. In under four months, the group evolved from opportunistic exploitation of exposed Docker APIs to a coordinated campaign that compromised five major vendor ecosystems, deployed a blockchain-resilient worm, integrated a geopolitically targeted wiper, and partnered with a ransomware-as-a-service operation, all stemming from a single unrevoked CI credential.

The campaign exposes critical systemic weaknesses: incomplete credential rotation, implicit trust in security tooling, mutable version references in CI/CD workflows, and the lack of behavioral monitoring in software supply chains. Cryptographic integrity checks alone failed against attacks using legitimate but compromised credentials.

Organizations should urgently review their software bills of materials for affected packages, enforce immutable SHA-pinned workflow references, implement strict credential rotation with verification, deploy behavioral anomaly detection across CI/CD environments, and monitor for the indicators of compromise listed below. The convergence of supply chain compromise, credential theft, worm propagation, wiper deployment, and ransomware partnership makes TeamPCP one of the most operationally dangerous threat actors active today.

---

## 6. Indicators of Compromise (IoC List)

### 6.1 IP Addresses (C2 Servers)

| Type | Value | Description |
|------|-------|-------------|
| IPv4 | `23.142.184[.]129` | TeamPCP C2 server for exfiltration and remote access |
| IPv4 | `45.148.10[.]212` | TeamPCP C2 server for data exfiltration |
| IPv4 | `63.251.162[.]11` | TeamPCP C2 server |
| IPv4 | `83.142.209[.]11` | TeamPCP C2 server |
| IPv4 | `83.142.209[.]203` | TeamPCP C2 server |
| IPv4 | `195.5.171[.]242` | TeamPCP C2 server |
| IPv4 | `209.34.235[.]18` | TeamPCP C2 server |
| IPv4 | `212.71.124[.]188` | TeamPCP C2 server |

### 6.2 Domains & URLs (C2 / Exfiltration)

| Type | Value | Description |
|------|-------|-------------|
| Domain | `scan.aquasecurtiy[.]org` | Typosquatted primary C2 for Trivy exfiltration |
| Domain | `checkmarx[.]zone` | Typosquatted primary C2 for Checkmarx KICS exfiltration |
| Domain | `models.litellm[.]cloud` | Typosquatted primary C2 for LiteLLM exfiltration |
| Domain | `tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0[.]io` | ICP canister decentralized backup C2 |
| Domain | `championships-peoples-point-cassette.trycloudflare[.]com` | Cloudflare tunnel C2 |
| Domain | `create-sensitivity-grad-sequence.trycloudflare[.]com` | Cloudflare tunnel C2 |
| Domain | `investigation-launches-hearings-copying.trycloudflare[.]com` | Cloudflare tunnel C2 |
| Domain | `plug-tab-protective-relay.trycloudflare[.]com` | Cloudflare tunnel C2 |
| Domain | `souls-entire-defined-routes.trycloudflare[.]com` | Cloudflare tunnel C2 |

### 6.3 File Hashes (SHA256)

| Value | Description |
|-------|-------------|
| `0880819ef821cff918960a39c1c1aada55a5593c61c608ea9215da858a86e349` | `kamikaze.sh` initial credential harvester |
| `30015dd1e2cf4dbd49fff9ddef2ad4622da2e60e5c0b6228595325532e948f14` | Self-signed certificate (Wave 1) |
| `41c4f2f37c0b257d1e20fe167f2098da9d2e0a939b09ed3f63bc4fe010f8365c` | Self-signed certificate (Wave 2) |
| `d8caf4581c9f0000c7568d78fb7d2e595ab36134e2346297d78615942cbbd727` | Self-signed certificate (Wave 3) |
| `0c0d206d5e68c0cf64d57ffa8bc5b1dad54f2dda52f24e96e02e237498cb9c3a` | Malicious payload |
| `0c6a3555c4eb49f240d7e0e3edbfbb3c900f123033b4f6e99ac3724b9b76278f` | Malicious payload |
| `18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a` | Malicious payload |
| `1e559c51f19972e96fcc5a92d710732159cdae72f407864607a513b20729decb` | Malicious payload |
| `5e2ba7c4c53fa6e0cef58011acdd50682cf83fb7b989712d2fcf1b5173bad956` | Malicious payload |
| `61ff00a81b19624adaad425b9129ba2f312f4ab76fb5ddc2c628a5037d31a4ba` | Malicious payload |
| `6328a34b26a63423b555a61f89a6a0525a534e9c88584c815d937910f1ddd538` | Malicious payload |
| `7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9` | Malicious payload |
| `7b5cc85e82249b0c452c66563edca498ce9d0c70badef04ab2c52acef4d629ca` | Malicious payload |
| `7df6cef7ab9aae2ea08f2f872f6456b5d51d896ddda907a238cd6668ccdc4bb7` | Malicious payload |
| `822dd269ec10459572dfaaefe163dae693c344249a0161953f0d5cdd110bd2a0` | Malicious payload |
| `887e1f5b5b50162a60bd03b66269e0ae545d0aef0583c1c5b00972152ad7e073` | Malicious payload |
| `bef7e2c5a92c4fa4af17791efc1e46311c0f304796f1172fce192f5efc40f5d7` | Malicious payload |
| `c37c0ae9641d2e5329fcdee847a756bf1140fdb7f0b7c78a40fdc39055e7d926` | Malicious payload |
| `cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3` | Malicious payload |
| `d5edd791021b966fb6af0ace09319ace7b97d6642363ef27b3d5056ca654a94c` | Malicious payload |
| `e4edd126e139493d2721d50c3a8c49d3a23ad7766d0b90bc45979ba675f35fea` | Malicious payload |
| `e6310d8a003d7ac101a6b1cd39ff6c6a88ee454b767c1bdce143e04bc1113243` | Malicious payload |
| `e64e152afe2c722d750f10259626f357cdea40420c5eedae37969fbf13abbecf` | Malicious payload |
| `e87a55d3ba1c47e84207678b88cacb631a32d0cb3798610e7ef2d15307303c49` | Malicious payload |
| `e9b1e069efc778c1e77fb3f5fcc3bd3580bbc810604cbf4347897ddb4b8c163b` | Malicious payload |
| `ecce7ae5ffc9f57bb70efd3ea136a2923f701334a8cd47d4fbf01a97fd22859c` | Malicious payload |
| `f398f06eefcd3558c38820a397e3193856e4e6e7c67f81ecc8e533275284b152` | Malicious payload |
| `f7084b0229dce605ccc5506b14acd4d954a496da4b6134a294844ca8d601970d` | Malicious payload |

### 6.4 File Paths & Filenames

| Type | Value | Description |
|------|-------|-------------|
| Filename | `kamikaze.sh` | Initial credential harvester script |
| Filename | `kube.py` | Worm/wiper payload for Kubernetes |
| Filename | `prop.py` | Malicious Python payload |
| Filename | `proxy_server.py` | Malicious Python payload |
| Filename | `tpcp.tar.gz` | Malicious archive for payload delivery |
| Path | `/host/root/.config/sysmon/sysmon.py` | Persistence dropper location |
| Path | `/var/lib/pgmon/pgmon.py` | CanisterWorm backdoor disguised as PostgreSQL utility |
| Path | `/var/lib/svc_internal/runner.py` | Wiper/backdoor runner script |
| Path | `/tmp/pglog` | Temporary file for malware staging |
| Path | `/tmp/.pg_state` | Temporary file for malware staging |
| Path | `/etc/systemd/system/internal-monitor.service` | Malicious systemd persistence |
| Path | `/etc/systemd/system/pgmonitor.service` | Malicious systemd persistence |

### 6.5 Kubernetes Artifacts

| Value | Description |
|-------|-------------|
| DaemonSet: `host-provisioner-iran` in `kube-system` | Iran-targeted wiper DaemonSet |
| DaemonSet: `host-provisioner-std` in `kube-system` | Backdoor DaemonSet for non-Iranian clusters |
| Container name: `kamikaze` | Wiper container within the DaemonSet |
| Container name: `provisioner` | Backdoor container within the DaemonSet |

### 6.6 Trojanized Packages

| Package | Registry | Malicious Versions |
|---------|----------|--------------------|
| LiteLLM | PyPI | `1.82.7`, `1.82.8` |
| Telnyx Python SDK | PyPI | Compromised versions |
| ast-results | OpenVSX | `v2.53.0` |
| cx-dev-assist | OpenVSX | `v1.7.0` |
| Multiple npm packages | npm | CanisterWorm-propagated |

---

## 7. MITRE ATT&CK Techniques

| Technique ID | Technique Name | Tactic | Description |
|--------------|----------------|--------|-------------|
| T1195 | Supply Chain Compromise | Initial Access | Systematic compromise of trusted OSS security tools such as Trivy, KICS, LiteLLM, and Telnyx to gain access to downstream consumers. |
| T1195.002 | Compromise Software Dependencies and Development Tools | Initial Access | Injection of infostealer payloads directly into GitHub Actions, PyPI registries, and npm packages. |
| T1078.004 | Valid Accounts: Cloud Accounts | Initial Access | Use of stolen GitHub PATs, PyPI publishing tokens, and service account credentials for authenticated access. |
| T1059.004 | Command and Scripting Interpreter: Unix Shell | Execution | `kamikaze.sh` credential harvester execution across CI/CD runners. |
| T1059.006 | Command and Scripting Interpreter: Python | Execution | `kube.py` worm/wiper and `.pth`-based credential stealer execution on every Python process initialization. |
| T1053.003 | Scheduled Task/Job: At (Linux) | Persistence | Systemd service registration for persistent backdoor (`pgmonitor.service`, `internal-monitor.service`). |
| T1036.005 | Masquerading: Match Legitimate Name or Location | Defense Evasion | Disguising malware as PostgreSQL utilities (`pgmon`, `pglog`, `pg_state`) and systemd services. |
| T1027 | Obfuscated Files or Information | Defense Evasion | Double Base64-encoded payloads and WAV steganography to bypass static analysis. |
| T1140 | Deobfuscate/Decode Files or Information | Defense Evasion | Runtime decoding of Base64 payloads to extract C2 endpoints. |
| T1552.001 | Unsecured Credentials: Credentials in Files | Credential Access | Sweeping `.env` files, AWS/Azure/GCP config directories, and SSH keys for credential harvesting. |
| T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | Credential Access | Harvesting credentials from cloud instance metadata service (IMDS) endpoints. |
| T1558.001 | Steal or Forge Kerberos Tickets: Golden Ticket | Credential Access | Using a victim's `GITHUB_TOKEN` to create hidden repositories as a fallback exfiltration channel. |
| T1530 | Data from Cloud Storage Object | Collection | Extraction of cloud access tokens, SSH keys, and Kubernetes secrets. |
| T1567.002 | Exfiltration Over Web Service | Exfiltration | Data exfiltration to vendor-themed typosquatted domains and ICP canister endpoints. |
| T1020 | Automated Exfiltration | Exfiltration | Automatic credential exfiltration triggered by npm install and Python process initialization. |
| T1570 | Lateral Tool Transfer | Lateral Movement | Worm propagation across Kubernetes clusters and Docker hosts. |
| T1021.007 | Remote Services: Kubernetes API | Lateral Movement | Scanning exposed Docker APIs on port `2375`, Kubernetes API exploitation, and SSH key harvesting for lateral spread. |
| T1072 | Software Deployment Tools | Lateral Movement | SDK-squatting targeting internal development kits. |
| T1105 | Ingress Tool Transfer | Command and Control | Download of second-stage payloads (`kube.py`, WAV steganography payloads). |
| T1573.002 | Encrypted Channel: Asymmetric Cryptography | Command and Control | AES-256-CBC session key wrapped in a 4096-bit RSA public key for encrypted C2 traffic. |
| T1008 | Fallback Channels | Command and Control | ICP canister backup C2, Cloudflare tunnels, and victim GitHub repositories as fallback channels. |
| T1486 | Data Encrypted for Impact | Impact | Ransomware deployment via the Vect partnership for extortion at scale. |
| T1485 | Data Destruction | Impact | Iran-targeted Kubernetes wiper deploying privileged DaemonSets to brick cluster nodes. |

---

*Report generated by TI Mindmap HUB - Cross-source Threat Intelligence Analysis*
*Analysis date: 2026-04-03 | Sources analyzed: 20 | Classification: TLP:WHITE*