# 🔐 NTLM Security Monitoring Dashboard 

Is NTLM Still Running in Your Network? Here’s How to Find It https://studio.youtube.com/video/32miUuQ88uE/edit

A Microsoft Sentinel **workbook** for end-to-end monitoring of **NTLM authentication** —
brute-force and credential-attack detection, lateral-movement and coerced-auth hunting,
compliance/deprecation tracking, and a dedicated **NTLM-removal** hunting tab. NTLM is a
legacy protocol exposed to Pass-the-Hash, coerced-auth, and relay attacks; this dashboard
helps you detect active abuse and prove NTLM can be turned off.

- **File:** `NTLM-Security-Monitoring-DashboardV2.workbook`
- **Tabs:** 8 · **Query tiles:** 71 · **Parameters:** 2
- **Primary data sources:** `SecurityEvent`, `Event` (System / NTLM Operational logs)
- **Type:** Azure Monitor / Microsoft Sentinel workbook

---

## Why this workbook

NTLM is everywhere and rarely fully retired. This dashboard gives a single place to
answer: *is NTLM volume normal, who is attacking, where is NTLM still used, does it tie to
known threats, which version/geography, what do the modern audit events show, am I
compliant — and what are the last dependencies I must kill to disable NTLM?* It supports
both classic Server 2016–2022 events and the enhanced **Windows 11 24H2 / Server 2025**
NTLM audit events.

---

## Tabs

| Tab | What it answers |
|---|---|
| **1 · Overview** | Normal NTLM volume? Anomaly vs 7-day baseline? — event summary, attack sources, legitimate usage, timeline, logon types, top devices, baseline deviation. |
| **2 · Attack Detection** | Who is brute-forced, from where, did any attack succeed? — most-targeted accounts, top attacking IPs, high-frequency windows, **credential-stuffing success**, **privileged accounts using NTLM**. |
| **3 · Identity & Device Analysis** | Where is NTLM used across MDI/MDE; lateral movement or insider abuse? — `IdentityLogonEvents`, `DeviceLogonEvents`, **lateral-movement detection**, after-hours activity, service-account migration candidates. |
| **4 · Threat Intelligence** | Which NTLM activity ties to known actors/indicators? — MITRE ATT&CK coverage, **`ThreatIntelIndicators` correlation**, top TI-matched IPs, threat-actor TTPs, deprecation progress. |
| **5 · NTLM Authentication Analysis** | Which version, from what geography, where are the risky external logons? — version analysis, protocol distribution, failure reasons, success/failure maps, external-IP analysis, new-geo detection, NTLM-vs-Kerberos trend, deprecation priority list. |
| **6 · Advanced NTLM Traffic** | Per-event-ID deep dive — 4769 SPN requests, 8001 outbound, 8003 inbound, **4020 client (24H2+)** with reason/targets, **4022 server (2025+)** clients/users, event-type summary & trend. |
| **7 · Best Practices & Compliance** | Am I compliant, what still needs changing? — GPO/registry recipes, NTLMv1, auditing/Credential Guard, SMB signing, privileged/service accounts, compliance summary & trend, exception-list candidates, devices needing upgrade. |
| **8 · NTLM Removal Scenarios** *(new)* | Hunt the last NTLM dependencies & offensive tooling, then prove NTLM can be disabled — coercion pipes, external NTLM surface, hash-exfil vectors, VM-snapshot theft, LSASS backdoors, non-Windows clients, Responder/Inveigh heuristic, NTDS.dit/SAM dumping, per-scenario remediation. |

---

## Key capabilities

- **Credential-attack detection** — brute force, high-frequency windows, credential-
  stuffing success, and privileged-account NTLM use.
- **Lateral-movement & insider hunting** — multi-device short-timeframe logons, after-hours
  activity, and service-account migration candidates across MDI (`IdentityLogonEvents`) and
  MDE (`DeviceLogonEvents`).
- **Coerced-auth & offensive-tooling hunts** — Coercer / PetitPotam / PrinterBug / DFSCoerce
  pipes, NTLMRecon / msprobe surface probing, CVE-2023-23397 / CVE-2024-21413 hash-exfil,
  VMkatz snapshot theft, LSASS backdoors (nosferatu / mimikatz / pypykatz), Impacket / Titanis
  clients, Responder / Inveigh heuristic, and NTDS.dit / SAM hive dumping.
- **Modern audit-event support** — enhanced NTLM events 4020/4022/4030/4032 (Win11 24H2 /
  Server 2025), including **NTLMv1 detection from the DC log alone via event 4032**.
- **Threat-intel & MITRE mapping** — `ThreatIntelIndicators` (STIX) correlation and
  T1550.002 (PtH), T1187 (Forced Auth), T1557.001 (Poisoning), T1003 (Credential Dumping).
- **Deprecation & compliance** — version analysis, priority lists, compliance summary/trend,
  and exception-list candidates.
- **Geolocation** — external-IP analysis, country/city distribution, and new-geo detection.

---

## Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `TimeRange` | Time picker | 30 days | Global time scope for every tile. |
| `Workspace` | Resource picker | — | Target workspace(s) via `crossComponentResources` (multi-workspace supported). |

---

## Data sources & prerequisites

| Source | Used by |
|---|---|
| `SecurityEvent` (4624/4625, 4776, 4769, 5145) | Overview, Attack Detection, Auth Analysis, Compliance, Removal Scenarios |
| `Event` (System / NTLM Operational: 8001–8006, 4001–4006, 4020/4022/4030/4032, blocked 4021/4023/4031/4033) | Advanced NTLM Traffic, version detection |
| `IdentityLogonEvents` (Microsoft Defender for Identity) | Identity & Device Analysis |
| `DeviceLogonEvents` / `DeviceNetworkEvents` / `DeviceFileEvents` / `DeviceEvents` (Defender for Endpoint) | Identity & Device Analysis, Removal Scenarios |
| `ThreatIntelIndicators` (STIX) | Threat Intelligence |
| `W3CIISLog` | External NTLM surface analysis |

**Prerequisites**
- Collect Windows **Security** events (4624/4625/4776/4769/5145) via AMA from DCs and
  members.
- Collect the **NTLM Operational** channel (`Microsoft-Windows-NTLM/Operational`) to
  populate 8001–8006 / 4020–4032; enable NTLM auditing GPO. Enhanced events require
  Windows 11 24H2 / Server 2025.
- *(Optional)* Onboard MDI / MDE for identity/device tables, a TI connector for
  `ThreatIntelIndicators`, and IIS logs for `W3CIISLog`.
- Cross-log tiles degrade gracefully — missing sources render empty, not error.

---

## Deploy / import

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `NTLM-Security-Monitoring-DashboardV2.workbook` and **Apply**.
3. **Done Editing** → **Save**, name it *NTLM Security Monitoring*, and pick your resource
   group / workspace.
4. Select **Workspace** and **Time Range**, then work the tabs from Overview → Removal
   Scenarios.

---

## Notes

- **Read-only.** The workbook only queries logs; it changes no configuration.
- **Modern TI schema.** Uses `ThreatIntelIndicators` (STIX) — not the retired
  `ThreatIntelligenceIndicator` table.
- **NTLMv1 accuracy.** On Server 2016–2022, NTLMv1 is inferred from `4624 LmPackageName`;
  on Server 2025 DCs prefer **event 4032** for authoritative NTLMv1 detection.
- **Compliance tiles** provide GPO/registry remediation recipes alongside the detections.
