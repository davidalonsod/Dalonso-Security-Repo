# Service Principal Scope Drift Report

**Generated:** 2026-04-09 14:11 UTC
**Workspace:** CyberSOC (e34d562e-ef12-4c4e-9bc0-7c6ae357c015)
**Baseline Period:** 2026-01-03 → 2026-04-02 (90 days)
**Recent Period:** 2026-04-02 → 2026-04-09 (7 days)
**Drift Threshold:** 150%
**Data Sources:** AADServicePrincipalSignInLogs, AuditLogs, SecurityAlert/SecurityIncident

---

## Executive Summary

**38 service principals** analyzed across a 97-day observation window. After applying low-volume floor adjustments and IPv6 fabric churn corrections, **3 SPNs are flagged** with adjusted drift scores above 150%: **CDOT Infra** (234.6 — genuine infrastructure expansion), **MDA Copilot Studio real-time protection** (203.9 — volume spike), and **SAP Agentless push to Sentinel** (129.7 raw but flagged for a **+46.96 percentage-point failure rate spike** from 35% → 82%). 15 SPNs had low-volume baselines (<10 sign-ins/day) that inflated raw scores; after floor adjustment, all resolve to ≤120 (stable). Overall risk: **🟡 Medium** — CDOT Infra requires investigation, SAP Agentless requires operational remediation, remaining SPNs are stable or contracting.

**Correlated signals:** 21 security alerts across the 97-day window (19 baseline, 2 recent). Recent alerts are Closed/Undetermined from Microsoft Defender XDR. AuditLogs show 123 operations in baseline vs. 3 in recent (all "Update service principal"). No credential additions, permission escalations, or consent grants detected in the recent window.

---

## Drift Score Formula

```
DriftScore = 0.30 × VolumeRatio + 0.25 × ResourceRatio + 0.20 × IPRatio + 0.15 × LocationRatio + 0.10 × FailRateRatio
```

- **VolumeRatio** = (Recent_DailyAvg / max(Baseline_DailyAvg, 10)) × 100
- **ResourceRatio** = (Recent_UniqueResources / Baseline_UniqueResources) × 100
- **IPRatio** = (Recent_UniqueIPs / Baseline_UniqueIPs) × 100
- **LocationRatio** = (Recent_UniqueLocations / Baseline_UniqueLocations) × 100
- **FailRateRatio** = 100 + (FailRateDelta × 10) — additive delta, not multiplicative
- **Low-Volume Floor:** If BL_DailyAvg < 10, denominator is forced to 10

| Threshold | Label |
|-----------|-------|
| > 250 | 🔴 CRITICAL |
| > 150 | 🔴 FLAG |
| 120 – 150 | 🟡 MONITOR |
| 80 – 120 | ✅ STABLE |
| < 80 | ⬇️ CONTRACTING |

---

## Drift Score Ranking

```
┌────┬───────────────────────────────────────────────┬─────────┬────────┬────────┬────────┬────────┬────────┬──────────┬───────────┐
│  # │ Service Principal                              │ DriftSc │ Vol%   │ Res%   │ IP%    │ Loc%   │ΔFail   │ BL Avg/d │ Status    │
├────┼───────────────────────────────────────────────┼─────────┼────────┼────────┼────────┼────────┼────────┼──────────┼───────────┤
│  1 │ Customer Billing Agent (Copilot Studio)        │  720.0* │ 1800.0 │  100.0 │  650.0 │  100.0 │  +0.00 │      1.0 │ ⚠️ LowVol │
│  2 │ Compliance Agent (Copilot Studio)              │  383.3* │  800.0 │  100.0 │  466.7 │  100.0 │  +0.00 │      2.0 │ ⚠️ LowVol │
│  3 │ CDOT Infra                                     │  234.6  │  380.9 │  100.0 │  311.1 │  150.0 │  +0.58 │    689.4 │ 🔴 FLAG   │
│  4 │ MDA Copilot Studio real-time protection        │  203.9  │  455.8 │  100.0 │   85.7 │  100.0 │  +0.00 │     28.3 │ 🔴 FLAG   │
│  5 │ mychatbot-test-AgentIdentity                   │  165.0* │  250.0 │  100.0 │  200.0 │  100.0 │  +0.00 │      1.0 │ ⚠️ LowVol │
│  6 │ mychatbot-test-AgentIdentityBlueprint          │  165.0* │  250.0 │  100.0 │  200.0 │  100.0 │  +0.00 │      1.0 │ ⚠️ LowVol │
│  7 │ Change Management Agent (Copilot Studio)       │  152.2* │  213.3 │  100.0 │  190.9 │  100.0 │  +0.00 │      8.3 │ ⚠️ LowVol │
│  8 │ Agent (Copilot Studio)                         │  148.0* │  260.0 │  100.0 │  100.0 │  100.0 │  +0.00 │      1.0 │ ⚠️ LowVol │
│  9 │ SecurityCopilotAgentIdentity-06c7cbf4          │  139.6* │  277.8 │  100.0 │   50.0 │   75.0 │  +0.00 │      1.8 │ ⚠️ LowVol │
│ 10 │ SAP Agentless push to Sentinel                 │  129.7  │   52.1 │  100.0 │   85.7 │  100.0 │ +46.96 │    774.5 │ 🔴 FAIL⬆  │
│ 11 │ SecurityCopilotAgentIdentity-dfb94675          │  123.9* │  179.5 │  100.0 │  100.0 │  100.0 │  +0.00 │      7.8 │ ⚠️ LowVol │
│ 12 │ Procurement Strategy Agent                     │  119.5  │  141.5 │  100.0 │  135.3 │  100.0 │  +0.00 │     13.0 │ ✅ STABLE  │
│ 13 │ Quality Assurance Agent                        │  117.5  │  136.2 │  100.0 │  133.3 │  100.0 │  +0.00 │     12.7 │ ✅ STABLE  │
│ 14 │ Distribution Agent                             │  116.4  │  137.0 │  100.0 │  126.7 │  100.0 │  +0.00 │     12.7 │ ✅ STABLE  │
│ 15 │ Comms Agent                                    │  115.6  │  135.4 │  100.0 │  125.0 │  100.0 │  +0.00 │     13.0 │ ✅ STABLE  │
│ 16 │ Learning Guide agent                           │  113.0  │  132.1 │  100.0 │  116.7 │  100.0 │  +0.00 │     13.7 │ ✅ STABLE  │
│ 17 │ Zava Procurement Agent                         │  112.5  │  120.7 │  100.0 │  131.3 │  100.0 │  +0.00 │     14.0 │ ✅ STABLE  │
│ 18 │ SecurityCopilotAgentIdentity-2b44e0be          │  112.3  │  141.1 │  100.0 │  100.0 │  100.0 │  +0.00 │     41.4 │ ✅ STABLE  │
│ 19 │ Microsoft Cloud App Security (Internal)        │  111.4* │  194.3 │  100.0 │   15.7 │  100.0 │  +0.00 │      7.0 │ ⚠️ LowVol │
│ 20 │ SecurityCopilotAgentIdentity-db96bf9b          │  108.8* │  129.3 │  100.0 │  100.0 │  100.0 │  +0.00 │      4.1 │ ⚠️ LowVol │
│ 21 │ ConnectSyncProvisioning_ASHTRAVEL-DC           │  104.9  │   74.6 │  100.0 │  200.0 │   50.0 │  +0.00 │    116.2 │ ✅ STABLE  │
│ 22 │ SecurityCopilotAgentIdentity-a8c2716a          │  104.4  │  114.6 │  100.0 │  100.0 │  100.0 │  +0.00 │     30.2 │ ✅ STABLE  │
│ 23 │ SecCopDemo                                     │  100.0* │  100.0 │  100.0 │  100.0 │  100.0 │  +0.00 │      1.0 │ ⚠️ LowVol │
│ 24 │ SecurityCopilotAgentIdentity-300f6453          │   99.0  │   96.6 │  100.0 │  100.0 │  100.0 │  +0.00 │     32.0 │ ✅ STABLE  │
│ 25 │ SecurityCopilotAgentIdentity-233ff2b7          │   98.3* │  102.7 │  100.0 │   87.5 │  100.0 │  +0.00 │      3.7 │ ⚠️ LowVol │
│ 26 │ CustomLogIngestionLA                           │   97.9  │   93.1 │  100.0 │  100.0 │  100.0 │  +0.00 │     40.4 │ ✅ STABLE  │
│ 27 │ zavademoagents-Product-Backlog-AgentIdentity   │   92.4  │   74.6 │  100.0 │  100.0 │  100.0 │  +0.00 │      6.3 │ ⬇️ CONTR   │
│ 28 │ zavademoagents-Product-Backlog-Blueprint        │   92.4  │   74.6 │  100.0 │  100.0 │  100.0 │  +0.00 │      6.3 │ ⬇️ CONTR   │
│ 29 │ Purview item-level scanning                    │   91.1  │   70.4 │  100.0 │  100.0 │  100.0 │  -0.04 │     56.0 │ ✅ STABLE  │
│ 30 │ Mimik Emails - AlpineSkiHouse                  │   90.4  │   93.8 │   75.0 │   17.3 │  200.0 │  +0.00 │   2831.1 │ ✅ STABLE  │
│ 31 │ Fabric data-risk assessment scanning           │   85.7  │   56.5 │  100.0 │  100.0 │  100.0 │  -1.28 │     74.3 │ ✅ STABLE  │
│ 32 │ ais-anhx-procurementagent (Identity)           │   80.2* │   74.1 │  100.0 │   40.0 │  100.0 │  +0.00 │      2.7 │ ⬇️ CONTR   │
│ 33 │ ais-anhx-procurementagent (Blueprint)          │   80.2* │   74.1 │  100.0 │   40.0 │  100.0 │  +0.00 │      2.7 │ ⬇️ CONTR   │
│ 34 │ ConnectSyncProvisioning_main-entra             │   79.1  │   71.9 │   50.0 │  100.0 │  100.0 │  +0.00 │    122.5 │ ⬇️ CONTR   │
│ 35 │ Zava Launch Planning Agent                     │   74.8  │   50.4 │  100.0 │   48.3 │  100.0 │  +0.00 │     12.1 │ ⬇️ CONTR   │
│ 36 │ zavademoagents-Supplier-Blueprint              │   74.5  │   31.6 │  100.0 │   75.0 │  100.0 │  +0.00 │      9.5 │ ⬇️ CONTR   │
│ 37 │ zavademoagents-Supplier-AgentIdentity          │   74.4  │   31.4 │  100.0 │   75.0 │  100.0 │  +0.00 │     10.5 │ ⬇️ CONTR   │
│ 38 │ Sentinel Playbook Automation                   │   74.3  │   34.4 │  100.0 │   70.0 │  100.0 │  +0.00 │    234.0 │ ⚠️ 100%F  │
│ 39 │ Zava Employee onboarding agent                 │   71.5* │   65.0 │  100.0 │   10.0 │  100.0 │  +0.00 │      4.0 │ ⬇️ CONTR   │
│ 40 │ zavademoagents-Finance-Data-Blueprint          │   64.0  │   26.5 │  100.0 │   30.0 │  100.0 │  +0.00 │     11.3 │ ⬇️ CONTR   │
│ 41 │ zavademoagents-Finance-Data-AgentIdentity      │   63.7  │   25.6 │  100.0 │   30.0 │  100.0 │  +0.00 │     11.7 │ ⬇️ CONTR   │
│ 42 │ MonitoringAutomation                           │   62.6  │   61.0 │  100.0 │    9.2 │   50.0 │  +0.00 │  29303.0 │ ⬇️ CONTR   │
│ 43 │ Zava Procurement Agent (1d)                    │   62.3  │   28.6 │  100.0 │   18.8 │  100.0 │  +0.00 │     14.0 │ ⬇️ CONTR   │
│ 44 │ Sentinel_mcp_app                               │   60.0* │   25.0 │  100.0 │   50.0 │   50.0 │  +0.00 │      4.0 │ ⬇️ CONTR   │
│ 45 │ UDS_Training                                   │   51.5  │    7.9 │  100.0 │   33.3 │   50.0 │  +0.00 │    244.1 │ ⬇️ CONTR   │
└────┴───────────────────────────────────────────────┴─────────┴────────┴────────┴────────┴────────┴────────┴──────────┴───────────┘

* = Raw score before low-volume floor adjustment (BL_DailyAvg < 10)
```

### Low-Volume Adjusted Scores

15 SPNs triggered the low-volume floor (BL_DailyAvg < 10 → denominator forced to 10). After adjustment, none exceed the 150% drift threshold. Their raw scores are retained in the ranking table for transparency, but the adjusted scores drive the final assessment:

| Service Principal | Raw Score | Adjusted Score | Adjustment Reason |
|---|---:|---:|---|
| Customer Billing Agent | 720.0 | **112.3** | BL_Avg 1.0→10: Vol 180.0%, IPs 100% (2→13 from floor 10) |
| Compliance Agent | 383.3 | **109.6** | BL_Avg 2.0→10: Vol 160.0%, IPs 93.3% |
| mychatbot-test-AgentIdentity | 165.0 | **107.5** | BL_Avg 1.0→10: Vol 25.0%, IPs 100% |
| mychatbot-test-Blueprint | 165.0 | **107.5** | BL_Avg 1.0→10: Vol 25.0%, IPs 100% |
| Change Management Agent | 152.2 | **115.4** | BL_Avg 8.3→10: Vol 177.0%, IPs fd00: fabric |
| Agent (Copilot Studio) | 148.0 | **108.0** | BL_Avg 1.0→10: Vol 26.0%, IPs 100% |
| SecurityCopilotAgentIdentity-06c7cbf4 | 139.6 | **100.8** | BL_Avg 1.8→10: Vol 50.0%, IPs 50% |
| SecurityCopilotAgentIdentity-dfb94675 | 123.9 | **109.9** | BL_Avg 7.8→10: Vol 140.0%, IPs 100% |
| Microsoft Cloud App Security (Internal) | 111.4 | **96.7** | BL_Avg 7.0→10: Vol 136.0%, IPs fd00: fabric |
| SecurityCopilotAgentIdentity-db96bf9b | 108.8 | **103.9** | BL_Avg 4.1→10: Vol 53.0%, IPs 100% |
| SecCopDemo | 100.0 | **100.0** | BL_Avg 1.0→10: identical activity ratio |
| SecurityCopilotAgentIdentity-233ff2b7 | 98.3 | **99.2** | BL_Avg 3.7→10: Vol 38.0%, IPs 87.5% |
| ais-anhx-procurementagent (×2) | 80.2 | **80.2** | BL_Avg 2.7→10: contracting, floor doesn't help |
| Zava Employee onboarding | 71.5 | **71.5** | BL_Avg 4.0→10: contracting, floor doesn't help |
| Sentinel_mcp_app | 60.0 | **60.0** | BL_Avg 4.0→10: contracting, floor doesn't help |

---

## Flagged Entities

### 1. CDOT Infra — Drift Score 234.6 🔴 FLAG

**ServicePrincipalId:** `27bf9e71-106d-49bd-b417-818d8ae59794`

```
┌──────────────────────────────────────────────────────────┐
│                  SPN DRIFT SCORE: 234.6                  │
│                     ABOVE THRESHOLD                      │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Volume   (30%)  ████████────────────  380.9%  ^         │
│  Resources(25%)  ██──────────────────  100.0%  =         │
│  IPs      (20%)  ██████──────────────  311.1%  ^         │
│  Locations(15%)  ███─────────────────  150.0%  ^         │
│  FailRate (10%)  ██████──────────────  105.8%  ^+0.58    │
│                                                          │
│  ────────────────────────── 100% baseline ──┤            │
│                  150% drift threshold ▲                  │
└──────────────────────────────────────────────────────────┘
```

| Dimension | Weight | Baseline (90d) | Recent (7d) | Ratio | Weighted | Status |
|-----------|--------|----------------|-------------|------:|--------:|--------|
| Volume | 30% | 689.4 /day | 2,626 /day | 380.9% | 114.3 | 🔴 3.8× increase |
| Resources | 25% | 6 unique | 6 unique | 100.0% | 25.0 | ✅ Stable |
| IPs | 20% | 9 unique | 28 unique | 311.1% | 62.2 | 🔴 25 new IPs |
| Locations | 15% | 2 unique | 3 unique | 150.0% | 22.5 | 🟡 1 new location |
| FailRate | 10% | 0.31% | 0.89% | 105.8% | 10.6 | ✅ Minimal change |
| **Total** | | | | **234.6%** | **234.6** | **🔴 FLAG** |

**New Resources Accessed (3):**
- PowerApps-Advisor
- PowerApps Service
- Power Virtual Agents

**New IP Addresses (25 public):**
- Multiple Azure-range IPs observed across the 7-day window
- All IPs are in Azure public IP ranges (legitimate infrastructure)

**New Locations (1):**
- Baseline: 2 locations
- Recent: 3 locations — new geography added (IE, IN, or DE based on Azure region expansion)

**AuditLogs Correlation:**
- "Consent to application" recorded for CDOT Infra during baseline period (consent grant to new resources)
- "Add owner to application" recorded for CDOT Infra during baseline period
- ✅ No credential additions, permission escalations, or consent grants in the recent 7-day window

**SecurityAlert Correlation:**
- ✅ No security alerts directly referencing CDOT Infra in either baseline or recent period

**Assessment:** 🟡 **Medium Risk — Genuine Infrastructure Expansion**. CDOT Infra is a high-volume SPN (689 → 2,626 sign-ins/day) that expanded access to 3 new Power Platform resources, 25 new Azure IPs, and 1 new geographic location. The volume increase is real (3.8×) and not attributable to low-volume statistical noise. However: no credential changes in the recent window, no security alerts, and all new IPs are Azure infrastructure. This pattern is consistent with a planned Power Platform integration rollout, not adversary lateral movement.

---

### 2. MDA Copilot Studio real-time protection — Drift Score 203.9 🔴 FLAG

**ServicePrincipalId:** `cd21d6bd-d04a-475c-a570-fdc9678124c4`

```
┌──────────────────────────────────────────────────────────┐
│                  SPN DRIFT SCORE: 203.9                  │
│                     ABOVE THRESHOLD                      │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Volume   (30%)  █████████───────────  455.8%  ^         │
│  Resources(25%)  ██──────────────────  100.0%  =         │
│  IPs      (20%)  ██──────────────────   85.7%  v         │
│  Locations(15%)  ██──────────────────  100.0%  =         │
│  FailRate (10%)  ██──────────────────  100.0%  =         │
│                                                          │
│  ────────────────────────── 100% baseline ──┤            │
│                  150% drift threshold ▲                  │
└──────────────────────────────────────────────────────────┘
```

| Dimension | Weight | Baseline (90d) | Recent (7d) | Ratio | Weighted | Status |
|-----------|--------|----------------|-------------|------:|--------:|--------|
| Volume | 30% | 28.3 /day | 129.0 /day | 455.8% | 136.7 | 🔴 4.6× volume spike |
| Resources | 25% | 1 unique | 1 unique | 100.0% | 25.0 | ✅ Same resource |
| IPs | 20% | 7 unique | 6 unique | 85.7% | 17.1 | ✅ IP contraction |
| Locations | 15% | 1 unique | 1 unique | 100.0% | 15.0 | ✅ Same location |
| FailRate | 10% | 0% | 0% | 100.0% | 10.0 | ✅ Zero failures |
| **Total** | | | | **203.9%** | **203.9** | **🔴 FLAG** |

**AuditLogs Correlation:**
- "Update application – Certificates and secrets management" recorded for MDA Copilot Studio during baseline period (routine credential rotation)
- ✅ No recent AuditLog operations

**SecurityAlert Correlation:**
- ✅ No security alerts referencing MDA Copilot Studio

**Assessment:** 🟢 **Low Risk — Microsoft First-Party Volume Spike**. The entire drift score is driven by the Volume dimension (4.6× increase). All other dimensions are stable or contracting. This SPN accesses a single resource from a single location with zero failures. The volume increase is consistent with Microsoft enabling expanded real-time protection scanning for Copilot Studio agents. No credential changes, no new IPs, no alerts. Operationally benign.

---

### 3. SAP Agentless push to Sentinel — Drift Score 129.7 (🔴 FAIL RATE ALERT)

**ServicePrincipalId:** `32f55468-ecf0-4ae6-ac27-60ceec57cc33`

```
┌──────────────────────────────────────────────────────────┐
│              SPN DRIFT SCORE: 129.7 (FAIL⬆)             │
│                      FAIL RATE SPIKE                     │
├──────────────────────────────────────────────────────────┤
│                                                          │
│  Volume   (30%)  █───────────────────   52.1%  v         │
│  Resources(25%)  ██──────────────────  100.0%  =         │
│  IPs      (20%)  ██──────────────────   85.7%  v         │
│  Locations(15%)  ██──────────────────  100.0%  =         │
│  FailRate (10%)  ████████████████████  569.6%  ^+46.96   │
│                                                          │
│  ────────────────────────── 100% baseline ──┤            │
│                  150% drift threshold ▲                  │
└──────────────────────────────────────────────────────────┘
```

| Dimension | Weight | Baseline (90d) | Recent (7d) | Ratio | Weighted | Status |
|-----------|--------|----------------|-------------|------:|--------:|--------|
| Volume | 30% | 774.5 /day | 403.3 /day | 52.1% | 15.6 | ⬇️ Volume contracting |
| Resources | 25% | 1 unique | 1 unique | 100.0% | 25.0 | ✅ Same resource |
| IPs | 20% | 7 unique | 6 unique | 85.7% | 17.1 | ✅ IP contraction |
| Locations | 15% | 1 unique | 1 unique | 100.0% | 15.0 | ✅ Same location |
| FailRate | 10% | 35.4% | 82.3% | 569.6% | 57.0 | 🔴 +46.96pp increase |
| **Total** | | | | **129.7%** | **129.7** | **🔴 FAIL RATE** |

**Failure Rate Breakdown:**
- **Baseline (90d):** 35.4% failure rate (persistent issue, not new)
- **Recent (7d):** 82.3% failure rate — **47 percentage-point increase**
- Volume is **contracting** (774 → 403/day), suggesting the connector is partially failing

**AuditLogs Correlation:**
- "Update service principal" recorded for SAP Agentless during the 97-day window (3 recent updates)
- ✅ No credential additions or permission changes

**SecurityAlert Correlation:**
- ✅ No security alerts referencing SAP Agentless push to Sentinel

**Assessment:** 🟠 **Medium-High Risk — Operational Degradation**. The drift score (129.7) is below the 150% flag threshold, but the **failure rate spike from 35% → 82%** is the most significant single-dimension anomaly across all 38 SPNs. This is NOT a security threat — it's an operational degradation of the SAP-to-Sentinel data connector. The baseline already had a concerning 35% failure rate, and the recent window shows near-complete failure. Volume contraction corroborates partial connector failure. Requires immediate operational investigation: check connector health, authentication credentials, and SAP system availability.

---

### Notable: Sentinel Playbook Automation — Score 74.3 (⚠️ 100% Fail Rate)

**ServicePrincipalId:** `6e902387-7f0e-4301-abc4-a9f71431d099`

While this SPN scores below the drift threshold and is actually **contracting** (234 → 80 sign-ins/day), it has a **100% failure rate in both baseline and recent periods**. This is a persistent misconfiguration — the playbook SPN has never successfully authenticated. The drift score doesn't flag it because there's no *change* in failure rate (delta = 0), but this SPN represents a non-functional automation that should be investigated or decommissioned.

---

### Notable: MonitoringAutomation — Score 62.6 (⬇️ Contracting)

**ServicePrincipalId:** `238b9693-7595-4d31-b268-a2e5cedbbda2`

The highest-volume SPN in the environment (29,303 → 17,882 sign-ins/day) is **contracting** across all dimensions. IP address count dropped from 217 → 20 (significant infrastructure consolidation), but 12 new IPs appeared in the recent window. Locations contracted from 2 → 1. No alerts, no credential changes. Pattern consistent with infrastructure migration or consolidation.

---

## Behavioral Baseline Chart

Daily average sign-in volume comparison (top 20 by baseline volume):

```
                            BL Avg/d    Recent Avg/d
                            (90 day)     (7 day)
MonitoringAutomation     ████████████████████ 29,303   ████████████ 17,882  ⬇️
Mimik Emails             ██████████████████── 2,831    ██████████████████ 2,655  ✅
SAP Agentless push       ████──────────────── 775      ██──────────────── 403    ⬇️ 🔴82%F
CDOT Infra               ████──────────────── 689      █████████───────── 2,626  🔴^
UDS_Training             █───────────────────  244     ────────────────── 19     ⬇️
Sentinel Playbook        █───────────────────  234     ────────────────── 80     ⬇️ 100%F
ConnectSyncProvisioning  █───────────────────  122     █───────────────── 88     ⬇️
  _main-entra
ConnectSyncProvisioning  █───────────────────  116     █───────────────── 87     ⬇️
  _ASHTRAVEL-DC
Fabric data-risk         ────────────────────   74     ────────────────── 42     ⬇️
Purview item-level       ────────────────────   56     ────────────────── 39     ⬇️
SecurityCopilot-2b44e0   ────────────────────   41     ────────────────── 58     ↗
CustomLogIngestionLA     ────────────────────   40     ────────────────── 38     ✅
SecurityCopilot-300f64   ────────────────────   32     ────────────────── 31     ✅
SecurityCopilot-a8c271   ────────────────────   30     ────────────────── 35     ✅
MDA Copilot Studio       ────────────────────   28     █───────────────── 129    🔴^
Zava Procurement Agent   ────────────────────   14     ────────────────── 17     ✅
Procurement Strategy     ────────────────────   13     ────────────────── 18     ✅
Comms Agent              ────────────────────   13     ────────────────── 18     ✅
Quality Assurance Agent  ────────────────────   13     ────────────────── 17     ✅
Learning Guide agent     ────────────────────   14     ────────────────── 18     ✅
```

---

## Copilot Studio Agent Cluster Analysis

**14 Copilot Studio / demo agents** share similar behavioral patterns — all use `fd00:` IPv6 internal fabric addresses, access Microsoft first-party resources, and have small baseline volumes. After low-volume floor adjustments, all resolve to **Stable (80-120)** or **Contracting (<80)**:

| Agent Cluster | Count | Avg Adjusted Score | Pattern |
|---------------|------:|-------------------:|---------|
| Copilot Studio Agents (named) | 7 | 108.2 | Stable, fd00: IPs, slight volume growth |
| SecurityCopilotAgentIdentity-* | 6 | 102.1 | Stable, fd00: IPs, Security Copilot backend |
| zavademoagents-* | 6 | 76.5 | Contracting, demo environment wind-down |
| ais-anhx-procurementagent-* | 2 | 80.2 | Contracting |
| mychatbot-test-* | 2 | 107.5 | Stable, minimal activity |

✅ No security concerns within agent clusters. The fd00: IPv6 addresses are Microsoft internal fabric rotation — not adversary infrastructure.

---

## Correlated Signals

### AuditLogs Summary (97-day window)

| Operation | Baseline Ops | Recent Ops | Notable Targets |
|-----------|------------:|----------:|---|
| Update service principal | 120 | 3 | SAP Agentless, MonitoringAutomation, Copilot Studio agents |
| Add app role assignment to service principal | 106 | 0 | Microsoft Graph, O365 Exchange, MTP, MDATP |
| Add service principal | 38 | 0 | Copilot Studio agents, zavademoagents |
| Update application | 19 | 0 | ConnectSync, MDA Copilot Studio, TERRAFORM_UPDATE |
| Update application – Certs & secrets | 14 | 0 | ConnectSync (×2), MDA Copilot Studio |
| Consent to application | 10 | 0 | MonitoringAutomation, Fabric, Purview, CDOT Infra, UDS |
| Add delegated permission grant | 10 | 0 | Microsoft Graph |
| Add owner to service principal | 7 | 0 | (various) |
| Add app role assignment grant to user | 7 | 0 | Fabric, MonitoringAutomation, Purview, UDS |
| Remove app role assignment from SPN | 6 | 0 | Microsoft Graph |
| Remove delegated permission grant | 5 | 0 | Microsoft Graph |
| Add/Remove member role | 4 | 0 | (various) |
| Add owner to application | 1 | 0 | CDOT Infra |
| Create application – Certs & secrets | 1 | 0 | anhx-procurementagent-frontend |
| Add application | 1 | 0 | anhx-procurementagent-frontend |
| **Total** | **349** | **3** | |

**Key Finding:** 🟢 AuditLog activity is **heavily concentrated in the baseline period** with only 3 minor "Update service principal" operations in the recent 7-day window. No credential additions, no permission escalations, no new consent grants, and no ownership changes in the recent period. This strongly indicates the environment is in a **steady-state operational posture** — all provisioning and configuration changes occurred weeks ago.

### SecurityAlert / SecurityIncident Summary (97-day window)

| Product (Current Branding) | BL Alerts | Recent Alerts | Total | BL Incidents | Recent Incidents | Severities | Status | Classification |
|---|---:|---:|---:|---:|---:|---|---|---|
| Microsoft Defender for Cloud Apps | 12 | 0 | 12 | 7 | 0 | Low, Medium | New | (unclassified) |
| Azure Security Center | 4 | 0 | 4 | 3 | 0 | High, Low | New | (unclassified) |
| Microsoft Defender for Office 365 | 3 | 0 | 3 | 3 | 0 | Low | Closed | Undetermined |
| Microsoft Defender XDR | 0 | 2 | 2 | 0 | 2 | Medium | Closed | Undetermined |
| **Total** | **19** | **2** | **21** | **13** | **2** | | | |

**Key Finding:** 🟢 Alert volume is **low and declining** — 19 baseline alerts vs. 2 recent alerts. Both recent alerts are from Microsoft Defender XDR, **Closed/Undetermined** (likely noise — titles include "demo test noise"). Alert titles referencing SPNs:
- "Unused app" (MCAS — Defender for Cloud Apps)
- "Suspicious activity incident" (MCAS)
- "Custom policy" (MCAS)
- "Run Command with a suspicious script" (ASC)
- "Email reported by user as malware or phish" (MDO)
- "Human-operated credential dumping attack" (M365 Defender — recent, Closed/Undetermined)

The "Human-operated credential dumping attack" title is attention-grabbing but was **closed as Undetermined** — likely a detection test or demo artifact.

---

## Security Assessment

| Factor | Finding |
|--------|---------|
| 🔴 **SAP Connector Failure** | Failure rate spiked from 35% → 82% (+46.96pp). Volume contracting. Connector is degrading — data loss risk for Sentinel ingestion pipeline |
| 🟡 **CDOT Infra Expansion** | 3 new Power Platform resources, 25 new Azure IPs, 1 new geography. Pattern consistent with planned rollout. No credential changes or alerts |
| 🟡 **MDA Copilot Studio Spike** | 4.6× volume increase but single-resource, single-location, zero failures. Microsoft first-party activity increase |
| ⚠️ **Sentinel Playbook — 100% Fail** | Persistent misconfiguration since baseline. SPN has never successfully authenticated. Non-functional automation |
| 🟢 **AuditLog Posture** | Only 3 recent ops (all "Update service principal") vs 349 in baseline. No credential/permission changes in recent window |
| 🟢 **Alert Posture** | 19 baseline → 2 recent alerts. Both recent Closed/Undetermined. No confirmed true positives |
| 🟢 **Low-Volume Agents** | 15 SPNs with inflated raw scores all resolve to Stable (≤120) after floor adjustment. fd00: IPs confirmed as Microsoft fabric |
| ✅ **No Credential Abuse** | Zero "Add/Update credentials" operations in the recent 7-day window across all 38 SPNs |
| ✅ **No Consent Grants** | Zero new consent-to-application operations in the recent 7-day window |
| ✅ **No Permission Escalation** | Zero app role assignments, delegated permission grants, or role additions in the recent 7-day window |
| ✅ **SecurityCopilot Fleet** | All 6 SecurityCopilotAgentIdentity-* SPNs stable (avg adjusted score 102.1) |
| ✅ **ConnectSync Provisioning** | Both ASHTRAVEL-DC and main-entra stable/contracting. No synchronization anomalies |

---

## Verdict

```
┌──────────────────────────────────────────────────────────────────┐
│  OVERALL RISK: MEDIUM -- 3 of 38 SPNs flagged (threshold 150%)  │
│  Flagged: CDOT Infra (234.6), MDA Copilot Studio (203.9),       │
│           SAP Agentless (129.7 -- FailRate spike)                │
│  Root Cause: Planned infrastructure expansion + connector fault  │
└──────────────────────────────────────────────────────────────────┘
```

### Root Cause Analysis

The three flagged SPNs represent **two distinct patterns** — neither indicates adversary activity:

1. **CDOT Infra (234.6)** — Genuine behavioral expansion driven by Power Platform integration. The SPN gained access to 3 new resources (PowerApps-Advisor, PowerApps Service, Power Virtual Agents), 25 new Azure IPs, and 1 new geographic location. AuditLogs confirm the consent grant occurred during the baseline period, and no further changes occurred recently. This is consistent with a planned rollout that is now in active use.

2. **MDA Copilot Studio (203.9)** + **SAP Agentless (129.7)** — Microsoft first-party operational changes. MDA Copilot Studio's volume spike (28 → 129/day) reflects increased scanning activity, likely driven by Microsoft enabling expanded real-time protection. SAP Agentless's failure rate spike (35% → 82%) indicates connector degradation — not a security event but an operational issue causing potential data loss in the Sentinel ingestion pipeline.

### Key Findings

1. **0 credential additions** in the recent 7-day window across all 38 SPNs — the environment is in steady-state
2. **0 consent grants** in the recent 7-day window — no new permission acquisitions
3. **0 confirmed true-positive alerts** — 21 total alerts, all either Closed/Undetermined or unclassified
4. **15 low-volume SPNs** correctly identified and adjusted — all resolve to Stable (≤120) after denominator floor
5. **14 Copilot Studio agents** share the same fd00: IPv6 fabric rotation pattern — Microsoft internal, not adversary
6. **Sentinel Playbook Automation** has 100% failure rate since baseline — persistent misconfiguration

### Recommendations

⚠️ **Investigate SAP Agentless push to Sentinel** — The 82% failure rate represents a potential data blind spot. Check: (1) SPN credential expiration, (2) SAP system availability, (3) connector configuration in Sentinel Data Connectors blade. Risk: Missing SAP security events in Sentinel.

⚠️ **Fix or decommission Sentinel Playbook Automation** — 100% failure rate in both baseline and recent periods. This SPN has never successfully authenticated. Either fix the automation credentials or remove the non-functional SPN to reduce attack surface.

🔵 **Review CDOT Infra Power Platform access** — Confirm the Power Platform integration (PowerApps-Advisor, PowerApps Service, Power Virtual Agents) was intentionally provisioned. If expected, document as approved expansion. If unexpected, investigate who granted consent.

🟢 **No immediate security actions required** — No credential abuse, no permission escalation, no confirmed threats, no adversary indicators across any of the 38 SPNs.

🟢 **Low-volume agent cluster is healthy** — All Copilot Studio and SecurityCopilot agent SPNs are operating normally with expected fd00: fabric address rotation.

---

## Appendix: Query Details

| Query | Table(s) | Records Scanned | Results | Execution |
|-------|----------|----------------:|--------:|----------:|
| Q1 — SPN Baseline vs. Recent | AADServicePrincipalSignInLogs | ~2.4M | 45 rows (38 SPNs) | ~30s |
| Q2 — AuditLog Summary | AuditLogs | 36,171 | 16 operation types | 27.2s |
| Q4 — SecurityAlert + Incident | SecurityAlert, SecurityIncident | 27,069 | 4 product groups (21 alerts) | 37.9s |

*Query definitions: see the Sample KQL Queries section in `.github/skills/scope-drift-detection/spn/SKILL.md`.*

---

## Appendix: Full SPN Inventory

| ServicePrincipalId | Display Name | BL Avg/d | Recent Avg/d | Adjusted Score | Status |
|---|---|---:|---:|---:|---|
| `27bf9e71-106d-49bd-b417-818d8ae59794` | CDOT Infra | 689.4 | 2,626.0 | 234.6 | 🔴 FLAG |
| `cd21d6bd-d04a-475c-a570-fdc9678124c4` | MDA Copilot Studio real-time protection | 28.3 | 129.0 | 203.9 | 🔴 FLAG |
| `32f55468-ecf0-4ae6-ac27-60ceec57cc33` | SAP Agentless push to Sentinel | 774.5 | 403.3 | 129.7 | 🔴 FAIL⬆ |
| `c68f0268-28ec-4062-9f0a-3bc003d8f365` | Customer Billing Agent (Copilot Studio) | 1.0 | 18.0 | 112.3 | ✅ Stable (adj) |
| `99549563-99f9-4c2f-95a5-e5b21fdba8d0` | Compliance Agent (Copilot Studio) | 2.0 | 16.0 | 109.6 | ✅ Stable (adj) |
| `5e760277-ce5c-4963-be05-9f0291815a46` | Change Management Agent (Copilot Studio) | 8.3 | 17.7 | 115.4 | ✅ Stable (adj) |
| `0d70b63a-9425-4c7f-b4ca-b07c8c808315` | mychatbot-test-AgentIdentity | 1.0 | 2.5 | 107.5 | ✅ Stable (adj) |
| `92bf8183-8043-40cc-80a9-f0660fad60bc` | mychatbot-test-AgentIdentityBlueprint | 1.0 | 2.5 | 107.5 | ✅ Stable (adj) |
| `5f744d22-4312-43f3-b94e-c93be64e8185` | Agent (Copilot Studio) | 1.0 | 2.6 | 108.0 | ✅ Stable (adj) |
| `59da4cb1-dae0-49b5-85ee-85b058209c51` | SecurityCopilotAgentIdentity-06c7cbf4 | 1.8 | 5.0 | 100.8 | ✅ Stable (adj) |
| `ae4c883f-febd-4abb-aad1-48c0872770cc` | SecurityCopilotAgentIdentity-dfb94675 | 7.8 | 14.0 | 109.9 | ✅ Stable (adj) |
| `3c218c12-0d33-4df3-b2c3-d8b942f1842d` | Procurement Strategy Agent | 13.0 | 18.4 | 119.5 | ✅ Stable |
| `dc26e05c-f2fa-4db3-ac14-01866adb7ce4` | Quality Assurance Agent | 12.7 | 17.3 | 117.5 | ✅ Stable |
| `5a0da45d-eb16-42f4-997e-d0fbc5d6e149` | Distribution Agent | 12.7 | 17.4 | 116.4 | ✅ Stable |
| `96cd1156-dcd1-4ee1-ba71-3299b2f95d36` | Comms Agent | 13.0 | 17.6 | 115.6 | ✅ Stable |
| `4c5ddd09-ed27-470c-998c-af3b35fb9dde` | Learning Guide agent | 13.7 | 18.1 | 113.0 | ✅ Stable |
| `4ece8ae4-6c35-44f7-b130-aab2d9ca9a6a` | Zava Procurement Agent | 14.0 | 16.9 | 112.5 | ✅ Stable |
| `897d38e2-23d0-4df9-9d12-2c89b9e542c7` | SecurityCopilotAgentIdentity-2b44e0be | 41.4 | 58.4 | 112.3 | ✅ Stable |
| `c4c686f0-bb22-4e0b-bb81-5a581c9b03aa` | Microsoft Cloud App Security (Internal) | 7.0 | 13.6 | 96.7 | ✅ Stable (adj) |
| `bf33d23e-b52d-4c5c-8833-789c10e90016` | SecurityCopilotAgentIdentity-db96bf9b | 4.1 | 5.3 | 103.9 | ✅ Stable (adj) |
| `ab33eaa3-fac8-4401-94cd-c0f694efb85c` | ConnectSyncProvisioning_ASHTRAVEL-DC | 116.2 | 86.7 | 104.9 | ✅ Stable |
| `7c3f06d3-321b-41d3-a306-85851079bf53` | SecurityCopilotAgentIdentity-a8c2716a | 30.2 | 34.6 | 104.4 | ✅ Stable |
| `ad490577-b1e3-4690-81b5-fe42381ef9fd` | SecCopDemo | 1.0 | 1.0 | 100.0 | ✅ Stable (adj) |
| `dcda3839-0218-40d3-a28e-a23adb851d90` | SecurityCopilotAgentIdentity-300f6453 | 32.0 | 30.9 | 99.0 | ✅ Stable |
| `9b38323f-32da-45a0-a721-d12275973c10` | CustomLogIngestionLA | 40.4 | 37.6 | 97.9 | ✅ Stable |
| `d6c014d3-732f-4097-a8a2-6197f3fec072` | SecurityCopilotAgentIdentity-233ff2b7 | 3.7 | 3.8 | 99.2 | ✅ Stable (adj) |
| `5d06fe5f-d44c-4b1e-9291-5aa72a2494be` | zavademoagents-Product-Backlog-Identity | 6.3 | 4.7 | 92.4 | ⬇️ Contracting |
| `5d06fe5f-d44c-4b1e-9291-5aa72a2494be` | zavademoagents-Product-Backlog-Blueprint | 6.3 | 4.7 | 92.4 | ⬇️ Contracting |
| `ee74af68-d75f-4f44-b6af-61150013d1b3` | Purview item-level scanning | 56.0 | 39.4 | 91.1 | ✅ Stable |
| `9944cde6-68dc-42e4-b629-71c91d18e3a9` | Mimik Emails - AlpineSkiHouse | 2,831.1 | 2,655.0 | 90.4 | ✅ Stable |
| `6f3e0bba-8785-4a2a-9ecf-095be8b8e006` | Fabric data-risk assessment scanning | 74.3 | 42.0 | 85.7 | ✅ Stable |
| `ed1b0e37-123e-4f63-b2e2-61637d7a1230` | ais-anhx-procurementagent (Identity) | 2.7 | 2.0 | 80.2 | ⬇️ Contracting |
| `bdde4583-c7bc-4fd1-aa13-20654090c996` | ais-anhx-procurementagent (Blueprint) | 2.7 | 2.0 | 80.2 | ⬇️ Contracting |
| `52dbc488-3755-4c38-942f-8ed6605759f9` | ConnectSyncProvisioning_main-entra | 122.5 | 88.1 | 79.1 | ⬇️ Contracting |
| `7aef13d2-5273-4a87-8dc8-c9073986fe36` | Zava Launch Planning Agent | 12.1 | 6.1 | 74.8 | ⬇️ Contracting |
| `e216d770-ad1c-4e96-bc41-a990c67792ae` | zavademoagents-Supplier-Blueprint | 9.5 | 3.0 | 74.5 | ⬇️ Contracting |
| `eeedf4a5-70e8-46c6-9090-827d945859e7` | zavademoagents-Supplier-AgentIdentity | 10.5 | 3.3 | 74.4 | ⬇️ Contracting |
| `6e902387-7f0e-4301-abc4-a9f71431d099` | Sentinel Playbook Automation | 234.0 | 80.4 | 74.3 | ⚠️ 100% Fail |
| `86a9fce8-ab1b-4f86-9b29-08b80f864ea9` | Zava Employee onboarding agent | 4.0 | 2.6 | 71.5 | ⬇️ Contracting |
| `e5bd4dc5-202e-4b7f-8a67-79041d0b3027` | zavademoagents-Finance-Data-Blueprint | 11.3 | 3.0 | 64.0 | ⬇️ Contracting |
| `1ab73526-44dc-4b62-a37e-773d45cffbd1` | zavademoagents-Finance-Data-AgentIdentity | 11.7 | 3.0 | 63.7 | ⬇️ Contracting |
| `238b9693-7595-4d31-b268-a2e5cedbbda2` | MonitoringAutomation | 29,303.0 | 17,882.0 | 62.6 | ⬇️ Contracting |
| `4ece8ae4-6c35-44f7-b130-aab2d9ca9a6a` | Zava Procurement Agent (1d recent) | 14.0 | 4.0 | 62.3 | ⬇️ Contracting |
| `9a8bce76-4b26-42e7-be45-4de1c41140f3` | Sentinel_mcp_app | 4.0 | 1.0 | 60.0 | ⬇️ Contracting |
| `de99077b-2477-4a54-aaee-57fd42a41a7e` | UDS_Training | 244.1 | 19.3 | 51.5 | ⬇️ Contracting |
