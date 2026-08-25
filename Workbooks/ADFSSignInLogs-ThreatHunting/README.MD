# 🛡️ ADFSSignInLogs Threat Hunting Workbook

An Azure Monitor / Microsoft Sentinel **workbook** for hunting across federated
**Active Directory Federation Services (ADFS)** authentication events in the
`ADFSSignInLogs` table — and **cross-correlating with `SignInLogs`,
`SecurityEvent`, `AuditLogs`, and `Heartbeat`** to surface attacks that bypass or
tamper with the ADFS log stream itself.

- **File:** `ADFSSignInLogs-ThreatHunting-Workbook.json`
- **Tabs:** 10 · **Query tiles:** 51 · **Parameters:** 13
- **Type:** Azure Monitor Workbook (deploy via the Sentinel/Monitor Workbooks gallery)

> This workbook is the **interactive/visual** companion to the query pack in this
> repo. The scheduled detections live in [`Analytic-Rules/`](./Analytic-Rules),
> the interactive hunts in [`HuntingQueries/`](./HuntingQueries), and the
> standalone KQL pack is documented in the sibling [`README.md`](./README.md).
> Every tile honours the **same exclusion filters** as the analytic rules so what
> you hunt is exactly what the rules alert on.

---

## Why this workbook

ADFS is a Tier-0 identity component and a prime target: Golden SAML forgery,
extranet lockout / password spray, legacy-protocol MFA bypass, and log tampering
of the ADFS pipeline itself. This workbook turns the raw `ADFSSignInLogs` stream
into an analyst-ready hunting surface with baseline-aware anomaly tiles and
cross-log correlations that catch attacks **designed to be invisible in ADFS
alone**.

---

## Key capabilities

- **Cross-source identity hunting** — correlate ADFS with `SignInLogs`,
  `SecurityEvent`, `AuditLogs`, and `Heartbeat` to detect tampering or blind spots
  in the ADFS pipeline (all cross-log tiles use `union isfuzzy=true` so missing
  tables degrade gracefully).
- **Attack-pattern triage** — brute force, password spray (single-IP and
  distributed), impossible travel, legacy-auth abuse, botnet behavior, and
  token-issuer anomalies.
- **Golden SAML & token abuse** — unexpected token issuers, high SAML token
  volume, single-factor-on-ADFS, long-lived token reuse, and *Ghost* Golden SAML
  (federated success in `SignInLogs` with **no** matching ADFS record).
- **Privilege & persistence review** — break-glass use, privileged sign-in
  diversity, service accounts doing interactive auth, new/revived relying parties,
  and per-app issuer drift (`T1078`, `T1098`, `T1606.002`, `T1550.004`).
- **Behavioral anomaly detection** — MFA fatigue → success, time-of-day anomalies
  vs per-user baseline, auth-method drift (MFA → single-factor), user-agent
  entropy, and near-threshold failure suppression.
- **Operational guardrails** — parameter-driven exclusion pills and an optional
  `NetworkAllowlist` watchlist so hunting scope matches the deployed rules 1:1.
- **Rapid investigation workflow** — pivot from IPs, apps, issuers, and users to
  the raw event drill-down needed to validate and escalate.

---

## Tabs (audience map)

| Tab | Primary audience | What it answers |
|---|---|---|
| 📊 **Overview** | Management / IAM leads | Are ADFS sign-ins healthy? Where do they originate? Which apps drive volume? Baseline deviation. |
| 🔴 **Brute Force** | SOC analysts | Who is being hammered? Which IPs attack? Did any brute-force succeed (failure→success chain)? |
| 🟠 **Password Spray** | SOC analysts | Which IPs target many accounts? Low-and-slow campaigns below lockout threshold? |
| 🌍 **Geolocation** | SOC analysts | World map, sign-ins by country, high-risk countries, impossible travel, first-time-from-country. |
| 🛡️ **Token Issuer** | SOC / Identity engineers | MFA outcome breakdown, Golden SAML candidates, high SAML volume, single-factor on ADFS. |
| 🔍 **Legacy / ROPC** | Identity engineers | Who still uses legacy auth, ROPC, or device-code flows that bypass MFA/CA? |
| 🤖 **Botnet** | SOC analysts | Same UA across many users, IP reuse, heartbeat cadence (C2 signal). |
| 👑 **Privileged & Persistence** | IAM / Tier-0 owners | Break-glass use, privileged sign-in diversity, service-account interactive auth, new/revived RPs, issuer drift, long-lived token reuse. |
| 🧠 **Behavior & Anomalies** | SOC / UEBA | MFA fatigue → success, time-of-day anomalies, distributed spray, auth-method drift, UA entropy, near-threshold suppression, sign-in → `AuditLogs` privilege-action correlation. |
| 👻 **Advanced Threats** | Threat hunters / IR | Ghost Golden SAML, Hybrid Health log tampering (per-node volume drop + `SecurityEvent 1200` divergence), intranet-claim spoofing, modern-UA→legacy-WS-Trust downgrade, ESL-bypass lockout desync (`4740` without `396083`). |

---

## Highlighted detections

A selection of the 51 tiles that make this workbook ADFS-specific:

- **Failure → Success Chain** — failed brute-force run followed by a successful
  sign-in within 1 h (compromise indicator).
- **Impossible Travel** — same user, 3+ countries within a 1-hour window.
- **Unexpected Token Issuers** — `TokenIssuerName` outside your sanctioned list
  (Golden SAML candidate).
- **High SAML Token Volume** — > 50 tokens/hour per user+IP (automated replay).
- **Ghost Golden SAML** — `SignInLogs` federated success whose UPN has **no**
  `ADFSSignInLogs` event within ±5 min (forged SAML bypasses on-prem entirely).
- **Log-Tampering: Volume Drop per ADFS Node** — hourly per-`Computer` volume vs
  7-day baseline; flags SILENT / LOW / SPIKE.
- **SecurityEvent vs ADFSSignInLogs Divergence** — Windows `EventID 1200`
  (token issued) per node vs ADFS events (Hybrid Health Agent tamper / DPAPI key
  abuse).
- **Lockout Desync (ESL bypass)** — `SecurityEvent 4740` on-prem AD lockout with
  zero `396083` ADFS ESL hits in the prior 7 days.

---

## Parameters & exclusion model

Every tile starts with a parameter-driven prelude that **shadows `ADFSSignInLogs`
with a pre-filtered version**, so downstream KQL stays clean. Filters
AND-combine across pills and OR-combine within a multi-select. Order applied:
**ExcludedIPs → NetworkAllowlist → Countries → Apps → Issuers**.

| Parameter | Type | Default | Behaviour |
|---|---|---|---|
| `Workspace` | Resource | — | Target Log Analytics / Sentinel workspace (required). |
| `TimeRange` | Time picker | — | Global time scope (required). |
| `FailureThreshold` | Text | `10` | Failure count threshold for brute-force / spray tiles. |
| `BaselineDays` | Text | `30` | Baseline window length for first-seen / anomaly tiles. |
| `BaselineOffsetDays` | Text | `1` | Gap between baseline window and "now". |
| `ExcludedIPs` | Text | *(empty)* | Comma-separated IPv4 / CIDR / `a-b` ranges to drop. |
| `WatchlistFilter` | Dropdown | `\| where true` (Off) | **On** appends `\| invoke ExcludeAllowlistedIPs()` to match the analytic rules; **Off** is zero-cost. |
| `ExcludedCountries` | Multi-select | *(empty)* | Drop rows by `Location` (populated from data). |
| `Apps` | Multi-select | *(empty)* | Drop rows by `AppDisplayName` (populated from data). |
| `Issuers` | Multi-select | *(empty)* | Drop rows by `TokenIssuerName` — use sparingly, hides Golden SAML signal. |
| `PrivilegedUsers` | Text | `admin,sync_,svc-,service` | UPN substrings (`has_any`) scoping the Privileged tab. |
| `BreakGlassUsers` | Text | *(empty)* | **Exact** emergency-account UPNs; any sign-in is flagged. |
| `ServiceAccountPattern` | Text | `svc-,sa-,service_,_svc` | UPN substrings identifying service / non-interactive accounts. |

> 💡 Set **NetworkAllowlist = On** to align this workbook 1:1 with the analytic
> rules in `Analytic-Rules/azuredeploy.json`, which call the same
> `ExcludeAllowlistedIPs()` watchlist function.

---

## Required tables & connectors

| Table | Connector | Used by |
|---|---|---|
| `ADFSSignInLogs` | Microsoft Entra ID (ADFS sign-in stream) | Every tile |
| `SignInLogs` | Microsoft Entra ID | 👻 Advanced Threats → Ghost Golden SAML |
| `SecurityEvent` (`1200`, `4740`) | Windows Security Events / AMA | 👻 Advanced Threats → log-tampering divergence, ESL-bypass |
| `AuditLogs` | Microsoft Entra ID | 🧠 Behavior → sign-in → privileged-action correlation |
| `Heartbeat` | Azure Monitor Agent | Node coverage / tampering context |
| `Watchlist: NetworkAllowlist` + `ExcludeAllowlistedIPs()` | Deployed by `Analytic-Rules/azuredeploy.json` | Optional — only when `WatchlistFilter = On` |

Cross-log tiles use `union isfuzzy=true`, so tenants missing `SignInLogs`,
`SecurityEvent`, or `AuditLogs` still render — those specific detections simply
stay empty until the tables are onboarded.

---

## Deploy / import

**Option A — Portal (fastest)**

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `ADFSSignInLogs-ThreatHunting-Workbook.json` and **Apply**.
3. **Done Editing** → **Save**, name it *ADFSSignInLogs Threat Hunting*, and pick
   your resource group / workspace.
4. Select your **Workspace** and **Time range** pills, then work the tabs.

**Option B — Rebuild from source**

The JSON is generated from a compact spec:

```powershell
python .\build_workbook.py
```

**Companion analytic rules + watchlist** (optional but recommended):

```powershell
az deployment group create `
  --resource-group <sentinel-rg> `
  --template-file .\Analytic-Rules\azuredeploy.json `
  --parameters workspaceName=<workspace-name>
```

---

## Post-import tuning checklist

1. **Token Issuer → Unexpected Token Issuers** — replace the placeholder with your
   sanctioned ADFS federation service hostname(s).
2. **Geolocation → High-Risk Country Sign-Ins** — adjust the high-risk country
   list (`KP, IR, RU, BY, CU, SY, VE, MM` by default) to your policy.
3. **FailureThreshold** — raise for high-volume tenants, lower for tightly-scoped
   ones.
4. **BaselineDays / BaselineOffsetDays** — `30 / 1` default; widen for noisy
   environments.
5. **Privileged / Break-Glass / Service-Account pills** — populate before using
   the 👑 Privileged tab. Break-glass must be **exact UPNs**; the others are
   **substring** patterns.
6. **NetworkAllowlist** — set **On** to match deployed rules; ensure the watchlist
   and function exist (deployed by `Analytic-Rules/azuredeploy.json`).
7. **Advanced Threats** — onboard `SignInLogs`, `SecurityEvent`, and `AuditLogs`
   to light up Ghost Golden SAML, log-tampering, and ESL-bypass tiles.

---

## Repository layout

| Path | Contents |
|---|---|
| `ADFSSignInLogs-ThreatHunting-Workbook.json` | This workbook (import target) |
| `Analytic-Rules/` | Scheduled analytic rules + `ExcludeAllowlistedIPs()` / `NetworkAllowlist` ARM |
| `HuntingQueries/` | Interactive hunting-query YAMLs |
| `Watchlists/` | Watchlist definitions + seed data |
| `ADFSSignInLogs-ThreatHunting.kql` | Standalone KQL hunting pack |
| `README.md` | Docs for the standalone KQL hunting pack |
| `build_workbook.py` | Generates the workbook JSON from a spec |
| `patch_arm.py` / `patch_hunting_arm.py` | ARM packaging helpers |

---

## Notes

- The workbook is **read-only hunting** — it never modifies identity or ADFS
  configuration.
- Geolocation tiles enrich at query time with `geo_info_from_ip_address()`; no
  external IP-intel table is required for the map.
- Latency/duration tiles use `column_ifexists()` so they degrade gracefully on
  tenants where `DurationMs` / `ProcessingTimeInMs` is absent.
