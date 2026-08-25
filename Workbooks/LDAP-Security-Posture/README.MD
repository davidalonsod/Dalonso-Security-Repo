# 🛡️ LDAP Security Posture & DC Performance Dashboard

A Microsoft Sentinel **workbook** for monitoring **LDAP security and Domain Controller
performance** — clear-text/unsigned binds, expensive queries, AD reconnaissance,
privileged-object enumeration, attack-tool detection (BloodHound/SharpHound/PowerView),
and collection health. It multi-sources with `union isfuzzy=true` and falls back to DC
Security Events when Defender for Identity isn't deployed.

- **File:** `LDAP-Security-Posture-Dashboard.workbook`
- **Tabs:** 9 · **Query tiles:** 63 · **Parameters:** 2
- **Data sources:** MDI (`IdentityDirectoryEvents`, `IdentityQueryEvents`), `SecurityEvent` (2886–2889), `DeviceNetworkEvents` (LDAP ports), `Event` (1644), plus `SecurityAlert` / `SecurityIncident`
- **Type:** Azure Monitor / Microsoft Sentinel workbook

---

## Why this workbook

LDAP is the reconnaissance backbone of Active Directory attacks and a common DC
performance drain. This dashboard surfaces insecure bind hygiene (clear-text/unsigned),
expensive/inefficient queries hurting DCs, and the enumeration patterns that precede
Kerberoasting, DCSync, AD CS abuse, and ransomware — while also confirming your event
collection is healthy across every DC.

---

## Tabs

| Tab | What it covers |
|---|---|
| 📊 **Overview** | LDAP query volume, **unsigned** and **clear-text** binds, activity timeline, **LDAP vs LDAPS** usage, top query sources. |
| ⚡ **DC Performance** | **Expensive LDAP queries (Event 1644)**, trend, top clients causing DC load, unindexed-attribute queries, large subtree (domain-wide) scans, DC protection rejections, CPU↔query correlation. |
| 🔐 **Authentication** | Auth-method distribution, accounts using clear-text LDAP, binding issues, and geographic distribution (by country/city, new-geo detection). |
| 🔍 **Reconnaissance** | High-volume LDAP recon, after-hours activity, modifications to sensitive AD objects, data-source availability, raw Event 1644 view. |
| 👑 **Privileged Accounts** | Privileged-group enumeration, **KRBTGT access** (Golden Ticket), **AdminSDHolder** modifications, **SPN enumeration** (Kerberoasting), delegation discovery, GPO enumeration, **certificate-template enumeration (AD CS)**, domain-trust enumeration, RBCD queries. |
| 🛠️ **Attack Tools** | **BloodHound/SharpHound** collection detection, SharpHound membership pattern, **PowerView** enumeration. |
| ⚠️ **Abnormal Clients** | Top / first-time LDAP clients, connections by IP type, unusual-hours activity, **LDAP relay** indicators, attack-pattern timeline, IPs with both LDAP queries and failed auth. |
| 🎯 **Threat Intel** | LDAP/identity-related `SecurityAlert` + `SecurityIncident`, Defender XDR & **MDI** alerts, alert trend. |
| ✅ **Best Practices** | Per-event collection status, **DC agent / AMA health**, events per server, collection timeline per DC, **LDAP Security Posture Score**, per-DC compliance. |

---

## Key capabilities

- **Bind hygiene** — clear-text (389/3268) vs secure (636/3269) and unsigned-bind detection
  (Events 2886–2889).
- **DC performance protection** — expensive/inefficient query detection (Event 1644),
  domain-wide subtree scans, and client-load attribution.
- **AD reconnaissance & privilege-attack prep** — Kerberoasting (SPN), AD CS (cert
  templates), RBCD, delegation, domain-trust, KRBTGT, and AdminSDHolder enumeration.
- **Attack-tool detection** — BloodHound/SharpHound and PowerView collection patterns.
- **Abnormal-client & relay detection** — first-time clients, unusual hours, and LDAP relay
  indicators.
- **Threat-intel correlation** — MDI/XDR/Sentinel LDAP-and-identity alerts and incidents.
- **Collection assurance** — per-DC event-collection compliance and a posture score, so you
  know the data (and the detections) are trustworthy.

---

## Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `TimeRange` | Time picker | 30 days | Global time scope for every tile. |
| `Workspace` | Resource picker | *(set to your workspace)* | Target Log Analytics / Sentinel workspace (portable — replace the default). |

---

## Data sources & prerequisites

| Source | Used by |
|---|---|
| `IdentityDirectoryEvents` / `IdentityQueryEvents` (Defender for Identity) | Recon, Privileged, Attack Tools (preferred) |
| `SecurityEvent` (EventID 2886–2889) | Bind hygiene / signing enforcement (MDI fallback) |
| `DeviceNetworkEvents` (LDAP ports 389/636/3268/3269) | Overview, Abnormal Clients |
| `Event` (EventID 1644, Directory Service log) | DC Performance |
| `SecurityAlert` / `SecurityIncident` | 🎯 Threat Intel |

**Prerequisites**
- Collect the **Directory Service** log via AMA with this XPath:
  `Directory Service!*[System[(EventID=1644 or EventID=2886 or EventID=2887 or EventID=2888 or EventID=2889)]]`
- **Enable Event 1644** (expensive-query logging) on each DC via NTDS `15 Field
  Engineering = 5` and the search-result/time thresholds (see the workbook's title block
  for the exact `reg add` recipe).
- *(Recommended)* Deploy **Defender for Identity** for the richest recon/privileged
  coverage; without it, tiles fall back to DC Security Events.
- LDAP port ranges: **389/3268 = clear text (high risk)**, **636/3269 = TLS (secure)**.

---

## Deploy / import

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `LDAP-Security-Posture-Dashboard.workbook` and **Apply**.
3. **Done Editing** → **Save**, name it *LDAP Security Posture & DC Performance*, and pick
   your resource group / workspace.
4. Set **Workspace** (replace the baked-in default) and **Time Range**, then work the tabs.
   Start on **Best Practices** to confirm every DC is reporting the required events.

---

## Notes

- **Read-only.** The workbook only queries logs; it changes no AD or DC configuration.
- **Graceful degradation.** `union isfuzzy=true` means MDI / MDE / Directory-Service tiles
  render empty (not error) when a source isn't onboarded — verify via the Best Practices
  collection tiles.
- **Threat-actor context.** The title block maps LDAP TTPs to actors (APT29, APT28, FIN7,
  Conti/LockBit/BlackCat) for reference.
