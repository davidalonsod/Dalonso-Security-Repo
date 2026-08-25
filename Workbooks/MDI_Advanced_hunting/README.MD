# 🕵️ Defender for Identity — Identity Security Dashboard (MDI Advanced Hunting)

A Microsoft Sentinel **workbook** presenting **identity posture and activity** from
**Microsoft Defender XDR Advanced Hunting** — queried live against the `Identity*` (MDI)
tables rather than ingested into the Log Analytics workspace. It covers authentication,
brute-force/failures, reconnaissance, directory changes, MDI detections, and sensitive-
identity/honeytoken monitoring in one page.

- **File:** `MDI_Advanced_hunting_workbook.json`
- **Layout:** single page · **5 sections** · **Query tiles:** 14 · **Parameters:** 0
- **Data source:** Defender XDR **Advanced Hunting** (`queryType: advancedHunting`)
- **Tables:** `IdentityLogonEvents`, `IdentityInfo`, `IdentityQueryEvents`, `IdentityDirectoryEvents` (+ MDI alerts, Entra risky sign-ins)
- **Type:** Azure Monitor / Microsoft Sentinel workbook (Gallery Template JSON)

> **Advanced Hunting binding.** Every panel queries the Advanced Hunting data source (bound
> to a workspace, e.g. **CyberSOC**). If a panel shows no data after import, open the tile's
> **Advanced Editor** and confirm **Data source → Advanced hunting**, and re-point the
> workspace if needed.

---

## Why this workbook

Defender for Identity data lives in Defender XDR, not Sentinel's ingested tables. This
workbook surfaces MDI's identity signals — recon, credential attacks, Kerberos downgrades,
honeytoken hits, and sensitive-account targeting — using native Advanced Hunting, so there's
**no ingestion cost** and the figures match the Defender portal.

---

## Sections & tiles

| Section | Tiles |
|---|---|
| **Executive summary** | Identity activity (last 30 days), successful vs failed logons over time, MDI alerts by kill-chain stage & severity. |
| **Authentication, failures & reconnaissance** | Accounts with the most failed logons, reconnaissance queries by type, directory events by action type, **top 5 attacked users**, **top 5 users with anomalous logon increase**. |
| **Detections & hunting** | Reconnaissance (**SAMR / LDAP AllObjects / trust discovery**), **Kerberos encryption downgrade (RC4 / DES)**. |
| **Critical assets, honeytokens & cross-domain** | Sensitive identities at a glance, sensitive accounts targeted by MDI alerts, **honeytoken interaction (any = suspicious)**, **Entra risky sign-ins by MDI-flagged users**. |
| **Capabilities & authoritative sources** | Reference notes on the data sources each tile uses. |

---

## Key capabilities

- **Authentication & brute-force** — success/failure trend and the accounts absorbing the
  most failed logons.
- **Reconnaissance detection** — SAMR enumeration, LDAP AllObjects, trust discovery, and
  recon-query typing.
- **Credential-attack signals** — Kerberos encryption downgrade (RC4/DES) and anomalous
  logon-increase ranking.
- **MDI detections** — alerts by kill-chain stage & severity and the top attacked users.
- **Sensitive-identity protection** — sensitive-account inventory, MDI alerts targeting
  them, and **honeytoken** interaction (any hit is suspicious).
- **Cross-product correlation** — Entra ID risky sign-ins for users MDI has flagged.

---

## Parameters

_None._ The workbook renders directly against the bound Advanced Hunting workspace. (Adjust
the workspace binding on import if it isn't your Defender-connected workspace.)

---

## Data sources & prerequisites

| Table (Advanced Hunting) | Used for |
|---|---|
| `IdentityLogonEvents` | Authentication, failures, brute force, Kerberos downgrade |
| `IdentityQueryEvents` | Reconnaissance (SAMR / LDAP / trust discovery) |
| `IdentityDirectoryEvents` | Directory changes by action type |
| `IdentityInfo` | Sensitive-identity inventory / enrichment |
| MDI alerts (`AlertInfo`/`AlertEvidence`) | Alerts by kill-chain stage, attacked/targeted users |
| Entra risk (risky sign-ins) | Cross-product MDI-flagged risky sign-ins |

**Prerequisites**
- **Microsoft Defender for Identity** deployed and populating the `Identity*` Advanced
  Hunting tables.
- The workbook's tiles must point at **your** Defender-connected workspace (re-point as
  noted above).
- Permissions to run Defender XDR Advanced Hunting queries.
- *(Optional)* Configure **honeytoken** accounts in MDI so the honeytoken tile is meaningful.

---

## Deploy / import

1. Sentinel → **Workbooks** → **Add workbook** → **Edit** → **</> Advanced Editor**.
2. Paste the contents of `MDI_Advanced_hunting_workbook.json` and **Apply**.
3. **Done Editing** → **Save**, name it *Defender for Identity — Identity Security*, and pick
   your resource group / workspace.
4. If tiles are empty, confirm each tile's **Data source → Advanced hunting** and re-point the
   workspace to your Defender-connected workspace.

---

## Notes

- **Read-only.** The workbook only queries Advanced Hunting; it changes nothing.
- **No ingestion cost.** `Identity*` data is queried natively in Defender XDR — it is not
  ingested into the Log Analytics workspace.
- **Companion workbook.** Pairs with the Defender Vulnerability Management (MDVM) Advanced
  Hunting dashboard in this repo for a full XDR posture view.
