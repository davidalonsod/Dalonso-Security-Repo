# Defender for Office 365 — Custom Detection Rules

Five high-value, low-noise use cases promoted to **Microsoft Defender XDR custom detection
rules**. Each `MDO-CD-*.json` is a payload for the Microsoft Graph Security API
(`detectionRules`, beta) and also documents every setting you would enter in the portal
wizard.

| File | Detection | Severity | Schedule | MITRE |
|------|-----------|----------|----------|-------|
| MDO-CD-01 | Safe Links click-through to malicious URL | High | 1h | T1566, T1204 |
| MDO-CD-02 | BEC display-name impersonation | Medium | 1h | T1566 |
| MDO-CD-03 | Compromised internal sender | High | 3h | T1534, T1566 |
| MDO-CD-04 | Suspicious inbox rule after phishing click | High | 3h | T1114, T1564 |
| MDO-CD-05 | Illicit OAuth app consent | High | 1h | T1528, T1566 |

## Custom-detection query rules

Unlike Sentinel analytic rules, Defender custom-detection queries:

- **Must return `Timestamp` and `ReportId`** columns (the engine uses them to dedupe and
  time-stamp alerts). All five queries do.
- **Should NOT hard-code the primary `ago()` time filter** — the rule's **frequency**
  defines the lookback window automatically. (MDO-CD-04 keeps an explicit `ago(3h)` only for
  its two-stage click→rule correlation; set that rule's frequency to *Every 3 hours*.)
- **Must expose an entity column** to map to an impacted asset (user / mailbox / device).

## Option A — Create in the Microsoft Defender portal (recommended)

1. **Advanced hunting** → paste the `queryText` from the JSON → **Run** to confirm it returns
   rows with `Timestamp` and `ReportId`.
2. Click **Create detection rule** and fill in:
   - **Alert title / severity / category / description / recommended actions** — from the
     `alertTemplate` in the JSON.
   - **Frequency** — from `schedule.period` (1h / 3h).
   - **Impacted entities** — map the account/mailbox column (e.g. `AccountUpn`,
     `RecipientEmailAddress`, `AccountObjectId`).
   - **MITRE techniques** — from `mitreTechniques`.
   - **Actions** (optional) — e.g. mark user as compromised, disable user, run AV scan.
3. **Create**. The rule runs on schedule and raises alerts/incidents in Defender XDR (and in
   Sentinel when connected).

## Option B — Deploy via Microsoft Graph (beta)

> The `detectionRules` API is in **beta**; validate the schema and the `impactedAssets`
> identifier enum against current docs before bulk deployment. App/delegated permission
> required: `CustomDetection.ReadWrite.All`.

```powershell
$token = "<Graph access token>"
Get-ChildItem .\*.json | ForEach-Object {
    Invoke-RestMethod `
        -Method POST `
        -Uri "https://graph.microsoft.com/beta/security/rules/detectionRules" `
        -Headers @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" } `
        -Body (Get-Content $_.FullName -Raw)
}
```

## Customisation before enabling

- **MDO-CD-02** — set the `Execs` and `CorpDomains` lists in the query.
- Maintain exclusions for phishing-simulation tooling, reporting mailboxes and trusted bulk
  senders to keep these low-noise.
- Consider attaching **response actions** (disable user, revoke sessions) to CD-03 / CD-04
  once you trust the fidelity in your tenant.
