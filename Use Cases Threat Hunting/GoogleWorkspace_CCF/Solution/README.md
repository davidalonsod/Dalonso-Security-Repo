# Google Workspace Alert Center — Sentinel Content Hub Solution

> ⚠️ **The CCF (Codeless) data connector in this solution does not work** and
> is kept here only for the analytic rules / hunting queries / table schema.
> `alertcenter.googleapis.com` requires service-account + domain-wide
> delegation; user-OAuth (the only flow CCF supports) returns
> `400 invalid_scope` for `apps.alerts`. Use the **Function App connector**
> in [`../FunctionApp/`](../FunctionApp/README.md) instead — it ingests into
> the same `GWSAlerts_CL` table so all rules/hunts in this solution remain
> usable unchanged.

A Microsoft Sentinel solution that ingests **Google Workspace Alert Center** alerts, plus 10 scheduled analytic rules and 10 hunting queries mapped to MITRE ATT&CK.

## What's deployed

| Component | Count | Notes |
|---|---|---|
| Custom Log Analytics table | 1 | `GWSAlerts_CL` (22 columns) |
| Data Collection Rule (DCR) | 1 | `Direct` kind, stream `Custom-GWSAlerts_CL`, flattens `metadata` and surfaces `AlertDataType` discriminator |
| Scheduled analytic rules | 10 | High/Medium severity, MITRE-mapped, incident-creating |
| Hunting queries | 10 | Saved searches under **Hunting → Queries** in Sentinel |
| Content package metadata | 1 | Surfaces the solution in **Content Hub** as installed |

> **Ingestion is not part of this template.** Deploy the Function App in
> [`../FunctionApp/`](../FunctionApp/README.md) to actually populate
> `GWSAlerts_CL`. The Function App reuses the DCE/DCR created by this
> solution (or its own — both schemas match).

See [`../AnalyticRules/README.md`](../AnalyticRules/README.md) for the full rule/hunt index with MITRE mapping.

## Deploy

### Option A — Azure Portal (one-click)

```
https://portal.azure.com/#create/Microsoft.Template/uri/<RAW URL OF mainTemplate.json>
```

Replace `<RAW URL ...>` with the raw URL of `Solution/Package/mainTemplate.json` once published to your repo.

### Option B — Azure CLI

```bash
az deployment group create \
  --resource-group <rg> \
  --template-file Solution/Package/mainTemplate.json \
  --parameters \
      workspace=<sentinel-workspace-name> \
      workspace-location=<region>
```

No connector credentials are required — this template only provisions the
table, DCR and rules/hunts. Ingestion is wired up by the separate Function
App deploy.

### Option C — azd / Bicep wrapper

Wrap the JSON in a Bicep module:

```bicep
module gwsSolution 'Solution/Package/mainTemplate.json' = {
  name: 'gws-alertcenter-solution'
  params: {
    workspace: workspaceName
    'workspace-location': location
  }
}
```

## Post-deploy steps

1. **Sentinel → Content Hub** — confirm "Google Workspace Alert Center" is listed as **Installed**.
2. **Deploy the Function App** — follow [`../FunctionApp/README.md`](../FunctionApp/README.md) to deploy the poller (Storage + Function + KV + DCE/DCR + RBAC) and publish the Python code.
3. **Sentinel → Analytics → Active rules** — verify 10 GWS rules are enabled (filter on `GWS - `).
4. **Sentinel → Hunting → Queries** — verify 10 GWS queries exist (filter on `GWS Alerts -`).
5. Wait 5–15 minutes after the Function App's first run, then:
   ```kql
   GWSAlerts_CL | where TimeGenerated > ago(1h) | summarize count() by AlertType
   ```

## Solution metadata

| Field | Value |
|---|---|
| Solution ID | `azuresentinel.azure-sentinel-solution-googleworkspacealertcenter` |
| Display name | Google Workspace Alert Center |
| Version | 1.0.0 |
| Publisher | Community custom connector |
| Tier | Community |
| Content schema version | 3.0.0 |
