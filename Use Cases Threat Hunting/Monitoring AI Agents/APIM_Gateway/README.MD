# APIM AI Gateway AppRequests Detection Pack

Microsoft Sentinel analytics and hunts for Azure API Management AI gateway
telemetry in workspace-based Application Insights.

## Table mapping

- Application Insights resource scope: `requests` and `customDimensions`.
- Log Analytics / Sentinel workspace scope: `AppRequests` and `Properties`.

The YAML queries use `AppRequests`, because Sentinel analytics run against a Log
Analytics workspace. APIM rows are identified by `SDKVersion startswith "apim:"`
or `Properties["Service Type"] == "API Management"`.

## Scheduled analytics

| Rule | Severity | Signal |
| --- | --- | --- |
| `APIMContentSafetyBlockedRequest` | High | `403` response whose parsed message reports a content-safety check failure |
| `APIMPromptInjectionAllowed` | High | Injection/role-override marker in request input followed by a successful response |
| `APIMSensitiveDataInRequestBody` | High | Secret, credential, card-like, JWT, private key, or bulk-email indicator in a request body |
| `APIMCommandCapableToolDefinition` | High | Request exposes shell, command, code, SSH, terminal, or offensive tool definitions |
| `APIMSystemPromptDisclosure` | High | Prompt-disclosure request followed by instruction, guardrail, persona, or tool markers in a successful response |
| `APIMUnsafeActiveContentResponse` | Medium | Active HTML, script, event-handler, or executable URI marker returned successfully |
| `APIMAvailabilityPressure` | Medium | Concentrated throttling or server failures from one caller in five minutes |
| `APIMAbnormalRequestVolume` | Medium | Last-hour volume exceeds the agent/caller's seven-day median and p95 baseline |
| `APIMRepeatedUnauthorizedRequests` | Medium | At least 10 `401` or `403` responses from one agent/caller in five minutes |
| `APIMApiEnumeration` | Medium | At least 20 requests across 10 operations or routes, including successful enumeration |
| `APIMNewOperationFirstSeen` | Medium | Known agent/caller uses an operation absent from its prior 30-day history |
| `APIMNewCountryForKnownCaller` | Low | Known agent/caller appears from a new country with at least three requests |
| `APIMHighFailureRate` | Medium | At least 20 requests with a 50% failure rate by agent, API, and operation |

## Hunting queries

| Hunt | Purpose |
| --- | --- |
| `APIMRequestResponseBodyInvestigation` | Full input, instructions, tools, request body, response body, route, and correlation IDs |
| `APIMPayloadLoggingCoverage` | Quantify request/response body capture coverage |
| `APIMContentSafetyByModel` | Aggregate content-safety blocks by API, model, caller, and operation |
| `APIMModelToolInventory` | Inventory models, tool-choice settings, and tool definitions seen at the gateway |
| `APIMRequestVolumeBaseline` | Compare current agent/caller volume with seven-day hourly median and p95 |
| `APIMLatencyBaselineAnomaly` | Detect p95 request latency above the operation's historical distribution |
| `APIMUnusualOperationCombination` | Find broad operation sets containing new or state-changing actions |
| `APIMRequestDependencyCorrelation` | Reconstruct frontend request to downstream dependency flow using `OperationId` |
| `APIMRequestExceptionCorrelation` | Join failed frontend requests to exception telemetry using `OperationId` |

## Workbook parity

Workbook V2 has a dedicated APIM panel for each of the 13 scheduled analytics and
investigation panels for the hunting scenarios. All APIM query panels are generated
in both Log Analytics workspace and direct Application Insights modes.

## Agent identity enrichment

Behavioral rules use `AgentKey`, resolved in this order: custom `AgentId`, custom
`ApplicationId`, Application Insights role, APIM subscription, authenticated user,
user ID, then client IP. The current APIM workspace contains standard APIM dimensions
but no custom agent identity, so add stable application-defined properties where
technically and legally appropriate:

- `AgentId`, `AgentName`, `AgentType`, and `AgentVersion`
- `ApplicationId`, `TenantId`, and `Environment`
- `Model`, `ToolName`, and normalized API operation

Do not record secrets, authorization headers, raw tokens, or unnecessary personal
data. Stable workload identity is preferable to client IP for behavioral baselines.


## Sensitive evidence behavior

full payload visibility. These rules and hunts return
`Input`, `Instructions`, `Tools`, `RequestBody`, and `ResponseBody`. Scheduled rule
matches are copied into Sentinel alerts and incidents. Treat the workspace, alerts,
exports, screenshots, notebooks, and tickets as sensitive stores. Restrict access and
retention, and never capture authorization headers or API keys.

Body-driven rules are incomplete when APIM diagnostics do not populate
`Request-Body`/`Response-Body`. They also increase ingestion volume. Validate the
policy and diagnostics settings in a controlled environment.

## Deployment

```powershell
.\Deploy\New-APIMGatewayArmTemplate.ps1

az deployment group validate `
  --resource-group <sentinel-rg> `
  --template-file .\Deploy\azuredeploy.json `
  --parameters workspaceName=<workspace-with-AppRequests> enableAnalyticRules=false
```

Deploy only to the Sentinel workspace that receives the APIM Application Insights
`AppRequests` rows. The workbook can query a separate APIM workspace interactively,
but a scheduled Sentinel rule runs in its deployment workspace.
