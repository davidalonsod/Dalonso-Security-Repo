> ⚠ **NOT VALIDATED AGAINST TENANT DATA.** This report is a template/example rendering.
> Every row's confidence percentage and source table below was authored by hand or transcribed from a narrative --
> none of it was queried live from `CloudAppEvents`, `AppDependencies`, `BehaviorInfo`, or any other tenant table by this script.
> Confirm every row against your own tenant before treating this incident as real or acting on it.

# Suspicious agent-driven SharePoint modification

**Risk:** High

**Agent:** `Finance-Reconciliation-Agent`

**Agent ID:** `a365-fin-0231`

**Agent Identity:** `FinanceAgent-prod@contoso`

**Initiating user:** `user@contoso.com`

**Conversation:** `conv-8f72...`

**Investigation confidence:** **87%**

## What happened

```text
David

  │

  │ Asked agent to reconcile Q3 financial documents
  │ Evidence: EXACT

  ▼

Finance-Reconciliation-Agent

  │

  │ invoke_agent
  │ Evidence: EXACT — 100%

  ▼

MCP: SharePoint Enterprise

  │

  │ ExecuteTool: search
  │ Evidence: EXACT — 100%
  │
  ├── /sites/Finance/Q3
  ├── /sites/Finance/M&A
  └── /sites/Board
        │
        │ unusual resource for this agent
        ▼

MCP: SharePoint Enterprise

  │

  │ ExecuteTool: update-file
  │ Evidence: EXACT

  ▼

Microsoft Graph

  │

  │ PATCH /enterprise/...
  │ Evidence: CORRELATED — 92%

  ▼

Board-Forecast-Q3.xlsx
```

## Evidence table

| Time | Entity | Action | Evidence | Confidence |
| --- | --- | --- | --- | --- |
| 10:31:02 | User | Invoked Finance Agent | Agent 365 span | 100% |
| 10:31:03 | Agent | Started conversation | ConversationId | 100% |
| 10:31:05 | Agent | Called SharePoint MCP | Parent/child span | 100% |
| 10:31:06 | MCP | Search /Finance/Q3 | Tool span | 100% |
| 10:31:09 | MCP | Search /Board | Tool span | 100% |
| 10:31:12 | Graph | PATCH request | Identity + time correlation | 92% |
| 10:31:13 | SharePoint | File modified | Audit evidence | 96% |

## Why this is suspicious

**3 anomalies detected**

1. **New resource family**

   - Baseline: No prior access to /sites/Board in the agent's activity history
   - Current: Search executed against /sites/Board in this conversation

2. **Privilege expansion**

   - Baseline: READ
   - Current: WRITE

3. **Sensitive resource**

   - Current: Target classified as Highly Confidential

## Blast radius

```text
1 Agent
   │
   ├── 1 Agent Identity
   │
   ├── 3 SharePoint sites
   │
   ├── 17 Files read
   │
   └── 1 Sensitive file modified
```

## Analyst recommendation

**Priority: HIGH**

Investigate:

- why the agent accessed the Board site;
- whether the WRITE permission is expected;
- whether the MCP tool invocation was authorized;
- whether similar Graph operations occurred in other conversations;

## Evidence-to-telemetry map

| Time | Evidence | Source table |
| --- | --- | --- |
| 10:31:02 | Agent 365 span | AppDependencies (InvokeAgent span) or UnifiedAgentObservability |
| 10:31:03 | ConversationId | AppDependencies customDimensions.gen_ai.conversation.id |
| 10:31:05 | Parent/child span | AppDependencies operation_Id/operation_ParentId |
| 10:31:06 | Tool span | AppDependencies ExecuteTool span |
| 10:31:09 | Tool span | AppDependencies ExecuteTool span |
| 10:31:12 | Identity + time correlation | CloudAppEvents (Application=Microsoft Graph, joined by AccountObjectId + time window) |
| 10:31:13 | Audit evidence | CloudAppEvents / Office 365 audit log (file update record) |
