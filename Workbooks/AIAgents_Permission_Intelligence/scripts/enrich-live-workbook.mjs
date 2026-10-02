import fs from "node:fs";

const workbookPath = new URL("../workbook/agent-effective-access-workbook.json", import.meta.url);
const workbook = JSON.parse(fs.readFileSync(workbookPath, "utf8"));
const liveVisibility = {
  parameterName: "ContentMode",
  comparison: "isEqualTo",
  value: "live",
};

const group = (name) => workbook.items.find((item) => item.name === name);
const item = (groupName, name) =>
  group(groupName).content.items.find((candidate) => candidate.name === name);
const clone = (value) => JSON.parse(JSON.stringify(value));

function insertAfter(groupName, afterName, newItem) {
  const items = group(groupName).content.items;
  const existing = items.findIndex((candidate) => candidate.name === newItem.name);
  if (existing >= 0) {
    items.splice(existing, 1);
  }
  const after = items.findIndex((candidate) => candidate.name === afterName);
  items.splice(after + 1, 0, newItem);
}

function insertTopLevelAfter(afterName, newItem) {
  const items = workbook.items;
  const existing = items.findIndex((candidate) => candidate.name === newItem.name);
  if (existing >= 0) {
    items.splice(existing, 1);
  }
  const after = items.findIndex((candidate) => candidate.name === afterName);
  items.splice(after + 1, 0, newItem);
}

function setFormatters(groupName, name, formatters) {
  const target = item(groupName, name);
  if (!target) {
    return;
  }
  target.content.gridSettings = {
    ...(target.content.gridSettings ?? { filter: true, rowLimit: 1000 }),
    formatters,
  };
}

function setDescription(groupName, name, markdown, style = "info") {
  const target = item(groupName, name);
  if (!target) {
    return;
  }
  target.content.json = markdown;
  target.content.style = style;
}

function analyticsItem(templateName, name, title, query, visualization, settingsTemplateName) {
  const template =
    item("group-executive", templateName) ??
    item("group-sensitive-exposure", templateName) ??
    item("group-evidence", templateName);
  const result = clone(template);
  result.name = name;
  result.conditionalVisibility = clone(liveVisibility);
  result.content.query = query;
  result.content.title = title;
  result.content.queryType = 0;
  result.content.visualization = visualization;
  if (settingsTemplateName) {
    const settingsSource =
      item("group-executive", settingsTemplateName) ??
      item("group-sensitive-exposure", settingsTemplateName) ??
      item("group-evidence", settingsTemplateName) ??
      item("group-change-impact", settingsTemplateName);
    for (const property of ["tileSettings", "gridSettings", "graphSettings"]) {
      if (settingsSource?.content[property]) {
        result.content[property] = clone(settingsSource.content[property]);
      } else {
        delete result.content[property];
      }
    }
  }
  return result;
}

function dataLakeItem(name, title, kql, visualization, settingsTemplateName) {
  const result = clone(item("group-observed", "observed-live-datalake"));
  result.name = name;
  result.conditionalVisibility = clone(liveVisibility);
  result.content.query = JSON.stringify({
    workspaces: [{ id: "default", name: "default", apiName: "default" }],
    query: kql,
  });
  result.content.title = title;
  result.content.queryType = "sentinelDataLake";
  result.content.visualization = visualization;
  if (settingsTemplateName) {
    const settingsSource =
      item("group-executive", settingsTemplateName) ??
      item("group-evidence", settingsTemplateName) ??
      item("group-change-impact", settingsTemplateName);
    for (const property of ["tileSettings", "gridSettings", "graphSettings"]) {
      if (settingsSource?.content[property]) {
        result.content[property] = clone(settingsSource.content[property]);
      } else {
        delete result.content[property];
      }
    }
  }
  return result;
}

const edgePrelude = String.raw`let EdgeSource = union isfuzzy=true
(
    AgentPermissionEdges_CL
),
(
    datatable(
        TimeGenerated:datetime, EdgeId:string, EdgeClass:string, Relation:string,
        TenantId:string, SubjectId:string, SubjectType:string, TargetId:string,
        TargetType:string, PermissionId:string, PermissionValue:string,
        PermissionMode:string, AuthorizationMechanism:string, GrantOrigin:string,
        ConsentType:string, DeclarationState:string, GrantState:string,
        TokenState:string, ConfiguredEdgeId:string, ResourceScope:string,
        Operation:string, EventId:string, SourceSystem:string, SourceTable:string,
        SourceObjectId:string, EvidenceAuthority:string, Confidence:string,
        ObservedAt:datetime, RetrievedAt:datetime, ValidFrom:datetime,
        ValidTo:datetime, CollectorName:string, CollectorVersion:string,
        Details:dynamic
    )[]
);
let Edges = EdgeSource
| summarize arg_max(TimeGenerated, *) by EdgeId;
let AgentNames = Edges
| where SubjectType == "AgentIdentity"
| extend AgentName=tostring(Details.displayName)
| where isnotempty(AgentName)
| summarize arg_max(TimeGenerated, AgentName) by AgentId=SubjectId
| project AgentId, AgentName;
let BlueprintLinks = Edges
| where EdgeClass == "identityLifecycle" and Relation == "belongsTo" and SubjectType == "AgentIdentity"
| project AgentId=SubjectId, BlueprintId=TargetId;
let BlueprintNames = Edges
| where SubjectType == "AgentIdentityBlueprint"
| extend BlueprintName=tostring(Details.displayName)
| where isnotempty(BlueprintName)
| summarize arg_max(TimeGenerated, BlueprintName) by BlueprintId=SubjectId
| project BlueprintId, BlueprintName;`;

const reachPrelude = String.raw`${edgePrelude}
let ExistingReach = Edges
| where EdgeClass in ("reachableDeterministic", "reachableBounded", "reachableInferred")
| project SubjectId, PermissionValue, TargetId, TargetType, ResourceScope, EdgeClass,
          ConfiguredEdgeId, EvidenceAuthority, Confidence, SourceSystem, SourceObjectId,
          RetrievedAt, Details;
let ExistingConfiguredIds = ExistingReach
| where isnotempty(ConfiguredEdgeId)
| project ExistingConfiguredEdgeId=ConfiguredEdgeId;
let DerivedReach = Edges
| where EdgeClass == "configured" and SubjectType == "AgentIdentity" and isnotempty(PermissionValue)
| join kind=leftanti ExistingConfiguredIds on $left.EdgeId == $right.ExistingConfiguredEdgeId
| extend LowerPermission=tolower(PermissionValue)
| extend ResourceCategory=case(
    LowerPermission startswith "sites.", "SharePoint sites",
    LowerPermission startswith "files.", "SharePoint and OneDrive files",
    LowerPermission startswith "mail." or LowerPermission startswith "mailboxsettings.", "Exchange Online mailboxes",
    LowerPermission startswith "auditlog.", "Microsoft Entra audit logs",
    LowerPermission startswith "reports.", "Microsoft 365 reports",
    LowerPermission startswith "application.", "Microsoft Entra applications and service principals",
    LowerPermission startswith "rolemanagement.", "Microsoft Entra role management",
    LowerPermission startswith "user." or LowerPermission startswith "group." or LowerPermission startswith "directory.", "Microsoft Entra directory",
    AuthorizationMechanism == "azureRbac" and isnotempty(ResourceScope), ResourceScope,
    "Microsoft Graph resources")
| extend DerivedClass=case(
    AuthorizationMechanism == "azureRbac" and isnotempty(ResourceScope), "reachableDeterministic",
    AuthorizationMechanism == "directoryRole", "reachableBounded",
    "reachableInferred")
| extend AccessLevel=iff(LowerPermission has_any ("write", "manage", "fullcontrol", "send", "contributor", "owner"), "readWrite", "read")
| extend DerivedDetails=bag_pack(
    "ResourceCategory", ResourceCategory,
    "ResourceClassification", "Unknown",
    "AccessLevel", AccessLevel,
    "ExactResourceEvidence", DerivedClass == "reachableDeterministic",
    "DerivationReason", iff(DerivedClass == "reachableDeterministic", "Explicit Azure RBAC resource scope.", "Permission mapped to a resource category; exact resource authorization was not collected."))
| project SubjectId, PermissionValue,
          TargetId=iff(DerivedClass == "reachableDeterministic", ResourceScope, strcat("resource-category:", replace_string(tolower(ResourceCategory), " ", "-"))),
          TargetType=iff(DerivedClass == "reachableDeterministic", "AzureResourceScope", "ResourceCategory"),
          ResourceScope=ResourceCategory, EdgeClass=DerivedClass, ConfiguredEdgeId=EdgeId,
          EvidenceAuthority=case(DerivedClass == "reachableDeterministic", "deterministicDerived", DerivedClass == "reachableBounded", "boundedDerived", "inferred"),
          Confidence=case(DerivedClass == "reachableDeterministic", "confirmed", DerivedClass == "reachableBounded", "medium", "low"),
          SourceSystem="WorkbookPermissionMapping", SourceObjectId=EdgeId, RetrievedAt, Details=DerivedDetails;
let ReachEdges = union ExistingReach, DerivedReach;`;

const executivePostureQuery = String.raw`${reachPrelude}
let Filtered = Edges
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}";
let AgentCount = toscalar(Filtered | where EdgeClass == "identityLifecycle" and SubjectType == "AgentIdentity" | summarize dcount(SubjectId));
let ConfiguredCount = toscalar(Filtered | where EdgeClass == "configured" and SubjectType == "AgentIdentity" | summarize dcount(strcat(SubjectId, "|", PermissionValue)));
let DirectCount = toscalar(Filtered | where EdgeClass == "configured" and SubjectType == "AgentIdentity" and GrantOrigin == "direct" | summarize count());
let WriteCount = toscalar(Filtered | where EdgeClass == "configured" and SubjectType == "AgentIdentity" and PermissionValue matches regex "(?i)(write|manage|fullcontrol|send|owner|contributor)" | summarize dcount(strcat(SubjectId, "|", PermissionValue)));
let ObservedCount = toscalar(Filtered | where EdgeClass == "observed" and isnotempty(ConfiguredEdgeId) | summarize dcount(ConfiguredEdgeId));
let ReachCount = toscalar(ReachEdges
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| summarize dcount(strcat(SubjectId, "|", TargetId, "|", PermissionValue)));
let ControlCount = toscalar(Filtered | where EdgeClass == "control" | summarize count());
union
(print Metric="Agent identities", Value=AgentCount, Explanation="Agent Identity objects represented by canonical lifecycle evidence"),
(print Metric="Configured permissions", Value=ConfiguredCount, Explanation="Distinct agent-permission paths from authoritative configuration"),
(print Metric="Direct grant paths", Value=DirectCount, Explanation="Configured paths whose provenance is direct"),
(print Metric="Write-capable permissions", Value=WriteCount, Explanation="Permission names with write, manage, send, owner, or contributor semantics"),
(print Metric="Observed matched paths", Value=ObservedCount, Explanation="Configured edge IDs matched by canonical observed evidence"),
(print Metric="Reachability paths", Value=ReachCount, Explanation="Deterministic, bounded, or explicitly inferred reachability edges"),
(print Metric="Control edges", Value=ControlCount, Explanation="Disablement, credential, policy, or other control evidence")`;

const executivePosture = item("group-executive", "executive-live-permission-posture");
executivePosture.content.query = executivePostureQuery;
executivePosture.content.title = "Live permission intelligence posture";
executivePosture.content.tileSettings = clone(item("group-executive", "executive-attention-kpis").content.tileSettings);

setDescription(
  "group-executive",
  "executive-live-permission-posture-description",
  "## Live Permission Intelligence posture\n\nA multi-metric tenant posture from the latest canonical edge snapshot. The tiles separate identity population, configured permissions, direct grants, write-capable scopes, observed matches, reachable paths, and controls. **Zero observed or reachable paths means the corresponding evidence is not present; it does not mean zero real-world use or reach.**",
  "upsell",
);

const perAgentPostureQuery = String.raw`${reachPrelude}
let Configured = Edges
| where EdgeClass == "configured" and SubjectType == "AgentIdentity"
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| summarize ConfiguredPermissions=dcount(PermissionValue),
            PermissionList=make_set(PermissionValue, 100),
            DirectGrantPaths=countif(GrantOrigin == "direct"),
            BlueprintGrantPaths=countif(GrantOrigin == "blueprintInherited"),
            WriteCapablePermissions=dcountif(PermissionValue, PermissionValue matches regex "(?i)(write|manage|fullcontrol|send|owner|contributor)"),
            LatestConfigured=max(TimeGenerated)
  by AgentId=SubjectId;
let Observed = Edges
| where EdgeClass == "observed" and isnotempty(ConfiguredEdgeId)
| summarize ObservedConfiguredPaths=dcount(ConfiguredEdgeId), LastObserved=max(ObservedAt) by AgentId=SubjectId;
let Reach = ReachEdges
| summarize DeterministicReach=dcountif(TargetId, EdgeClass == "reachableDeterministic"),
            BoundedReach=dcountif(TargetId, EdgeClass == "reachableBounded"),
            InferredReach=dcountif(TargetId, EdgeClass == "reachableInferred")
  by AgentId=SubjectId;
let Controls = Edges
| where EdgeClass == "control"
| summarize Controls=count(), DisabledControls=countif(TargetId == "control:identity-disabled") by AgentId=SubjectId;
Configured
| join kind=leftouter Observed on AgentId
| join kind=leftouter Reach on AgentId
| join kind=leftouter Controls on AgentId
| join kind=leftouter AgentNames on AgentId
| join kind=leftouter BlueprintLinks on AgentId
| join kind=leftouter BlueprintNames on BlueprintId
| extend AgentName=coalesce(AgentName, AgentId),
         BlueprintName=coalesce(BlueprintName, "Unknown"),
         ObservedConfiguredPaths=coalesce(ObservedConfiguredPaths, long(0)),
         UnobservedPermissions=ConfiguredPermissions-coalesce(ObservedConfiguredPaths, long(0)),
         UtilizationPercent=iff(ConfiguredPermissions == 0, real(null), round(100.0 * todouble(ObservedConfiguredPaths) / todouble(ConfiguredPermissions), 0)),
         Attention=case(WriteCapablePermissions > 0 and DirectGrantPaths > 0, "High - direct write-capable access", DirectGrantPaths > 0, "Review - direct grant", DisabledControls > 0 and ConfiguredPermissions > 0, "Review - disabled identity retains grants", "Baseline")
| project AgentName, AgentObjectId=AgentId, BlueprintName, ConfiguredPermissions, ObservedConfiguredPaths,
          UnobservedPermissions, UtilizationPercent, DirectGrantPaths, BlueprintGrantPaths,
          WriteCapablePermissions, DeterministicReach=coalesce(DeterministicReach, long(0)),
          BoundedReach=coalesce(BoundedReach, long(0)), InferredReach=coalesce(InferredReach, long(0)),
          Controls=coalesce(Controls, long(0)), PermissionList, Attention, LatestEvidence=max_of(LatestConfigured, LastObserved)
| order by WriteCapablePermissions desc, DirectGrantPaths desc, AgentName asc`;

insertAfter(
  "group-executive",
  "executive-live-permission-posture",
  analyticsItem("privilege-exposure-matrix", "executive-live-agent-posture", "Live per-agent permission posture", perAgentPostureQuery, "table", "privilege-exposure-matrix"),
);

const utilizationChartQuery = String.raw`${edgePrelude}
let Configured = Edges
| where EdgeClass == "configured" and SubjectType == "AgentIdentity"
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| summarize Configured=dcount(PermissionValue) by AgentId=SubjectId;
let Observed = Edges
| where EdgeClass == "observed" and isnotempty(ConfiguredEdgeId)
| summarize Observed=dcount(ConfiguredEdgeId) by AgentId=SubjectId;
Configured
| join kind=leftouter Observed on AgentId
| join kind=leftouter AgentNames on AgentId
| extend AgentName=coalesce(AgentName, AgentId), Observed=coalesce(Observed, long(0)), Unobserved=Configured-coalesce(Observed, long(0))
| project AgentName, Observed, Unobserved
| order by Unobserved desc, AgentName asc`;
insertAfter(
  "group-executive",
  "executive-live-agent-posture",
  analyticsItem("agent-posture", "executive-live-utilization-chart", "Configured versus observed permission paths by agent", utilizationChartQuery, "barchart", "agent-posture"),
);

const concentrationQuery = String.raw`${edgePrelude}
Edges
| where EdgeClass == "configured" and SubjectType == "AgentIdentity" and isnotempty(PermissionValue)
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| summarize Agents=dcount(SubjectId), GrantPaths=count(), DirectGrantPaths=countif(GrantOrigin == "direct") by Permission=PermissionValue
| order by Agents desc, GrantPaths desc, Permission asc`;
insertAfter(
  "group-executive",
  "executive-live-utilization-chart",
  analyticsItem("agent-posture", "executive-live-concentration-chart", "Live permission concentration", concentrationQuery, "barchart", "agent-posture"),
);

const identityStatusKql = String.raw`let Blueprints =
    EntraAgentIdentityBlueprints
    | summarize arg_max(_SnapshotTime, *) by id
    | project BlueprintAppId=appId, BlueprintName=displayName;
EntraAgentIdentities
| summarize arg_max(_SnapshotTime, *) by id
| extend AgentStatus=iff(accountEnabled, "Active", "Disabled")
| join kind=leftouter Blueprints on $left.agentAppId == $right.BlueprintAppId
| where "{AgentFilter}" == "*" or id == "{AgentFilter}"
| where "{BlueprintFilter}" == "*" or agentAppId == "{BlueprintFilter}"
| where "{IdentityStateFilter}" == "*" or tolower(AgentStatus) == "{IdentityStateFilter}"
| summarize Agents=dcount(id) by Blueprint=coalesce(BlueprintName, "Unmatched blueprint"), AgentStatus
| order by Agents desc`;
insertAfter(
  "group-identity",
  "identity-live-datalake",
  dataLakeItem("identity-live-status-chart", "Live Agent Identity population by blueprint and state", identityStatusKql, "barchart", "agent-posture"),
);

const configuredLive = item("group-configured", "configured-live-edges");
configuredLive.content.query = String.raw`${edgePrelude}
Edges
| where EdgeClass == "configured"
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| join kind=leftouter AgentNames on $left.SubjectId == $right.AgentId
| join kind=leftouter BlueprintLinks on $left.SubjectId == $right.AgentId
| join kind=leftouter BlueprintNames on BlueprintId
| extend AgentName=coalesce(AgentName, iff(SubjectType == "AgentIdentityBlueprint", tostring(Details.displayName), SubjectId)),
         BlueprintName=coalesce(BlueprintName, iff(SubjectType == "AgentIdentityBlueprint", tostring(Details.displayName), "Unknown"))
| project TimeGenerated, AgentName, SubjectId, SubjectType, BlueprintName, PermissionValue, PermissionMode,
          AuthorizationMechanism, GrantOrigin, ConsentType, DeclarationState, GrantState, TargetId,
          ResourceScope, SourceSystem, SourceTable, EvidenceAuthority, Confidence, RetrievedAt, ValidFrom, ValidTo
| order by AgentName asc, PermissionValue asc`;
configuredLive.content.title = "Live configured permission evidence";

insertAfter(
  "group-configured",
  "configured-live-edges",
  analyticsItem("agent-posture", "configured-live-permission-chart", "Configured permissions by affected Agent ID", concentrationQuery, "barchart", "agent-posture"),
);
const provenanceChartQuery = String.raw`${edgePrelude}
Edges
| where EdgeClass == "configured" and SubjectType == "AgentIdentity"
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| summarize GrantPaths=count(), Agents=dcount(SubjectId) by GrantOrigin
| order by GrantPaths desc`;
insertAfter(
  "group-configured",
  "configured-live-permission-chart",
  analyticsItem("confidence-chart", "configured-live-provenance-chart", "Configured grant provenance", provenanceChartQuery, "piechart", "confidence-chart"),
);

const observedOperationsKql = String.raw`UnifiedAgentObservability
| where TimeGenerated between (datetime({TimeRange:startISO}) .. datetime({TimeRange:endISO}))
| extend AgentIdentityId=coalesce(TargetAgentId, SrcAgentId, PlatformTargetAgentId),
         AgentBlueprintId=coalesce(TargetAgentBlueprintId, SrcAgentBlueprintId),
         Operation=coalesce(EventOriginalType, EventType)
| extend ExecutionContext=case(isnotempty(ActorUserId) or isnotempty(ActorUsername), "delegatedObo", isnotempty(ActingAppId), "application", isnotempty(SrcAgentId), "agentToAgent", "unknown")
| where "{AgentFilter}" == "*" or AgentIdentityId == "{AgentFilter}" or SrcAgentId == "{AgentFilter}" or TargetAgentId == "{AgentFilter}"
| where "{BlueprintFilter}" == "*" or AgentBlueprintId == "{BlueprintFilter}"
| where "{ExecutionContextFilter}" == "*" or ExecutionContext == "{ExecutionContextFilter}"
| where "{ActivityTypeFilter}" == "*" or Operation == "{ActivityTypeFilter}"
| where "{ToolFilter}" == "*" or ToolName == "{ToolFilter}"
| summarize Events=count(), Agents=dcount(AgentIdentityId), Errors=countif(isnotempty(EventErrorDetails) or isnotempty(EventOriginalErrorType)) by Operation
| order by Events desc`;
insertAfter(
  "group-observed",
  "observed-live-datalake",
  dataLakeItem("observed-live-operation-chart", "Live activity by operation", observedOperationsKql, "barchart", "agent-posture"),
);
const observedTimelineKql = String.raw`UnifiedAgentObservability
| where TimeGenerated between (datetime({TimeRange:startISO}) .. datetime({TimeRange:endISO}))
| extend AgentIdentityId=coalesce(TargetAgentId, SrcAgentId, PlatformTargetAgentId),
         AgentBlueprintId=coalesce(TargetAgentBlueprintId, SrcAgentBlueprintId),
         Operation=coalesce(EventOriginalType, EventType)
| extend ExecutionContext=case(isnotempty(ActorUserId) or isnotempty(ActorUsername), "delegatedObo", isnotempty(ActingAppId), "application", isnotempty(SrcAgentId), "agentToAgent", "unknown")
| where "{AgentFilter}" == "*" or AgentIdentityId == "{AgentFilter}" or SrcAgentId == "{AgentFilter}" or TargetAgentId == "{AgentFilter}"
| where "{BlueprintFilter}" == "*" or AgentBlueprintId == "{BlueprintFilter}"
| where "{ExecutionContextFilter}" == "*" or ExecutionContext == "{ExecutionContextFilter}"
| where "{ActivityTypeFilter}" == "*" or Operation == "{ActivityTypeFilter}"
| where "{ToolFilter}" == "*" or ToolName == "{ToolFilter}"
| summarize Events=count() by bin(TimeGenerated, 1d), Operation
| order by TimeGenerated asc`;
insertAfter(
  "group-observed",
  "observed-live-operation-chart",
  dataLakeItem("observed-live-timeline", "Live Agent 365 activity timeline", observedTimelineKql, "timechart", "timeline-chart"),
);

const reachableLive = item("group-effective-access", "reachable-live-edges");
reachableLive.content.query = String.raw`${reachPrelude}
ReachEdges
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| join kind=leftouter AgentNames on $left.SubjectId == $right.AgentId
| extend AgentName=coalesce(AgentName, SubjectId),
         ReachabilityClass=case(EdgeClass == "reachableDeterministic", "Deterministic", EdgeClass == "reachableBounded", "Bounded", "Inferred"),
         Classification=coalesce(tostring(Details.ResourceClassification), "Unknown"),
         AccessLevel=coalesce(tostring(Details.AccessLevel), "Unknown"),
         Reason=coalesce(tostring(Details.DerivationReason), "Canonical reachability edge")
| project AgentName, AgentObjectId=SubjectId, PermissionValue, Resource=ResourceScope, TargetId, TargetType,
          Classification, AccessLevel, ReachabilityClass, Reason, ConfiguredEdgeId,
          EvidenceAuthority, Confidence, SourceSystem, RetrievedAt
| order by ReachabilityClass asc, AgentName asc, Resource asc`;
reachableLive.content.title = "Live effective and reachable access";
const reachChartQuery = String.raw`${reachPrelude}
ReachEdges
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| extend ReachabilityClass=case(EdgeClass == "reachableDeterministic", "Deterministic", EdgeClass == "reachableBounded", "Bounded", "Inferred")
| summarize Paths=dcount(strcat(SubjectId, "|", TargetId, "|", PermissionValue)) by ReachabilityClass`;
insertAfter(
  "group-effective-access",
  "reachable-live-edges",
  analyticsItem("confidence-chart", "reachable-live-class-chart", "Live reachability evidence mix", reachChartQuery, "piechart", "confidence-chart"),
);
const resourceReachChartQuery = String.raw`${reachPrelude}
ReachEdges
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| summarize Agents=dcount(SubjectId), Paths=dcount(strcat(SubjectId, "|", PermissionValue)) by Resource=ResourceScope
| order by Agents desc, Paths desc`;
insertAfter(
  "group-effective-access",
  "reachable-live-class-chart",
  analyticsItem("agent-posture", "reachable-live-resource-chart", "Agents by reachable resource category", resourceReachChartQuery, "barchart", "agent-posture"),
);

const driftQuery = String.raw`${edgePrelude}
let Declarations = Edges
| where EdgeClass == "configured" and Relation == "declares" and SubjectType == "AgentIdentityBlueprint"
| project BlueprintId=SubjectId, PermissionValue, BaselineEdgeId=EdgeId, BaselineTargetId=TargetId;
let Grants = Edges
| where EdgeClass == "configured" and SubjectType == "AgentIdentity" and Relation !in ("declares", "eligibleToInherit")
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| project AgentId=SubjectId, PermissionValue, GrantEdgeId=EdgeId, GrantOrigin, AuthorizationMechanism, PermissionMode, TargetId, RetrievedAt;
Grants
| join kind=leftouter BlueprintLinks on AgentId
| join kind=leftouter Declarations on BlueprintId, PermissionValue
| join kind=leftouter AgentNames on AgentId
| join kind=leftouter BlueprintNames on BlueprintId
| extend AgentName=coalesce(AgentName, AgentId), BlueprintName=coalesce(BlueprintName, "Unknown"),
         DriftClass=case(isempty(BlueprintId), "Unknown - no blueprint mapping", isnotempty(BaselineEdgeId), "Baseline match", "Direct exception"),
         Finding=case(isempty(BlueprintId), "Grant cannot be compared because the Agent ID has no collected blueprint link", isnotempty(BaselineEdgeId), "Configured grant matches a declared blueprint permission", "Configured Agent ID permission is not declared by its blueprint")
| project AgentName, AgentObjectId=AgentId, BlueprintName, BlueprintObjectId=BlueprintId, PermissionValue,
          PermissionMode, AuthorizationMechanism, GrantOrigin, DriftClass, Finding, GrantEdgeId, BaselineEdgeId, RetrievedAt
| order by DriftClass desc, AgentName asc, PermissionValue asc`;
const driftLive = item("group-drift", "drift-live-edges");
driftLive.content.query = driftQuery;
driftLive.content.title = "Live blueprint baseline comparison";
const driftChartQuery = `${driftQuery}\n| summarize Findings=count(), Agents=dcount(AgentObjectId) by DriftClass`;
insertAfter(
  "group-drift",
  "drift-live-edges",
  analyticsItem("confidence-chart", "drift-live-chart", "Live blueprint drift classification", driftChartQuery, "piechart", "confidence-chart"),
);

const exposureLive = item("group-sensitive-exposure", "exposure-live-edges");
const exposureQuery = String.raw`${reachPrelude}
ReachEdges
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| join kind=leftouter AgentNames on $left.SubjectId == $right.AgentId
| extend AgentName=coalesce(AgentName, SubjectId),
         Classification=coalesce(tostring(Details.ResourceClassification), "Unknown"),
         AccessLevel=coalesce(tostring(Details.AccessLevel), "Unknown"),
         ReachabilityClass=case(EdgeClass == "reachableDeterministic", "Deterministic", EdgeClass == "reachableBounded", "Bounded", "Inferred")
| extend ExposureState=iff(Classification in ("Confidential", "Highly Confidential"), "Classified sensitive exposure", "Potential exposure - classification unknown"),
         Priority=case(Classification == "Highly Confidential" and AccessLevel == "readWrite", "Critical", Classification in ("Confidential", "Highly Confidential"), "High", AccessLevel == "readWrite", "Medium", "Review")
| project AgentName, AgentObjectId=SubjectId, PermissionValue, Resource=ResourceScope, Classification,
          AccessLevel, ReachabilityClass, ExposureState, Priority, Confidence, EvidenceAuthority,
          EvidenceGap=iff(Classification == "Unknown", "Connect Purview or a governed resource-classification inventory", ""),
          RetrievedAt
| order by Priority asc, AgentName asc, Resource asc`;
exposureLive.content.query = exposureQuery;
exposureLive.content.title = "Live classified and potential exposure candidates";
const exposureChartQuery = String.raw`${reachPrelude}
ReachEdges
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| extend AccessLevel=coalesce(tostring(Details.AccessLevel), "Unknown")
| summarize Agents=dcount(SubjectId), PermissionPaths=dcount(strcat(SubjectId, "|", PermissionValue)) by Resource=ResourceScope, AccessLevel
| order by Agents desc`;
insertAfter(
  "group-sensitive-exposure",
  "exposure-live-edges",
  analyticsItem("agent-posture", "exposure-live-resource-chart", "Live exposure candidates by resource category", exposureChartQuery, "barchart", "agent-posture"),
);
const exposureAccessQuery = String.raw`${reachPrelude}
ReachEdges
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| extend AccessLevel=coalesce(tostring(Details.AccessLevel), "Unknown")
| summarize Paths=dcount(strcat(SubjectId, "|", TargetId, "|", PermissionValue)) by AccessLevel`;
insertAfter(
  "group-sensitive-exposure",
  "exposure-live-resource-chart",
  analyticsItem("confidence-chart", "exposure-live-access-chart", "Live potential access level", exposureAccessQuery, "piechart", "confidence-chart"),
);

const accessPathLive = item("group-access-path", "access-path-live-edges");
accessPathLive.content.query = String.raw`${reachPrelude}
let GraphEdges = union Edges, DerivedReach;
GraphEdges
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| join kind=leftouter AgentNames on $left.SubjectId == $right.AgentId
| join kind=leftouter BlueprintNames on $left.TargetId == $right.BlueprintId
| extend AgentName=coalesce(AgentName, SubjectId),
         FromNode=coalesce(AgentName, SubjectId),
         ToNode=case(isnotempty(BlueprintName), BlueprintName, isnotempty(ResourceScope), ResourceScope, isnotempty(PermissionValue), PermissionValue, TargetId),
         PathStage=case(EdgeClass == "identityLifecycle", 1, EdgeClass == "configured", 2, EdgeClass == "observed", 3, EdgeClass startswith "reachable", 4, EdgeClass == "control", 5, 9)
| project AgentName, AgentObjectId=SubjectId, PathStage, FromNode, Relation, ToNode, EdgeClass,
          PermissionValue, GrantOrigin, ConfiguredEdgeId, EvidenceAuthority, Confidence,
          SourceSystem, SourceTable, SourceObjectId, RetrievedAt
| order by AgentName asc, PermissionValue asc, PathStage asc, RetrievedAt asc`;
accessPathLive.content.title = "Live explainable access edges";
const accessPathChartQuery = String.raw`${edgePrelude}
Edges
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| summarize Edges=count(), Agents=dcountif(SubjectId, SubjectType == "AgentIdentity") by EvidencePlane=EdgeClass
| order by Edges desc`;
insertAfter(
  "group-access-path",
  "access-path-live-edges",
  analyticsItem("agent-posture", "access-path-live-chart", "Live access graph edge composition", accessPathChartQuery, "barchart", "agent-posture"),
);

const changeImpactQuery = String.raw`${reachPrelude}
let Configured = Edges
| where EdgeClass == "configured" and SubjectType == "AgentIdentity"
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| summarize ConfiguredPaths=count(), DirectPaths=countif(GrantOrigin == "direct"),
            BlueprintPaths=countif(GrantOrigin == "blueprintInherited"), ConfiguredEdgeIds=make_set(EdgeId, 100)
  by AgentId=SubjectId, PermissionValue;
let Observed = Edges
| where EdgeClass == "observed" and isnotempty(ConfiguredEdgeId)
| summarize ObservedDependencies=dcount(ConfiguredEdgeId), LastObserved=max(ObservedAt) by AgentId=SubjectId, PermissionValue;
let Reach = ReachEdges
| summarize DeterministicTargets=dcountif(TargetId, EdgeClass == "reachableDeterministic"),
            PotentialTargets=dcountif(TargetId, EdgeClass in ("reachableBounded", "reachableInferred")),
            ReachableCategories=make_set(ResourceScope, 50)
  by AgentId=SubjectId, PermissionValue;
Configured
| join kind=leftouter Observed on AgentId, PermissionValue
| join kind=leftouter Reach on AgentId, PermissionValue
| join kind=leftouter AgentNames on AgentId
| join kind=leftouter BlueprintLinks on AgentId
| join kind=leftouter BlueprintNames on BlueprintId
| extend AgentName=coalesce(AgentName, AgentId), BlueprintName=coalesce(BlueprintName, "Unknown"),
         ObservedDependencies=coalesce(ObservedDependencies, long(0)),
         DeterministicTargets=coalesce(DeterministicTargets, long(0)),
         PotentialTargets=coalesce(PotentialTargets, long(0)),
         ImpactConfidence=case(ObservedDependencies > 0 or DeterministicTargets > 0, "Higher - observed or deterministic dependency", PotentialTargets > 0, "Potential - inferred resource category", "Unknown - dependency evidence missing")
| project AgentName, AgentObjectId=AgentId, BlueprintName, PermissionValue, ConfiguredPaths,
          DirectPaths, BlueprintPaths, ObservedDependencies, DeterministicTargets, PotentialTargets,
          ReachableCategories, ImpactConfidence, LastObserved, ConfiguredEdgeIds
| order by ObservedDependencies desc, DeterministicTargets desc, PotentialTargets desc, AgentName asc`;
const changeLive = item("group-change-impact", "change-live-impact");
changeLive.content.query = changeImpactQuery;
changeLive.content.title = "Live permission-removal impact candidates (dry run)";
const blastChartQuery = String.raw`${edgePrelude}
Edges
| where EdgeClass == "configured" and SubjectType == "AgentIdentity" and isnotempty(PermissionValue)
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| summarize AffectedAgents=dcount(SubjectId), GrantPaths=count(), DirectPaths=countif(GrantOrigin == "direct") by Permission=PermissionValue
| order by AffectedAgents desc, GrantPaths desc`;
insertAfter(
  "group-change-impact",
  "change-live-impact",
  analyticsItem("agent-posture", "change-live-blast-chart", "Live permission blast radius", blastChartQuery, "barchart", "agent-posture"),
);
const blueprintBlastQuery = String.raw`${edgePrelude}
let Declarations = Edges
| where EdgeClass == "configured" and Relation == "declares" and SubjectType == "AgentIdentityBlueprint"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| project BlueprintId=SubjectId, PermissionValue, DeclarationEdgeId=EdgeId;
Declarations
| join kind=leftouter BlueprintLinks on BlueprintId
| join kind=leftouter AgentNames on AgentId
| join kind=leftouter BlueprintNames on BlueprintId
| summarize ChildAgents=dcount(AgentId), Agents=make_set(coalesce(AgentName, AgentId), 100) by Blueprint=coalesce(BlueprintName, BlueprintId), BlueprintId, PermissionValue
| where "{BlueprintFilter}" == "*" or BlueprintId == "{BlueprintFilter}"
| order by ChildAgents desc, Blueprint asc, PermissionValue asc`;
insertAfter(
  "group-change-impact",
  "change-live-blast-chart",
  analyticsItem("privilege-exposure-matrix", "change-live-blueprint-impact", "Live blueprint declaration blast radius", blueprintBlastQuery, "table", "privilege-exposure-matrix"),
);

const confidenceTableQuery = String.raw`${edgePrelude}
Edges
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| summarize Edges=count(), Agents=dcountif(SubjectId, SubjectType == "AgentIdentity"), LatestEvidence=max(TimeGenerated)
  by EvidencePlane=EdgeClass, Confidence, EvidenceAuthority
| order by EvidencePlane asc, Confidence asc`;
insertAfter(
  "group-evidence",
  "evidence-live-health",
  analyticsItem("privilege-exposure-matrix", "evidence-live-confidence", "Live canonical evidence confidence", confidenceTableQuery, "table", "privilege-exposure-matrix"),
);
const confidenceChartQuery = String.raw`${edgePrelude}
Edges
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| summarize Edges=count() by Confidence=iff(isempty(Confidence), "unknown", Confidence)
| order by Edges desc`;
insertAfter(
  "group-evidence",
  "evidence-live-confidence",
  analyticsItem("confidence-chart", "evidence-live-confidence-chart", "Live evidence confidence distribution", confidenceChartQuery, "piechart", "confidence-chart"),
);

const posture360 = item("group-permission-360", "permission-360-live-posture");
posture360.content.query = String.raw`${reachPrelude}
let Configured = Edges
| where EdgeClass == "configured" and SubjectType == "AgentIdentity"
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| summarize ConfiguredPermissions=dcount(PermissionValue), PermissionList=make_set(PermissionValue, 100),
            DirectPaths=countif(GrantOrigin == "direct"), BlueprintPaths=countif(GrantOrigin == "blueprintInherited"),
            LatestConfigured=max(TimeGenerated)
  by AgentId=SubjectId;
let Observed = Edges
| where EdgeClass == "observed" and isnotempty(ConfiguredEdgeId)
| summarize ObservedConfiguredPaths=dcount(ConfiguredEdgeId), LastObserved=max(ObservedAt) by AgentId=SubjectId;
let Reach = ReachEdges
| summarize DeterministicReach=dcountif(TargetId, EdgeClass == "reachableDeterministic"),
            BoundedReach=dcountif(TargetId, EdgeClass == "reachableBounded"),
            InferredReach=dcountif(TargetId, EdgeClass == "reachableInferred"),
            ResourceCategories=make_set(ResourceScope, 50)
  by AgentId=SubjectId;
let Controls = Edges
| where EdgeClass == "control"
| summarize Controls=count(), ControlList=make_set(TargetId, 50) by AgentId=SubjectId;
Configured
| join kind=leftouter Observed on AgentId
| join kind=leftouter Reach on AgentId
| join kind=leftouter Controls on AgentId
| join kind=leftouter AgentNames on AgentId
| join kind=leftouter BlueprintLinks on AgentId
| join kind=leftouter BlueprintNames on BlueprintId
| extend AgentName=coalesce(AgentName, AgentId), BlueprintName=coalesce(BlueprintName, "Unknown"),
         ObservedConfiguredPaths=coalesce(ObservedConfiguredPaths, long(0)),
         UnobservedPermissions=ConfiguredPermissions-coalesce(ObservedConfiguredPaths, long(0)),
         UtilizationPercent=iff(ConfiguredPermissions == 0, real(null), round(100.0*todouble(ObservedConfiguredPaths)/todouble(ConfiguredPermissions), 0))
| project AgentName, AgentObjectId=AgentId, BlueprintName, ConfiguredPermissions, PermissionList,
          DirectPaths, BlueprintPaths, ObservedConfiguredPaths, UnobservedPermissions, UtilizationPercent,
          DeterministicReach=coalesce(DeterministicReach, long(0)), BoundedReach=coalesce(BoundedReach, long(0)),
          InferredReach=coalesce(InferredReach, long(0)), ResourceCategories, Controls=coalesce(Controls, long(0)),
          ControlList, LatestEvidence=max_of(LatestConfigured, LastObserved)
| order by AgentName asc`;
posture360.content.title = "Live Agent Permission 360 posture";

const permission360DetailQuery = String.raw`${reachPrelude}
let Configured = Edges
| where EdgeClass == "configured" and SubjectType == "AgentIdentity"
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| project AgentId=SubjectId, PermissionValue, PermissionMode, AuthorizationMechanism, GrantOrigin,
          ConfiguredEdgeId=EdgeId, TargetServicePrincipal=TargetId, GrantState, RetrievedAt;
let Reach = ReachEdges
| summarize ReachabilityClasses=make_set(EdgeClass, 10), ReachableResources=make_set(ResourceScope, 50),
            DeterministicTargets=dcountif(TargetId, EdgeClass == "reachableDeterministic"),
            PotentialTargets=dcountif(TargetId, EdgeClass in ("reachableBounded", "reachableInferred"))
  by AgentId=SubjectId, PermissionValue;
let Observed = Edges
| where EdgeClass == "observed" and isnotempty(ConfiguredEdgeId)
| summarize Observations=count(), LastObserved=max(ObservedAt) by ConfiguredEdgeId;
Configured
| join kind=leftouter Reach on AgentId, PermissionValue
| join kind=leftouter Observed on ConfiguredEdgeId
| join kind=leftouter AgentNames on AgentId
| join kind=leftouter BlueprintLinks on AgentId
| join kind=leftouter BlueprintNames on BlueprintId
| extend AgentName=coalesce(AgentName, AgentId), BlueprintName=coalesce(BlueprintName, "Unknown")
| project AgentName, AgentObjectId=AgentId, BlueprintName, PermissionValue, PermissionMode,
          AuthorizationMechanism, GrantOrigin, GrantState, Observations=coalesce(Observations, long(0)),
          LastObserved, DeterministicTargets=coalesce(DeterministicTargets, long(0)),
          PotentialTargets=coalesce(PotentialTargets, long(0)), ReachabilityClasses, ReachableResources,
          TargetServicePrincipal, ConfiguredEdgeId, RetrievedAt
| order by AgentName asc, PermissionValue asc`;
insertAfter(
  "group-permission-360",
  "permission-360-live-posture",
  analyticsItem("privilege-exposure-matrix", "permission-360-live-permissions", "Live permissions, provenance, use, and reach", permission360DetailQuery, "table", "privilege-exposure-matrix"),
);
insertAfter(
  "group-permission-360",
  "permission-360-live-permissions",
  analyticsItem("agent-posture", "permission-360-live-utilization-chart", "Live configured versus observed permission paths", utilizationChartQuery, "barchart", "agent-posture"),
);
const edgeClass360Query = String.raw`${edgePrelude}
Edges
| where SubjectType == "AgentIdentity"
| where "{AgentFilter}" == "*" or SubjectId == "{AgentFilter}"
| where "{PermissionFilter}" == "*" or PermissionValue == "{PermissionFilter}"
| summarize Edges=count(), Agents=dcount(SubjectId) by EvidencePlane=EdgeClass
| order by Edges desc`;
insertAfter(
  "group-permission-360",
  "permission-360-live-utilization-chart",
  analyticsItem("confidence-chart", "permission-360-live-plane-chart", "Live Agent Permission 360 evidence planes", edgeClass360Query, "piechart", "confidence-chart"),
);

setDescription(
  "group-effective-access",
  "reachable-live-edges-description",
  "**Live effective reach:** combines canonical reachability edges with an explicit fallback mapping from configured permissions to resource categories. Azure RBAC with an exact scope is deterministic; directory roles are bounded; broad Microsoft Graph permissions remain inferred. The fallback never invents exact SharePoint sites, mailboxes, files, or sensitivity labels. Source: `AgentPermissionEdges_CL`.",
  "info",
);
setDescription(
  "group-sensitive-exposure",
  "exposure-intro",
  "## 07 Sensitive Exposure & Hygiene\n\n**What valuable data can it reach?** Live mode shows both classified sensitive resources and potential resource-category exposure. When Purview or another governed classification source is not connected, classification remains **Unknown** and the workbook displays the evidence gap instead of returning an empty result or inventing sensitivity.",
  "warning",
);
setDescription(
  "group-sensitive-exposure",
  "exposure-live-edges-description",
  "**Live exposure candidates:** shows every deterministic, bounded, or inferred resource path. Collector-provided sensitivity labels remain authoritative; when classification is missing, the row stays `Unknown` and identifies the Purview/resource-inventory evidence gap. Source: `AgentPermissionEdges_CL`.",
  "warning",
);
setDescription(
  "group-drift",
  "drift-live-edges-description",
  "**Live blueprint comparison:** joins each Agent ID to its parent blueprint, compares materialized child grants with blueprint `requiredResourceAccess` declarations, and labels each path as baseline match, direct exception, or unknown because the blueprint mapping is missing. Source: `AgentPermissionEdges_CL`.",
  "info",
);
setDescription(
  "group-change-impact",
  "change-live-impact-description",
  "**Live dry-run impact:** one row per Agent ID and permission, including configured paths, direct/blueprint provenance, matched observations, deterministic targets, inferred resource categories, and confidence. No permission is removed and no control is changed. Source: `AgentPermissionEdges_CL`.",
  "warning",
);
setDescription(
  "group-permission-360",
  "permission-360-live-posture-description",
  "**Live Permission 360 posture:** agent name, blueprint, permission list, direct and blueprint paths, matched observations, deterministic/bounded/inferred reach, resource categories, controls, and evidence freshness. Missing activity or classification remains unknown rather than being converted into a safe result. Source: `AgentPermissionEdges_CL`.",
  "upsell",
);

// --- Per-graphic source captions (added so every chart/table/tile names its
// exact source table, not just the group-level introduction) ---

function descriptionItem(name, markdown, style = "info") {
  return {
    type: 1,
    content: { json: markdown, style },
    name,
    conditionalVisibility: clone(liveVisibility),
  };
}

// Existing descriptions that covered only the first item in a multi-graphic
// group: add the explicit collector/Data lake source to each.
setDescription(
  "group-executive",
  "executive-live-permission-posture-description",
  "## Live Permission Intelligence posture\n\nA multi-metric tenant posture from the latest canonical edge snapshot. The tiles separate identity population, configured permissions, direct grants, write-capable scopes, observed matches, reachable paths, and controls. **Zero observed or reachable paths means the corresponding evidence is not present; it does not mean zero real-world use or reach.**\n\n**Source:** `AgentPermissionEdges_CL`.",
  "upsell",
);
setDescription(
  "group-configured",
  "configured-live-edges-description",
  "**Live configured access:** authoritative normalized grants from Microsoft Graph, Azure Resource Graph/ARM, RSC, groups, roles, or workload ACL collectors. Missing collectors produce no rows and remain unknown. Source: `AgentPermissionEdges_CL`.",
  "info",
);
setDescription(
  "group-access-path",
  "access-path-live-edges-description",
  "**Live access explanation edges:** canonical identity, configured, observed, reachable, and control relationships for the selected agent/permission. Preserve `EdgeClass` when reconstructing a path. Source: `AgentPermissionEdges_CL`.",
  "info",
);
setDescription(
  "group-evidence",
  "workspace-source-health-description",
  "**Analytics workspace output:** source population and freshness for configured-permission candidates and correlated activity in the selected Log Analytics workspace. Missing tables return no rows through `union isfuzzy=true`; they are not treated as zero coverage. Includes `AgentPermissionEdges_CL` alongside `AgentsInfo`, `MicrosoftGraphActivityLogs`, `AADServicePrincipalSignInLogs`, and `CloudAppEvents`.",
  "info",
);
setDescription(
  "group-executive",
  "executive-live-kpis-description",
  "**Live Agent 365 output:** current counts and freshness from `EntraAgentIdentityBlueprints`, `EntraAgentIdentities`, `EntraAgentUsers`, and `UnifiedAgentObservability` (Agent 365 Data lake). These values prove source population, not configured-permission completeness.",
  "info",
);
setDescription(
  "group-executive",
  "executive-live-blueprints-description",
  "**Live Agent 365 output:** current Agent ID blueprint count and newest snapshot from `EntraAgentIdentityBlueprints` (Agent 365 Data lake).",
  "info",
);
setDescription(
  "group-executive",
  "executive-live-users-description",
  "**Live Agent 365 output:** current embodied/agent-user count and newest snapshot from `EntraAgentUsers` (Agent 365 Data lake).",
  "info",
);
setDescription(
  "group-executive",
  "executive-live-events-description",
  "**Live Agent 365 output:** observed Agent 365 event volume during the selected time window, scoped by global agent and blueprint filters. Source: `UnifiedAgentObservability` (Agent 365 Data lake).",
  "info",
);
setDescription(
  "group-evidence",
  "evidence-live-health-description",
  "**Live Agent 365 output:** row counts and oldest/newest timestamps for each of `EntraAgentIdentityBlueprints`, `EntraAgentIdentities`, `EntraAgentUsers`, and `UnifiedAgentObservability` (Agent 365 Data lake). Fresh data does not by itself prove full connector coverage.",
  "info",
);
setDescription(
  "group-identity",
  "identity-live-datalake-description",
  "**Live Agent 365 output:** direct Data lake join of blueprint → agent identity → optional agent user using the confirmed Agent 365 keys. Source: `EntraAgentIdentityBlueprints`, `EntraAgentIdentities`, `EntraAgentUsers` (Agent 365 Data lake).",
  "info",
);
setDescription(
  "group-permission-360",
  "permission-360-live-identity-description",
  "**Live Agent 365 output:** current Agent ID, blueprint, service-principal type, lifecycle state, and optional agent-user context from `EntraAgentIdentityBlueprints`, `EntraAgentIdentities`, `EntraAgentUsers` (Agent 365 Data lake). It complements—rather than replaces—the synthetic permission posture until Graph authorization collectors are connected.",
  "info",
);

// New per-graphic captions for charts/tables that previously shared only
// their group's single lead-in description.
insertAfter(
  "group-executive",
  "executive-live-permission-posture",
  descriptionItem(
    "executive-live-agent-posture-description",
    "**Live per-agent posture:** the same configured/direct/observed/reachable/control counts as the tile above, broken out one row per Agent ID so agents can be compared side by side. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-executive",
  "executive-live-agent-posture",
  descriptionItem(
    "executive-live-utilization-chart-description",
    "**Live utilization:** configured permission paths versus the subset actually observed, per agent — the least-privilege headline in chart form. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-executive",
  "executive-live-utilization-chart",
  descriptionItem(
    "executive-live-concentration-chart-description",
    "**Live concentration:** which permissions are shared by the most agents, surfacing systemic exposure if one permission is later revoked or compromised. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-identity",
  "identity-live-datalake",
  descriptionItem(
    "identity-live-status-chart-description",
    "**Live status mix:** Agent Identity counts grouped by parent blueprint and enabled/disabled state. Source: `EntraAgentIdentityBlueprints`, `EntraAgentIdentities` (Agent 365 Data lake).",
  ),
);
insertAfter(
  "group-configured",
  "configured-live-edges",
  descriptionItem(
    "configured-live-permission-chart-description",
    "**Live grant volume:** counts configured permission edges per affected Agent ID, highlighting which identities carry the most configured grants. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-configured",
  "configured-live-permission-chart",
  descriptionItem(
    "configured-live-provenance-chart-description",
    "**Live provenance mix:** splits configured grants by how they were obtained — direct assignment, blueprint inheritance, group-derived, or role-derived. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-observed",
  "observed-live-datalake",
  descriptionItem(
    "observed-live-operation-chart-description",
    "**Live operation mix:** observed event volume grouped by operation, with distinct-agent and error counts per operation. Source: `UnifiedAgentObservability` (Agent 365 Data lake).",
  ),
);
insertAfter(
  "group-observed",
  "observed-live-operation-chart",
  descriptionItem(
    "observed-live-timeline-description",
    "**Live timeline:** daily observed-event volume over the selected time range, broken out by operation, so spikes or gaps are visible at a glance. Source: `UnifiedAgentObservability` (Agent 365 Data lake).",
  ),
);
insertAfter(
  "group-effective-access",
  "reachable-live-edges",
  descriptionItem(
    "reachable-live-class-chart-description",
    "**Live confidence mix:** the proportion of reachable edges that are deterministic, bounded, or inferred — the evidence behind the reachability table above. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-effective-access",
  "reachable-live-class-chart",
  descriptionItem(
    "reachable-live-resource-chart-description",
    "**Live resource reach:** distinct agents that can reach each resource category, showing which categories have the broadest agent exposure. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-drift",
  "drift-live-edges",
  descriptionItem(
    "drift-live-chart-description",
    "**Live drift mix:** the proportion of agents whose effective permissions match the blueprint baseline versus those with direct exceptions or an unknown baseline. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-sensitive-exposure",
  "exposure-live-edges",
  descriptionItem(
    "exposure-live-resource-chart-description",
    "**Live exposure volume:** exposure-candidate edges per resource category, showing where sensitive-reach evidence concentrates. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-sensitive-exposure",
  "exposure-live-resource-chart",
  descriptionItem(
    "exposure-live-access-chart-description",
    "**Live access-level mix:** exposure candidates split by access level (read/write/unknown), isolating write-capable paths into sensitive resource categories. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-access-path",
  "access-path-live-edges",
  descriptionItem(
    "access-path-live-chart-description",
    "**Live path composition:** explainable access-path edges counted by `EdgeClass`, showing how much of the path is configured, observed, reachable, or control evidence. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-change-impact",
  "change-live-impact",
  descriptionItem(
    "change-live-blast-chart-description",
    "**Live blast radius:** affected agents, configured edges, and deterministic paths that would be lost if the selected permission were removed — a dry run, nothing is changed. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-change-impact",
  "change-live-blast-chart",
  descriptionItem(
    "change-live-blueprint-impact-description",
    "**Live blueprint impact:** one row per blueprint declaration, showing how many child Agent IDs and materialized grants depend on it before any change is made. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-evidence",
  "evidence-live-health",
  descriptionItem(
    "evidence-live-confidence-description",
    "**Live confidence rows:** canonical edge counts grouped by evidence class and confidence level, showing how much of the graph is high-confidence versus inferred or unknown. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-evidence",
  "evidence-live-confidence",
  descriptionItem(
    "evidence-live-confidence-chart-description",
    "**Live confidence mix:** the same confidence breakdown visualized as a proportion of all canonical edges. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-permission-360",
  "permission-360-live-posture",
  descriptionItem(
    "permission-360-live-permissions-description",
    "**Live permission detail:** every configured permission for the selected agent, with provenance (direct/inherited), whether it was observed in use, and its reachability class. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-permission-360",
  "permission-360-live-permissions",
  descriptionItem(
    "permission-360-live-utilization-chart-description",
    "**Live utilization:** configured versus observed permission counts for the selected agent — the same least-privilege comparison as the Executive page, scoped to this agent. Source: `AgentPermissionEdges_CL`.",
  ),
);
insertAfter(
  "group-permission-360",
  "permission-360-live-utilization-chart",
  descriptionItem(
    "permission-360-live-plane-chart-description",
    "**Live evidence planes:** this agent's canonical edges broken down by evidence plane (configured/observed/reachable/control) — the full-picture view Permission 360 promises. Source: `AgentPermissionEdges_CL`.",
  ),
);

// --- Live aggregate-table color parity -------------------------------------
// Several live rollup tables either had no color formatters at all, or had
// stale formatters left over from an earlier draft (column names like
// ReadAgents/WriteAgents/AdminAgents that do not exist in the actual live
// query output, so they silently had zero visual effect). Raw per-edge list
// tables (configured-live-edges, reachable-live-edges, drift-live-edges,
// exposure-live-edges, access-path-live-edges, identity-live-datalake,
// observed-live-datalake) are intentionally left uncolored, matching their
// synthetic counterparts (configured-paths, reachable-results, etc.), which
// are also plain -- color formatting is reserved for aggregate/rollup rows
// where a heatmap bar is meaningful.
setFormatters("group-executive", "executive-live-agent-posture", [
  { columnMatch: "ConfiguredPermissions", formatter: 8, formatOptions: { palette: "lightBlue", showIcon: true, min: 0 } },
  { columnMatch: "ObservedConfiguredPaths", formatter: 8, formatOptions: { palette: "greenDark", showIcon: true, min: 0 } },
  { columnMatch: "UtilizationPercent", formatter: 8, formatOptions: { palette: "blueGreen", showIcon: true, min: 0, max: 100 } },
  { columnMatch: "DeterministicReach", formatter: 8, formatOptions: { palette: "greenBlue", showIcon: true, min: 0 } },
  { columnMatch: "InferredReach", formatter: 8, formatOptions: { palette: "purple", showIcon: true, min: 0 } },
  { columnMatch: "WriteCapablePermissions", formatter: 8, formatOptions: { palette: "blueOrange", showIcon: true, min: 0 } },
]);
setFormatters("group-change-impact", "change-live-impact", [
  { columnMatch: "ConfiguredPaths", formatter: 8, formatOptions: { palette: "lightBlue", showIcon: true, min: 0 } },
  { columnMatch: "DeterministicTargets", formatter: 8, formatOptions: { palette: "blueOrange", showIcon: true, min: 0 } },
  { columnMatch: "ObservedDependencies", formatter: 8, formatOptions: { palette: "greenDark", showIcon: true, min: 0 } },
  { columnMatch: "PotentialTargets", formatter: 8, formatOptions: { palette: "purple", showIcon: true, min: 0 } },
]);
setFormatters("group-change-impact", "change-live-blueprint-impact", [
  { columnMatch: "ChildAgents", formatter: 8, formatOptions: { palette: "lightBlue", showIcon: true, min: 0 } },
]);
setFormatters("group-permission-360", "permission-360-live-posture", [
  { columnMatch: "ConfiguredPermissions", formatter: 8, formatOptions: { palette: "lightBlue", showIcon: true, min: 0 } },
  { columnMatch: "ObservedConfiguredPaths", formatter: 8, formatOptions: { palette: "greenDark", showIcon: true, min: 0 } },
  { columnMatch: "UtilizationPercent", formatter: 8, formatOptions: { palette: "blueGreen", showIcon: true, min: 0, max: 100 } },
  { columnMatch: "DeterministicReach", formatter: 8, formatOptions: { palette: "greenBlue", showIcon: true, min: 0 } },
  { columnMatch: "InferredReach", formatter: 8, formatOptions: { palette: "purple", showIcon: true, min: 0 } },
]);
setFormatters("group-permission-360", "permission-360-live-permissions", [
  { columnMatch: "Observations", formatter: 8, formatOptions: { palette: "greenDark", showIcon: true, min: 0 } },
  { columnMatch: "DeterministicTargets", formatter: 8, formatOptions: { palette: "greenBlue", showIcon: true, min: 0 } },
  { columnMatch: "PotentialTargets", formatter: 8, formatOptions: { palette: "purple", showIcon: true, min: 0 } },
]);
setFormatters("group-evidence", "evidence-live-confidence", [
  { columnMatch: "Edges", formatter: 8, formatOptions: { palette: "greenBlue", showIcon: true, min: 0 } },
  { columnMatch: "Agents", formatter: 8, formatOptions: { palette: "lightBlue", showIcon: true, min: 0 } },
]);

// --- Main-page capability/source map -------------------------------------
// Puts the "which section reads which table" breakdown directly on the
// landing page, not just in chat/README, so a reader never has to ask.
const capabilitySourceMapMarkdown = `## What each view reads, and where it comes from

| # | Section | Data source | What it reads |
|---|---|---|---|
| 01 | Executive | Both | Collector (\`AgentPermissionEdges_CL\`) for permission posture, agent posture, utilization, and concentration; Data lake (\`EntraAgentIdentityBlueprints\` / \`EntraAgentIdentities\` / \`EntraAgentUsers\` / \`UnifiedAgentObservability\`) for the identity/blueprint/user/event KPI tiles |
| 02 | Identity & Lifecycle | Data lake only | \`EntraAgentIdentityBlueprints\`, \`EntraAgentIdentities\`, \`EntraAgentUsers\` (blueprint↔identity join, status chart) |
| 03 | Configured Access | Collector only | \`AgentPermissionEdges_CL\` (edges, permission chart, provenance chart) |
| 04 | Observed Access | Data lake only | \`UnifiedAgentObservability\` (activity table, operation chart, timeline) |
| 05 | Effective & Reachable Access | Collector only | \`AgentPermissionEdges_CL\` (reachability edges, class chart, resource chart) |
| 06 | Blueprint Drift | Collector only | \`AgentPermissionEdges_CL\` (drift edges, drift chart) |
| 07 | Sensitive Exposure & Hygiene | Collector only | \`AgentPermissionEdges_CL\` (exposure edges, resource/access charts) |
| 08 | Explain Access Paths | Collector only | \`AgentPermissionEdges_CL\` (path edges, path chart) |
| 09 | Change Impact | Collector only | \`AgentPermissionEdges_CL\` (impact simulation, blast-radius chart, blueprint-impact table) |
| 10 | Evidence & Methodology | Both | Collector for confidence tiles/chart and the workspace source-health query (includes \`AgentPermissionEdges_CL\` alongside \`AgentsInfo\`/Graph/sign-in/Defender tables); Data lake for its own health panel |
| 11 | Permission 360 | Both | Collector for posture, permissions, utilization, and plane charts; Data lake only for the identity-context lookup (resolving the agent's name/blueprint/state) |

**Why this split exists:**

- **Data lake–only** views (02, 04) ask *who/what is this agent* and *what did it do* — both answered directly by the native Agent 365 system tables, with no authorization semantics involved.
- **Collector-only** views (03, 05–09) all require *authorization* evidence — app-role assignments, delegated grants, Azure RBAC, directory roles, derived reachability — which does not exist in the Data lake tables. These populate only once the PowerShell/Azure Automation collector has written to \`AgentPermissionEdges_CL\`.
- **Blended** views (01, 10, 11) are landing/summary pages that intentionally combine both, to show identity, activity, and authorization together in one place.

If the collector has not run yet (or its daily schedule is disabled), views 03 and 05–09, and most of 01/10/11, show empty or **Unknown** — by design, not a bug.`;

insertTopLevelAfter(
  "intro",
  {
    type: 1,
    content: { json: capabilitySourceMapMarkdown, style: "info" },
    name: "capability-source-map",
  },
);

fs.writeFileSync(workbookPath, `${JSON.stringify(workbook, null, 2)}\n`);
