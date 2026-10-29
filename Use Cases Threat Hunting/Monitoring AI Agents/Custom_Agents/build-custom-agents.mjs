import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

export const directory = path.dirname(fileURLToPath(import.meta.url));
export function stableId(name) {
  const namespace = Buffer.from("747f7941668c4a4b8e326de857cd09ce", "hex");
  const bytes = crypto.createHash("sha1").update(namespace).update(name).digest().subarray(0, 16);
  bytes[6] = (bytes[6] & 15) | 80;
  bytes[8] = (bytes[8] & 63) | 128;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

const injection = String.raw`(?i)(ignore (all|any|the|previous|prior|above).{0,40}instruction|disregard.{0,40}instruction|developer mode|jailbreak|do anything now|reveal your (instructions|prompt))`;
const secrets = String.raw`(-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----|(?:AKIA|ASIA)[A-Z0-9]{16}|gh[pousr]_[A-Za-z0-9]{36,}|sk-[A-Za-z0-9_-]{20,})`;
const unsafe = String.raw`(?i)(<script(?:\s|>)|javascript\s*:|data\s*:\s*text/html|<iframe(?:\s|>)|<object(?:\s|>)|<embed(?:\s|>)|on(?:error|load|click)\s*=|document\.cookie|window\.location\s*=)`;
const exploit = String.raw`(?i)(remote code execution|reverse[_ -]?shell|metasploit|run_shell_command|vulnerabilities/exec|(execute|run).{0,40}(command|shell|powershell|terminal))`;
const spans = `CustomAgentSpans(1h)
| where Classification !in ('Excluded managed platform', 'Unattributed GenAI') and HasLineage`;
const inlineContent = "Evidence";
const evidenceColumns = `Prompt, Output, ToolArguments, ToolResult, InputMessages, OutputMessages,
    EvidenceSource, PromptEvidenceOrigin, OutputEvidenceOrigin, PromptEvidenceSpanId, OutputEvidenceSpanId,
    InputParseState, OutputParseState, ToolArgumentsState, ToolResultState`;
const relatedToolColumns = `TriggerSpanId, TriggerTime, TriggerTool, TriggerToolResult,
    TriggerServerDisplay, TriggerTargetHost, RiskyOutputKind, RelatedToolResults`;
const projection = `| extend TimeGenerated=EventTime, ResourceId=_ResourceId, TraceId=OperationId,
    EventCount=tolong(column_ifexists('EventCount', 1)),
    SuccessfulCalls=tolong(column_ifexists('SuccessfulCalls', 0)),
    FailedCalls=tolong(column_ifexists('FailedCalls', 0))
| project TimeGenerated, ResourceId, Agent, AgentId, AgentKey, AppRoleName,
    TraceId, SpanId, Conversation, Model, Tool, TargetHost, ServerDisplay,
    Signal, EventCount, SuccessfulCalls, FailedCalls,
    TriggerSpanId=tostring(column_ifexists('TriggerSpanId', '')),
    TriggerTime=todatetime(column_ifexists('TriggerTime', datetime(null))),
    TriggerTool=tostring(column_ifexists('TriggerTool', '')),
    TriggerToolResult=tostring(column_ifexists('TriggerToolResult', '')),
    TriggerServerDisplay=tostring(column_ifexists('TriggerServerDisplay', '')),
    TriggerTargetHost=tostring(column_ifexists('TriggerTargetHost', '')),
    RiskyOutputKind=tostring(column_ifexists('RiskyOutputKind', '')),
    RelatedToolResults=tolong(column_ifexists('RelatedToolResults', 0)),
    MatchedIntentPrompt=tostring(column_ifexists('IntentPrompt', '')),
    MatchedIntentSpanId=tostring(column_ifexists('IntentSpanId', ''))
| join kind=leftouter (Evidence
    | project ResourceId=_ResourceId, TraceId=OperationId, SpanId, AgentKey, ${evidenceColumns})
    on ResourceId, TraceId, SpanId, AgentKey
| extend Prompt=coalesce(MatchedIntentPrompt, Prompt),
    PromptEvidenceOrigin=iff(isnotempty(MatchedIntentPrompt), 'Matched intent span: user role', PromptEvidenceOrigin),
    PromptEvidenceSpanId=coalesce(MatchedIntentSpanId, PromptEvidenceSpanId)
| extend PreviewCharacters=toint(min_of(160, max_of(0, (1500 - string_size(tostring(bag_pack(
    'AgentId', AgentId, 'AgentKey', AgentKey, 'TraceId', TraceId, 'SpanId', SpanId,
    'Conversation', Conversation, 'ResourceId', ResourceId, 'Signal', Signal)))) / 12)))
| extend PromptPreview=substring(Prompt, 0, PreviewCharacters),
    OutputPreview=substring(Output, 0, PreviewCharacters)
| extend EvidencePreviewStatus=case(PreviewCharacters == 0, 'Metadata exhausted preview budget; inspect full query results',
    strlen(Prompt) > PreviewCharacters or strlen(Output) > PreviewCharacters, 'Inline evidence; previews shortened; full text in query results',
    isempty(Prompt) and isempty(Output), 'No prompt/output captured or parsed; not a protection verdict',
    'Inline evidence; full recorded text in query results')
| project TimeGenerated, ResourceId, Agent, AgentId, AgentKey, AppRoleName,
    TraceId, SpanId, Conversation, Model, Tool, TargetHost, ServerDisplay,
    Signal, EventCount, SuccessfulCalls, FailedCalls, ${evidenceColumns},
    PromptPreview, OutputPreview, EvidencePreviewStatus, ${relatedToolColumns}
| order by TimeGenerated desc`;

function rule(key, title, description, body, { content = false, severity = "Medium", tactics = [] } = {}) {
  return { key, id: stableId(key), name: `Custom Agents - ${title}`, description,
    content, severity, tactics, query: `let Evidence=materialize(CustomAgentInlineContent(1h));\n${body}\n${projection}\n` };
}
function contentRule(key, title, description, predicate, signal, options = {}) {
  return rule(key, title, description,
    `${inlineContent}\n| where ${predicate}\n| summarize arg_min(EventTime, *) by _ResourceId, OperationId, AgentKey\n| extend Signal='${signal}'`,
    { ...options, content: true });
}
function chainRule(key, title, pattern, toolPredicate, description) {
  return rule(key, title, description, `let Intent=${inlineContent}
| where UserText matches regex @'${pattern}'
| summarize arg_min(EventTime, UserText, SpanId) by _ResourceId, OperationId, AgentKey
| project _ResourceId, OperationId, AgentKey, IntentTime=EventTime, IntentPrompt=UserText, IntentSpanId=SpanId;
${spans}
| where IsTool and ${toolPredicate}
| join kind=inner Intent on _ResourceId, OperationId, AgentKey
| where EventTime between (IntentTime .. IntentTime + 10m)
| summarize EventCount=count(), SuccessfulCalls=countif(Success == true),
    FailedCalls=countif(Success == false), arg_min(EventTime, *)
    by _ResourceId, OperationId, AgentKey
| extend Signal='Recorded user intent before observed tool span; impact unproven'`,
  { content: true, severity: "High", tactics: ["Execution"] });
}

const indirectOutputBody = `let ToolResults=Evidence
| where IsTool and ToolResult matches regex @'${injection}'
| where isnotnull(DurationMs) and DurationMs >= 0
| project _ResourceId, OperationId, AgentKey, TriggerSpanId=SpanId,
    TriggerTime=EventTime + DurationMs * 1ms, TriggerTool=Tool, TriggerToolResult=ToolResult,
    TriggerServerDisplay=ServerDisplay, TriggerTargetHost=TargetHost;
Evidence
| where Operation == 'chat'
| extend SecretOutput=OutputText matches regex @'${secrets}', ActiveOutput=OutputText matches regex @'${unsafe}'
| where SecretOutput or ActiveOutput
| extend RiskyOutputKind=case(SecretOutput and ActiveOutput, 'Secret-shaped and active-content output',
    SecretOutput, 'Secret-shaped output', 'Active-content output')
| join kind=inner ToolResults on _ResourceId, OperationId, AgentKey
| where EventTime between (TriggerTime .. TriggerTime + 10m)
| summarize EventCount=dcount(SpanId), RelatedToolResults=dcount(TriggerSpanId), arg_min(EventTime, *)
    by _ResourceId, OperationId, AgentKey
| extend Signal='Instruction-override tool result precedes risky model output; causation unproven'`;

export const rules = [
  contentRule("CustomPromptInjectionAttempt", "Recorded user prompt-injection candidate",
    "Matches instruction-override language only in inline user-role messages. Quoted examples, tests and legitimate discussions can match. A match is not proof of bypass or compromise. Results include unmasked recorded prompt/output.",
    `UserText matches regex @'${injection}'`, "Inline user-input injection candidate",
    { tactics: ["DefenseEvasion"] }),
  contentRule("CustomSecretsInUserInput", "Secret-shaped value in recorded user input",
    "Finds private-key headers and selected credential-shaped patterns in inline user-role input. Returns unmasked recorded prompt/output. Rotate a real exposed credential after investigation; synthetic canaries can match.",
    `UserText matches regex @'${secrets}'`, "Inline user input contains a credential-shaped pattern",
    { severity: "High", tactics: ["CredentialAccess"] }),
  contentRule("CustomSecretShapedOutput", "Secret-shaped value in recorded model output",
    "Finds selected credential-shaped patterns in inline assistant/text output. This does not establish that the credential is valid, newly disclosed, or exfiltrated. Returns unmasked recorded prompt/output.",
    `OutputText matches regex @'${secrets}'`, "Inline output contains a credential-shaped pattern",
    { severity: "High", tactics: ["CredentialAccess"] }),
  contentRule("CustomSystemPromptDisclosure", "Recorded system-instruction prefix in output",
    "Requires at least 80 recorded system/developer characters and an exact case-insensitive match of that prefix in inline assistant/text output. Without recorded system instructions this check is inconclusive, not passed.",
    "strlen(SystemText) >= 80 and tolower(OutputText) contains tolower(substring(SystemText, 0, 80))",
    "Recorded system/developer prefix appears in output", { tactics: ["Collection"] }),
  contentRule("CustomUnsafeActiveContentOutput", "Active-content syntax in recorded output",
    "Flags script, iframe and other active-content syntax in inline assistant/text output. Code examples can match; this is emitted syntax, not evidence that a browser executed it.",
    `OutputText matches regex @'${unsafe}'`, "Inline output contains active-content syntax",
    { tactics: ["Execution"] }),
  contentRule("CustomToolResultInstructionInjection", "Instruction-override candidate in tool result",
    "Checks inline tool results attached to an observed tool span. It does not infer a tool result from user messages or prove that the agent followed the returned instruction.",
    `IsTool and ToolResult matches regex @'${injection}'`, "Inline tool result contains instruction-override language",
    { tactics: ["DefenseEvasion"] }),
  rule("CustomUnapprovedMcpServerExecution", "Observed MCP call to an unapproved target",
    "Requires explicit MCP metadata, a server identifier, and at least one enabled approved-target entry. Empty allowlists and missing server metadata are coverage gaps, not unapproved-server findings. URL paths are case-sensitive.",
    `${spans}\n| where IsTool and ExplicitMcp and Approval == 'UNAPPROVED'\n| extend Signal='Observed explicit MCP tool span with an unapproved exact target'`,
    { tactics: ["Execution"] }),
  rule("CustomCommandCapableMcpToolInvocation", "Observed command-capable MCP tool invocation",
    "Flags an observed explicitly identified MCP tool whose emitted name/description suggests command capability. Authorized administration and tests can match. A successful tool span is not proof of downstream shell execution.",
    `${spans}\n| where IsTool and ExplicitMcp and CommandCapable\n| extend Signal='Command-capable MCP tool span; downstream execution unproven'`,
    { severity: "High", tactics: ["Execution"] }),
  rule("CustomInternalNetworkToolTarget", "Observed tool call to an internal or metadata target",
    "Flags loopback, RFC1918, link-local, IPv6 unique-local, and selected local-name destinations in emitted tool URL metadata. This is target review, not proof of SSRF or target access; DNS rebinding and resolution need additional evidence.",
    `${spans}
| where IsTool and isnotempty(TargetHost)
| where ipv4_is_private(TargetHost) == true
    or ipv4_is_in_range(TargetHost, '127.0.0.0/8') == true
    or ipv4_is_in_range(TargetHost, '169.254.0.0/16') == true
    or ipv6_is_in_range(TargetHost, '::1/128') == true
    or ipv6_is_in_range(TargetHost, 'fc00::/7') == true
    or ipv6_is_in_range(TargetHost, 'fe80::/10') == true
    or TargetHost in ('localhost', 'metadata.google.internal')
    or TargetHost endswith '.localhost' or TargetHost endswith '.local'
| extend Signal='Observed internal tool destination; SSRF and impact unproven'`,
    { tactics: ["Discovery"] }),
  rule("CustomToolFailureStorm", "Observed tool failure storm",
    "Requires at least ten unique observed tool spans and an 80 percent failure rate in one resource/agent/trace within the hour. Sampling can undercount calls; retries and outages are not automatically attacks.",
    `${spans}
| where IsTool
| summarize EventCount=count(), FailedCalls=countif(Success == false),
    SuccessfulCalls=countif(Success == true), arg_max(EventTime, *)
    by _ResourceId, OperationId, AgentKey
| where EventCount >= 10 and 1.0 * FailedCalls / EventCount >= 0.8
| extend Signal='At least 10 observed tool spans; failure rate at least 80 percent'`),
  rule("CustomExcessiveToolCalls", "High observed tool-call volume in a trace",
    "Requires at least fifty unique emitted tool spans in one resource/agent/trace in one hour. This is a tunable volume heuristic, not evidence that authorized agency was exceeded.",
    `${spans}
| where IsTool
| summarize EventCount=count(), SuccessfulCalls=countif(Success == true),
    FailedCalls=countif(Success == false), arg_max(EventTime, *)
    by _ResourceId, OperationId, AgentKey
| where EventCount >= 50
| extend Signal='At least 50 observed tool spans in one resource/agent/trace'`),
  rule("CustomTokenUsageSpike", "High recorded model-token usage in a trace",
    "Sums only chat spans and requires at least 100000 recorded input/output tokens in one resource/agent/trace. It does not sum root aggregate tokens or estimate billing. Tune for normal workload size.",
    `${spans}
| where Operation == 'chat'
| summarize RecordedTokens=sum(InputTokens + OutputTokens), arg_max(EventTime, *)
    by _ResourceId, OperationId, AgentKey
| where RecordedTokens >= 100000
| extend EventCount=RecordedTokens, Signal='At least 100000 recorded chat-span tokens; not a billing estimate'`),
  rule("CustomExplicitGuardrailBlock", "Explicitly recorded guardrail block",
    "Reports an explicit normalized blocked attribute once per resource/agent/trace. This is control evidence, not compromise; ordinary errors, refusals and unavailable evaluations are not counted as blocks.",
    `${spans}
| where Blocked
| summarize arg_min(EventTime, *) by _ResourceId, OperationId, AgentKey
| extend Signal='Explicit guardrail block recorded; review as a control event'`,
    { severity: "Low" }),
  rule("CustomGuardrailEvaluationUnavailable", "Recorded guardrail evaluation unavailable",
    "Reports explicitly recorded unevaluated controls once per resource/agent/trace. An unavailable evaluation is an operational coverage gap, not a passed or blocked control.",
    `${spans}
| where EvaluationUnavailable
| summarize arg_min(EventTime, *) by _ResourceId, OperationId, AgentKey
| extend Signal='Guardrail evaluation unavailable; no protection verdict'`,
    { severity: "Low" }),
  chainRule("CustomExploitIntentMcpCommandChain", "Recorded exploit intent before command-capable MCP call",
    exploit, "ExplicitMcp and CommandCapable",
    "Correlates inline user-role exploit/command intent with a later command-capable explicit MCP span in the same resource, agent and trace, at most ten minutes later. Other agents/resources, reverse order and late calls cannot satisfy the chain. Successful spans do not prove downstream exploitation."),
  chainRule("CustomPromptInjectionToolChain", "Recorded injection candidate before tool call",
    injection, "true",
    "Correlates inline user-role instruction-override language with a later observed tool span in the same resource, agent and trace within ten minutes. It is an ordered observation, not proof that the input caused the tool action."),
  contentRule("CustomSecretsInToolArguments", "Secret-shaped value in observed tool arguments",
    "Finds selected credential-shaped patterns in inline arguments on an observed tool-execution span. Authorized authentication and synthetic canaries can match. This is recorded cleartext exposure, not proof of unauthorized delivery or exfiltration.",
    `IsTool and ToolArguments matches regex @'${secrets}'`, "Observed tool arguments contain a credential-shaped pattern",
    { severity: "High", tactics: ["CredentialAccess"] }),
  contentRule("CustomSecretsInToolResult", "Secret-shaped value in observed tool result",
    "Finds selected credential-shaped patterns in inline results on an observed tool-execution span. This does not prove a valid credential, model consumption, disclosure in a response or exfiltration.",
    `IsTool and ToolResult matches regex @'${secrets}'`, "Observed tool result contains a credential-shaped pattern",
    { severity: "High", tactics: ["CredentialAccess"] }),
  rule("CustomToolResultRiskyOutputChain", "Instruction-override tool result before risky model output",
    "Requires an instruction-override candidate in an observed tool result with a recorded nonnegative duration, followed by a chat span containing secret-shaped or active-content output. Model start must be at/after recorded tool end and within ten minutes, on the same resource, agent and trace. Returns the actual triggering tool result and output span. Ordered observation is not proof of instruction following, valid secrets, browser execution or bypass.",
    indirectOutputBody, { content: true, severity: "High", tactics: ["Collection"] }),
];

const watchlistHealth = (alias) => `(_GetWatchlist('${alias}')
| extend W=todynamic(column_ifexists('WatchlistItem', dynamic(null)))
| summarize Rows=count(),
    EnabledRows=countif(coalesce(tostring(column_ifexists('Enabled', '')), tostring(W.Enabled)) =~ 'true'),
    LastSeen=max(todatetime(column_ifexists('LastUpdatedTimeUTC', datetime(null))))
| extend Source='Watchlist: ${alias}',
    State=case(Rows == 0, 'EMPTY / NOT READY: configuration unavailable',
        EnabledRows == 0, 'NO ENABLED ENTRIES: configuration not active',
        'ENABLED ROWS PRESENT: validate scope and approval'))`;

export const hunts = [
  { key: "CustomSourceHealth", name: "Custom Agents - Source health and classification counts",
    description: "Reports observed rows and configuration readiness. Missing required telemetry tables are query errors. Empty/not-ready watchlists mean unavailable configuration, not protection. Zero inventory can mean SDK-only mode.",
    query: `union
(${spans.split("\n| where")[0]}
| summarize Rows=count(), LastSeen=max(EventTime) by Classification
| extend Source=strcat('Runtime: ', Classification)
| project Source, Rows, LastSeen),
(CustomAgentInventory() | summarize Rows=count(), LastSeen=max(Snapshot)
| extend Source='Inventory: optional, zero can mean SDK-only mode'),
${watchlistHealth("CustomAgentScope")},
${watchlistHealth("CustomAgentApprovedMcpTargets")}
| project Source, Rows, EnabledRows, State, LastSeen` },
  { key: "CustomAttributionGaps", name: "Custom Agents - Unattributed GenAI and missing lineage",
    description: "Shows missing custom attribution or stable lineage without classifying generic GenAI as custom. Does not expose captured content.",
    query: `CustomAgentSpans(24h)
| where Classification == 'Unattributed GenAI' or not(HasLineage)
| summarize Records=count(), LastSeen=max(EventTime) by AppRoleName, Classification, HasLineage
| order by Records desc` },
  { key: "CustomObservedAgentInventory", name: "Custom Agents - Observed custom application inventory",
    description: "Runtime-observed applications, not registry counts. Exact custom scope or explicit markers are necessary in SDK-only mode.",
    query: `${spans}
| summarize FirstSeen=min(EventTime), LastSeen=max(EventTime), Traces=dcount(OperationId),
    Models=make_set_if(Model, isnotempty(Model), 20) by _ResourceId, AppRoleName, Agent, AgentId, AgentKey, Classification` },
  { key: "CustomModelUsage", name: "Custom Agents - Recorded model usage",
    description: "Counts only chat spans and their emitted token totals; root aggregate tokens are excluded.",
    query: `${spans}
| where Operation == 'chat'
| summarize ModelSpans=count(), InputTokens=sum(InputTokens), OutputTokens=sum(OutputTokens),
    P95DurationMs=percentile(DurationMs, 95) by _ResourceId, Agent, AgentKey, Model` },
  { key: "CustomToolInventory", name: "Custom Agents - Observed tool inventory",
    description: "Separates observed execution operations from tool metadata without execution evidence. Record counts can be incomplete under sampling.",
    query: `${spans}
| where IsTool or isnotempty(Tool)
| extend ExecutionEvidence=iff(IsTool, 'Observed tool-execution operation', 'Tool metadata without execution operation')
| summarize Records=count(), Failed=countif(Success == false), LastSeen=max(EventTime)
    by _ResourceId, Agent, AgentKey, Tool, ToolType, ExplicitMcp, ExecutionEvidence, ServerDisplay, TargetHost` },
  { key: "CustomMcpRuntimeInventory", name: "Custom Agents - Explicit MCP and heuristic metadata candidates",
    description: "Keeps explicit MCP evidence separate from name-only candidates. Missing server identity or an empty approval list remains an explicit coverage state.",
    query: `${spans}
| where ExplicitMcp or McpNameHint
| extend Evidence=case(ExplicitMcp and IsTool, 'Explicit MCP tool-execution operation',
    ExplicitMcp, 'Explicit MCP metadata without tool-execution operation', 'Name-only candidate; not MCP proof')
| summarize Records=count(), LastSeen=max(EventTime) by _ResourceId, Agent, AgentKey,
    Tool, Evidence, ServerDisplay, TargetHost, Approval, CommandCapable` },
  { key: "CustomMcpDeclaredConfiguration", name: "Custom Agents - Declared MCP configuration",
    description: "Requires useAgentInventory=true and AgentsInfo.McpServers. Configuration is not execution. Empty SDK-only inventory is an unsupported evidence plane, not no configured servers.",
    query: `CustomAgentInventory()
| where Custom and not(Managed)
| mv-expand Server=McpServers
| extend ServerName=coalesce(tostring(Server.name), tostring(Server.serverLabel)),
    Host=tostring(parse_url(coalesce(tostring(Server.url), tostring(Server.endpoint))).Host)
| project Snapshot, InventoryId, InventoryAgent, Platform, ServerName, Host` },
  { key: "CustomTraceTimeline", name: "Custom Agents - Custom-attributed trace timeline",
    description: "Unmasked inline prompt/output and raw recorded envelopes. Exact finding-span content wins; same-resource/agent/trace context is labeled with source span IDs. Filter these exact keys for investigation. Missing content is not a passed check.",
    query: `CustomAgentInlineContent(24h)
| project EventTime, _ResourceId, Agent, AgentId, AgentKey, OperationId, SpanId,
    Conversation, Operation, Model, Tool, ServerDisplay, TargetHost, Success, DurationMs, ${evidenceColumns}
| order by EventTime asc
| take 500` },
  { key: "CustomProtectedContentCoverage", name: "Custom Agents - Inline content and role coverage",
    content: true,
    description: "Reports same-span inline role/body coverage, not inherited context. Missing capture or unsupported roles mean unavailable evidence, never that a content detection passed. The stable saved-search ID is retained from the former protected coverage hunt.",
    query: `CustomAgentInlineContent(1h)
| extend HasInputEnvelope=isnotempty(InputMessages) and InputMessages !in ('[]', '{}', 'null'),
    HasOutputEnvelope=isnotempty(OutputMessages) and OutputMessages !in ('[]', '{}', 'null'),
    HasUser=strlen(UserText)>0, HasSystem=strlen(SystemText)>0,
    HasOutput=strlen(OutputText)>0, HasToolResult=ToolResultState == 'Recorded nonempty'
| summarize Spans=count(), InputEnvelopes=countif(HasInputEnvelope), OutputEnvelopes=countif(HasOutputEnvelope),
    UserContent=countif(HasUser == true), SystemContent=countif(HasSystem == true),
    OutputContent=countif(HasOutput == true), ToolResults=countif(HasToolResult == true),
    InputNotRecorded=countif(InputParseState == 'Not recorded'),
    InputEmpty=countif(InputParseState == 'Recorded empty'),
    InputUnstructured=countif(InputParseState == 'Unstructured; user role unverified'),
    InputWithoutUserText=countif(InputParseState startswith 'Recorded;' or InputParseState startswith 'No user role'),
    OutputNotRecorded=countif(OutputParseState == 'Not recorded'),
    OutputEmpty=countif(OutputParseState == 'Recorded empty'),
    OutputWithoutAssistantText=countif(OutputParseState startswith 'Recorded;'),
    ToolSpans=countif(IsTool),
    ToolsWithArguments=countif(IsTool and ToolArgumentsState == 'Recorded nonempty'),
    ToolsWithResults=countif(IsTool and ToolResultState == 'Recorded nonempty')
    by _ResourceId, Agent, AgentKey` },
  { key: "CustomInlineContentSecurityEvidence", name: "Custom Agents - Inline content security evidence",
    content: true,
    description: "Unmasked recorded prompt/output and tool bodies for eight content heuristics. Matches are investigation candidates, not proof of bypass, valid credentials or execution. System/developer text is never user intent.",
    query: `CustomAgentInlineContent(24h)
| extend UserInjection=UserText matches regex @'${injection}',
    SecretInput=UserText matches regex @'${secrets}', SecretOutput=OutputText matches regex @'${secrets}',
    SystemDisclosure=strlen(SystemText) >= 80 and tolower(OutputText) contains tolower(substring(SystemText, 0, 80)),
    ActiveOutput=OutputText matches regex @'${unsafe}', ToolInjection=IsTool and ToolResult matches regex @'${injection}',
    SecretToolArguments=IsTool and ToolArguments matches regex @'${secrets}',
    SecretToolResult=IsTool and ToolResult matches regex @'${secrets}'
| where UserInjection or SecretInput or SecretOutput or SystemDisclosure or ActiveOutput or ToolInjection
    or SecretToolArguments or SecretToolResult
| project EventTime, _ResourceId, Agent, AgentId, AgentKey, OperationId, SpanId, Conversation,
    UserInjection, SecretInput, SecretOutput, SystemDisclosure, ActiveOutput, ToolInjection,
    SecretToolArguments, SecretToolResult, ${evidenceColumns}
| order by EventTime desc
| take 500` },
  { key: "CustomToolContentSecurityEvidence", name: "Custom Agents - Tool argument and result security evidence",
    content: true,
    description: "Observed tool executions with credential-shaped bodies or instruction-override candidates in arguments/results. Argument instructions alone are not indirect-result injection proof. Includes unmasked bodies and labeled prompt/output context.",
    query: `CustomAgentInlineContent(24h)
| where IsTool
| extend SecretArguments=ToolArguments matches regex @'${secrets}', SecretResult=ToolResult matches regex @'${secrets}',
    ArgumentInjection=ToolArguments matches regex @'${injection}', ResultInjection=ToolResult matches regex @'${injection}'
| where SecretArguments or SecretResult or ArgumentInjection or ResultInjection
| project EventTime, _ResourceId, Agent, AgentId, AgentKey, OperationId, SpanId, Tool, ServerDisplay, TargetHost,
    SecretArguments, SecretResult, ArgumentInjection, ResultInjection, ${evidenceColumns}
| order by EventTime desc
| take 500` },
  { key: "CustomInlineContentGaps", name: "Custom Agents - Inline capture and parsing gaps",
    description: "Same-span diagnostics distinguish not recorded, recorded empty, unverified input role and recorded-but-unparsed output. Does not expose bodies or infer that capture is disabled. A gap or empty field is not a passed safety check.",
    query: `CustomAgentInlineContent(24h)
| where InputParseState != 'Parsed user role' or OutputParseState != 'Parsed assistant/text'
    or (IsTool and (ToolArgumentsState != 'Recorded nonempty' or ToolResultState != 'Recorded nonempty'
        or isnull(DurationMs) or DurationMs < 0))
| project EventTime, _ResourceId, Agent, AgentId, AgentKey, OperationId, SpanId, Operation, Tool,
    InputParseState, OutputParseState, ToolArgumentsState, ToolResultState,
    TimingAvailable=isnotnull(DurationMs) and DurationMs >= 0
| order by EventTime desc
| take 500` },
  { key: "CustomIndirectInjectionOutputEvidence", name: "Custom Agents - Indirect-injection and risky-output chain evidence",
    content: true,
    description: "24-hour hunt using the exact scheduled indirect-result/output predicate and evidence projection. Returns triggering tool result/end time and risky model output; not proof of causation. Both events must be inside the lookback and at most ten minutes apart.",
    query: rules.find((r) => r.key === "CustomToolResultRiskyOutputChain").query
      .replace("CustomAgentInlineContent(1h)", "CustomAgentInlineContent(24h)") + "| take 500" },
  { key: "CustomGuardrailOutcomes", name: "Custom Agents - Explicit control outcomes",
    description: "Recorded blocks, evaluation unavailability and absent explicit verdicts remain separate. No block is not equivalent to allowed or safe.",
    query: `${spans}
| summarize Blocked=max(toint(Blocked)), Unavailable=max(toint(EvaluationUnavailable))
    by _ResourceId, OperationId, AgentKey, Agent
| extend Outcome=case(Unavailable > 0, 'Evaluation unavailable; inspect controls',
    Blocked > 0, 'Explicit recorded block', 'No explicit verdict; inconclusive')
| summarize Traces=count() by Agent, AgentKey, Outcome` },
].map((hunt) => ({ ...hunt, id: stableId(hunt.key), content: Boolean(hunt.content) }));

export function readFunction(name) {
  return fs.readFileSync(path.join(directory, "Functions", `${name}.kql`), "utf8").trim();
}
function yaml(object) {
  return Object.entries(object).map(([key, value]) => typeof value === "string" && value.includes("\n")
    ? `${key}: |\n${value.trimEnd().split("\n").map((line) => `  ${line}`).join("\n")}`
    : `${key}: ${JSON.stringify(value)}`).join("\n") + "\n";
}
const resourceId = (type, id) => `[resourceId('${type}', parameters('workspaceName'), '${id}')]`;
const searchType = "Microsoft.OperationalInsights/workspaces/savedSearches";
export function buildPack() {
  const resources = [];
  const write = (relative, text) => {
    const target = path.join(directory, relative);
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, text, "utf8");
  };
  const functionNames = ["CustomAgentInventory", "CustomAgentSpans", "CustomAgentInlineContent"];
  const functionId = (name) => stableId(`function:${name}`);
  const watchlists = ["CustomAgentScope", "CustomAgentApprovedMcpTargets"];
  for (const alias of watchlists) {
    const definition = JSON.parse(fs.readFileSync(path.join(directory, "Watchlists", alias, "watchlist.json"), "utf8"));
    resources.push({
      type: "Microsoft.OperationalInsights/workspaces/providers/watchlists",
      apiVersion: "2023-12-01-preview",
      name: `[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/${alias}')]`,
      properties: { displayName: definition.displayName, description: definition.description,
        provider: definition.provider, itemsSearchKey: definition.itemsSearchKey,
        source: `${alias}.csv`, contentType: "text/csv", numberOfLinesToSkip: 0,
        rawContent: fs.readFileSync(path.join(directory, "Watchlists", alias, "data.csv"), "utf8") },
    });
  }
  for (const name of functionNames) {
    const dependencies = name === "CustomAgentInventory" ? [] :
      [resourceId(searchType, functionId(name === "CustomAgentSpans" ? "CustomAgentInventory" : "CustomAgentSpans"))];
    if (name === "CustomAgentSpans") {
      for (const alias of watchlists) dependencies.push(
        `[resourceId('Microsoft.OperationalInsights/workspaces/providers/watchlists', parameters('workspaceName'), 'Microsoft.SecurityInsights', '${alias}')]`);
    }
    resources.push({
      type: searchType, apiVersion: "2022-10-01",
      name: `[concat(parameters('workspaceName'), '/${functionId(name)}')]`,
      dependsOn: dependencies,
      properties: { displayName: name, category: "Custom Agent Detection Functions",
        functionAlias: name, functionParameters: name === "CustomAgentInventory" ? "" : "lookback:timespan",
        query: name === "CustomAgentInventory"
          ? "[if(parameters('useAgentInventory'), variables('inventoryQuery'), variables('sdkOnlyInventoryQuery'))]"
          : readFunction(name), version: 1 },
    });
  }
  for (const item of rules) {
    const metadata = {
      id: item.id, name: item.name, description: item.description, severity: item.severity,
      requiredDataConnectors: [{ connectorId: "ApplicationInsights", dataTypes: ["AppRequests", "AppDependencies"] }],
      queryFrequency: "PT1H", queryPeriod: "P14D", triggerOperator: "gt", triggerThreshold: 0,
      enabled: false, tactics: item.tactics, relevantTechniques: [], query: item.query,
      entityMappings: [
        { entityType: "AzureResource", fieldMappings: [{ identifier: "ResourceId", columnName: "ResourceId" }] },
        { entityType: "CloudApplication", fieldMappings: [{ identifier: "Name", columnName: "Agent" }] },
      ],
      customDetails: { AgentId: "AgentId", AgentKey: "AgentKey", TraceId: "TraceId",
        SpanId: "SpanId", Conversation: "Conversation", ResourceId: "ResourceId", Signal: "Signal",
        Prompt: "PromptPreview", Output: "OutputPreview", EvidenceStatus: "EvidencePreviewStatus" },
      eventGroupingSettings: { aggregationKind: "AlertPerResult" },
      incidentConfiguration: { createIncident: true, groupingConfiguration: {
        enabled: true, reopenClosedIncident: false, lookbackDuration: "PT1H",
        matchingMethod: "Selected", groupByEntities: [], groupByAlertDetails: [],
        groupByCustomDetails: ["AgentKey", "ResourceId"],
      } },
      version: "1.2.0", kind: "Scheduled",
      tags: ["Sentinel-As-Code", "Custom", "AI", "Custom-Agents", "Inline-Unmasked-Evidence"],
    };
    write(path.join("AnalyticalRules", `${item.key}.yaml`), yaml(metadata));
    resources.push({
      type: "Microsoft.OperationalInsights/workspaces/providers/alertRules", apiVersion: "2023-12-01-preview",
      name: `[concat(parameters('workspaceName'), '/Microsoft.SecurityInsights/${item.id}')]`, kind: "Scheduled",
      ...(item.content ? { condition: "[parameters('deployContentDetections')]" } : {}),
      dependsOn: [resourceId(searchType, functionId("CustomAgentInlineContent"))],
      properties: {
        displayName: item.name, description: item.description, severity: item.severity,
        enabled: "[parameters('enableAnalyticRules')]", query: item.query,
        queryFrequency: metadata.queryFrequency, queryPeriod: metadata.queryPeriod,
        triggerOperator: "GreaterThan", triggerThreshold: 0,
        suppressionDuration: "PT1H", suppressionEnabled: false, tactics: item.tactics, techniques: [],
        entityMappings: metadata.entityMappings, customDetails: metadata.customDetails,
        eventGroupingSettings: metadata.eventGroupingSettings, incidentConfiguration: metadata.incidentConfiguration,
      },
    });
  }
  for (const item of hunts) {
    write(path.join("HuntingQueries", `${item.key}.yaml`), yaml({
      id: item.id, name: item.name, description: item.description, query: item.query + "\n",
      tactics: [], techniques: [], tags: ["Sentinel-As-Code", "Custom", "Custom-Agents"],
    }));
    resources.push({
      type: searchType, apiVersion: "2022-10-01",
      name: `[concat(parameters('workspaceName'), '/${item.id}')]`,
      ...(item.content ? { condition: "[parameters('deployContentDetections')]" } : {}),
      dependsOn: [resourceId(searchType, functionId("CustomAgentInlineContent"))],
      properties: { category: "Hunting Queries", displayName: item.name, query: item.query, version: 2,
        tags: [{ name: "description", value: item.description.slice(0, 255) }] },
    });
  }
  const template = {
    $schema: "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    contentVersion: "1.0.0.0",
    metadata: { description: "Custom-only SDK agent detections; inline-only unmasked SOC evidence; disabled by default." },
    parameters: {
      workspaceName: { type: "string", minLength: 1, metadata: { description: "Target Sentinel workspace name in this deployment resource group." } },
      enableAnalyticRules: { type: "bool", defaultValue: false },
      deployContentDetections: { type: "bool", defaultValue: false,
        metadata: { description: `Deploy ${rules.filter((r) => r.content).length} inline-content analytics and ${hunts.filter((h) => h.content).length} content hunts. All analytics include unmasked inline prompt/output evidence. Requires approved capture and appropriate analyst access; never reads AppGenAIContent.` } },
      useAgentInventory: { type: "bool", defaultValue: false,
        metadata: { description: "Query an ingested AgentsInfo copy for classification and declared MCP configuration. False is SDK-only mode with no reference to that table in the deployed inventory function." } },
    },
    variables: { inventoryQuery: readFunction("CustomAgentInventory"),
      sdkOnlyInventoryQuery: readFunction("CustomAgentInventory.Disabled") },
    resources,
    outputs: {
      analyticRuleCount: { type: "int", value: `[if(parameters('deployContentDetections'), ${rules.length}, ${rules.filter((r) => !r.content).length})]` },
      huntingQueryCount: { type: "int", value: `[if(parameters('deployContentDetections'), ${hunts.length}, ${hunts.filter((h) => !h.content).length})]` },
      analyticRulesEnabled: { type: "bool", value: "[parameters('enableAnalyticRules')]" },
    },
  };
  write(path.join("Deploy", "azuredeploy.json"), JSON.stringify(template, null, 2) + "\n");
  write(path.join("Deploy", "azuredeploy.parameters.json"), JSON.stringify({
    $schema: "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
    contentVersion: "1.0.0.0", parameters: {
      workspaceName: { value: "<target-sentinel-workspace>" },
      enableAnalyticRules: { value: false }, deployContentDetections: { value: false },
      useAgentInventory: { value: false },
    },
  }, null, 2) + "\n");
  console.log(`Custom Agents: generated ${rules.length} disabled analytics, ${hunts.length} hunts, 3 functions and 2 watchlists.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) buildPack();
