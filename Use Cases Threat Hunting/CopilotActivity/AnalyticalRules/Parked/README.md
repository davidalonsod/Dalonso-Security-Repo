# Parked Copilot Content

The YAML files in this folder are intentionally excluded from the deployed
ARM template. The Copilot ARM generator scans `AnalyticalRules\` and
`HuntingQueries\` non-recursively, so anything in `Parked\` is automatically
skipped.

Why these rules are parked
--------------------------

Each parked rule was originally written against speculative field names on
`CopilotActivity.LLMEventData` that turned out **not** to exist in the
schema Microsoft actually exposes (confirmed by direct probing of the live
table). Re-enabling them requires either:

1. Microsoft documenting / shipping the referenced field, or
2. A rewrite onto a different surrogate signal.

| File | Speculative field(s) used | Re-enable when |
|------|---------------------------|----------------|
| `CopilotApiMisuseHighFailureRate.yaml` | `LLMEventData.ResponseStatus`, `.ErrorCode` | A status / error column appears in `CopilotActivity` (or correlate via Graph API audit) |
| `CopilotToxicOrUnsafeOutput.yaml` | `LLMEventData.SafetyVerdict`, `.ResponseClassifications` | Microsoft exposes per-response Content Safety verdicts |
| `CopilotPromptInjectionPatterns.yaml` | `LLMEventData.Prompt` raw text | Superseded by `CopilotIndirectPromptInjection.yaml` (XPIADetected) |
| `CopilotDelegationChainAnomaly.yaml` | `LLMEventData.DelegationChain`, `.OnBehalfOf` | Agent-to-agent delegation telemetry ships |
| `CopilotHallucinationAndQualityDrift.yaml` | `LLMEventData.Response`, `.Citations`, `.ConfidenceScore` | Response-quality fields exposed |
| `CopilotBiasOrPiiInOutput.yaml` | `LLMEventData.Response` raw text | Output text + classifiers exposed |

Do **not** move these back into the active folders without first running
the schema probe (`Testing\Probe-CopilotActivity.kql`) and confirming the
referenced fields exist.
