See ..\..\AnalyticalRules\Parked\README.md for the rationale; the hunting
queries below are parked for the same reason (speculative LLMEventData
fields that do not exist in the live schema).

- CopilotPromptInjectionPatterns.yaml      (superseded by CopilotIndirectPromptInjection analytic)
- CopilotDelegationChainAnomaly.yaml       (no delegation telemetry exposed)
- CopilotHallucinationAndQualityDrift.yaml (no response-quality fields exposed)
- CopilotBiasOrPiiInOutput.yaml            (no raw response text exposed)
