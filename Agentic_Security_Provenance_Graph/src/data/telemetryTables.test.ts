import { describe, expect, it } from "vitest";
import healthSnapshot from "../../examples/imports/table-health-snapshot.json";
import { telemetryTables } from "./telemetryTables";

describe("telemetry table catalog", () => {
  it("contains unique table names", () => {
    const names = telemetryTables.map((table) => table.name);
    expect(new Set(names).size).toBe(names.length);
  });

  it("covers every monitoring plane", () => {
    const planes = new Set(telemetryTables.map((table) => table.plane));
    expect(planes).toEqual(
      new Set([
        "Application Insights",
        "Microsoft 365",
        "OpenAI connector",
        "Defender XDR",
        "Microsoft Sentinel",
        "Microsoft Entra",
        "Agent 365 data lake",
        "Azure platform"
      ])
    );
  });

  it("includes the core Agent ID and runtime tables", () => {
    const names = new Set(telemetryTables.map((table) => table.name));
    for (const name of [
      "UnifiedAgentObservability",
      "EntraAgentIdentities",
      "EntraAgentIdentityBlueprints",
      "EntraAgentIdentityBlueprintPrincipals",
      "EntraAgentUsers",
      "AADServicePrincipalSignInLogs",
      "SecurityAlert"
    ]) {
      expect(names.has(name)).toBe(true);
    }
  });

  it("provides a valid mixed-freshness import example", () => {
    const catalog = new Set(telemetryTables.map((table) => table.name));
    expect(healthSnapshot.length).toBeGreaterThan(15);
    expect(healthSnapshot.every((row) => catalog.has(row.table))).toBe(true);
    expect(healthSnapshot.some((row) => row.events === 0 && !("lastSeen" in row))).toBe(
      true
    );
    expect(healthSnapshot.some((row) => (row.gigabytes ?? 0) > 1)).toBe(true);
  });
});
