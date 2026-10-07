import { describe, expect, it } from "vitest";
import evidenceGraphJson from "../../graph-data.json";
import actionGraphJson from "../../action-provenance-finance-agent.json";
import importExampleJson from "../../examples/imports/mcp-data-exfiltration-provenance.json";
import type { ProvenanceGraph } from "../types";
import { connectedNodeIds, validateGraph } from "./graph";

describe("provenance graph contract", () => {
  it.each([
    ["evidence", evidenceGraphJson],
    ["action", actionGraphJson],
    ["MCP import example", importExampleJson]
  ])("validates the %s graph", (_, graph) => {
    expect(validateGraph(graph)).toEqual([]);
  });

  it("finds direct relationships in both directions", () => {
    const graph = evidenceGraphJson as ProvenanceGraph;
    const firstEdge = graph.edges[0];
    const connected = connectedNodeIds(firstEdge.from, graph.edges);
    expect(connected.has(firstEdge.from)).toBe(true);
    expect(connected.has(firstEdge.to)).toBe(true);
  });

  it("rejects an edge with an unknown node", () => {
    const graph = structuredClone(evidenceGraphJson) as ProvenanceGraph;
    graph.edges[0].to = "missing-node";
    expect(validateGraph(graph)).toContain(
      `Edge ${graph.edges[0].id} references an unknown node.`
    );
  });
});
