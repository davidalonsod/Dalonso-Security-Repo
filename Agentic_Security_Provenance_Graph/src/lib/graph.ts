import type {
  EvidenceType,
  ProvenanceEdge,
  ProvenanceGraph,
  ProvenanceNode
} from "../types";

export const nodeColors: Record<string, string> = {
  source: "#6ea8ff",
  behavior: "#ab8bff",
  action: "#ff8cad",
  control: "#ffb55e",
  entity: "#7fc7ff",
  telemetry: "#30d9bc",
  parameter: "#ebc957",
  detection: "#42dc84",
  validation: "#49cfff",
  finding: "#ff707b",
  output: "#b9e95d",
  technique: "#d49cff"
};

export const evidenceColors: Record<EvidenceType, string> = {
  exact: "#42dc84",
  correlated: "#ebc957",
  contextual: "#49aef7",
  conflict: "#ff5867"
};

export function validateGraph(value: unknown): string[] {
  if (!value || typeof value !== "object") return ["Graph must be an object."];
  const graph = value as Partial<ProvenanceGraph>;
  const issues: string[] = [];

  if (!graph.metadata?.title) issues.push("Graph metadata.title is required.");
  if (!Array.isArray(graph.stages) || graph.stages.length === 0) {
    issues.push("At least one stage is required.");
  }
  if (!Array.isArray(graph.nodes) || graph.nodes.length === 0) {
    issues.push("At least one node is required.");
  }
  if (!Array.isArray(graph.edges)) issues.push("Edges must be an array.");
  if (issues.length > 0) return issues;

  const stages = new Set(graph.stages!.map((stage) => stage.id));
  const nodes = new Set<string>();
  for (const node of graph.nodes!) {
    if (!node.id || !node.type || !node.stage || !node.label) {
      issues.push("Every node requires id, type, stage, and label.");
    }
    if (nodes.has(node.id)) issues.push(`Duplicate node ID: ${node.id}.`);
    nodes.add(node.id);
    if (!stages.has(node.stage)) {
      issues.push(`Node ${node.id} references unknown stage ${node.stage}.`);
    }
  }

  const edges = new Set<string>();
  for (const edge of graph.edges!) {
    if (edges.has(edge.id)) issues.push(`Duplicate edge ID: ${edge.id}.`);
    edges.add(edge.id);
    if (!nodes.has(edge.from) || !nodes.has(edge.to)) {
      issues.push(`Edge ${edge.id} references an unknown node.`);
    }
  }
  return issues;
}

export function connectedNodeIds(
  selectedId: string | null,
  edges: ProvenanceEdge[]
): Set<string> {
  const connected = new Set<string>();
  if (!selectedId) return connected;
  connected.add(selectedId);
  for (const edge of edges) {
    if (edge.from === selectedId) connected.add(edge.to);
    if (edge.to === selectedId) connected.add(edge.from);
  }
  return connected;
}

export function searchableNode(node: ProvenanceNode): string {
  return [
    node.id,
    node.type,
    node.stage,
    node.label,
    node.description,
    node.confidence,
    ...node.evidence
  ]
    .join(" ")
    .toLowerCase();
}

export function downloadJson(filename: string, value: unknown): void {
  const blob = new Blob([`${JSON.stringify(value, null, 2)}\n`], {
    type: "application/json"
  });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(url);
}

export function deriveFreshness(lastSeen?: string): {
  label: string;
  tone: "good" | "warning" | "critical" | "unknown";
} {
  if (!lastSeen) return { label: "No snapshot", tone: "unknown" };
  const timestamp = Date.parse(lastSeen);
  if (Number.isNaN(timestamp)) return { label: "Invalid timestamp", tone: "critical" };
  const hours = (Date.now() - timestamp) / 3_600_000;
  if (hours < 2) return { label: "Active", tone: "good" };
  if (hours < 24) return { label: "Delayed", tone: "warning" };
  return { label: "Stale", tone: "critical" };
}
