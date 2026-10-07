export type Confidence = "low" | "medium" | "high";
export type EvidenceType = "exact" | "correlated" | "contextual" | "conflict";

export interface GraphMetadata {
  title: string;
  description: string;
  source: string;
  generatedAt: string;
  deploymentStatus: "draft" | "requires-tuning" | "ready" | "deployed" | "retired";
  statusReason?: string;
  behaviorCluster?: string;
  detectionId?: string;
}

export interface GraphStage {
  id: string;
  label: string;
}

export interface ProvenanceNode {
  id: string;
  type: string;
  stage: string;
  label: string;
  description: string;
  evidence: string[];
  confidence: Confidence;
}

export interface ProvenanceEdge {
  id: string;
  from: string;
  to: string;
  relation: string;
  description: string;
  evidence: string;
  evidenceType: EvidenceType;
  conditional?: boolean;
}

export interface ProvenanceGraph {
  $schema?: string;
  version: string;
  metadata: GraphMetadata;
  stages: GraphStage[];
  nodes: ProvenanceNode[];
  edges: ProvenanceEdge[];
}

export type TelemetryPlane =
  | "Application Insights"
  | "Microsoft 365"
  | "OpenAI connector"
  | "Defender XDR"
  | "Microsoft Sentinel"
  | "Microsoft Entra"
  | "Agent 365 data lake"
  | "Azure platform";

export type TableRequirement = "Core" | "Conditional" | "Optional" | "Preview";

export interface TelemetryTable {
  name: string;
  plane: TelemetryPlane;
  product: string;
  purpose: string;
  requirement: TableRequirement;
  tier: "Analytics" | "Basic" | "Auxiliary" | "Data lake" | "Advanced Hunting";
  costModel: string;
  freshnessTarget: string;
  sensitive: boolean;
  preview?: boolean;
  keyFields: string[];
}

export interface TableHealthSnapshot {
  table: string;
  events?: number;
  gigabytes?: number;
  lastSeen?: string;
}
