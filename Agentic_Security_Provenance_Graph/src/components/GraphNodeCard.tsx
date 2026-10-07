import { Handle, Position, type NodeProps } from "@xyflow/react";
import { ShieldCheck } from "lucide-react";
import { nodeColors } from "../lib/graph";

export interface GraphNodeData extends Record<string, unknown> {
  label: string;
  nodeType: string;
  confidence: string;
  selected: boolean;
  related: boolean;
  dimmed: boolean;
}

export function GraphNodeCard({ data }: NodeProps) {
  const nodeData = data as GraphNodeData;
  const color = nodeColors[nodeData.nodeType] ?? "#8ca2bd";
  return (
    <article
      className={[
        "graph-node",
        nodeData.selected ? "is-selected" : "",
        nodeData.related ? "is-related" : "",
        nodeData.dimmed ? "is-dimmed" : ""
      ].join(" ")}
      style={{ "--node-color": color } as React.CSSProperties}
    >
      <Handle type="target" position={Position.Left} />
      <span className="graph-node__type">{nodeData.nodeType}</span>
      <strong>{nodeData.label}</strong>
      <span className="graph-node__confidence">
        <ShieldCheck size={13} aria-hidden="true" />
        {nodeData.confidence} confidence
      </span>
      <Handle type="source" position={Position.Right} />
    </article>
  );
}
