import { useMemo } from "react";
import {
  Background,
  BackgroundVariant,
  Controls,
  MarkerType,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
  type NodeMouseHandler
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { ProvenanceEdge, ProvenanceGraph, ProvenanceNode } from "../types";
import { connectedNodeIds, evidenceColors, nodeColors } from "../lib/graph";
import { GraphNodeCard, type GraphNodeData } from "./GraphNodeCard";

interface GraphCanvasProps {
  graph: ProvenanceGraph;
  visibleNodes: ProvenanceNode[];
  visibleEdges: ProvenanceEdge[];
  selectedId: string | null;
  onSelect: (id: string | null) => void;
}

const nodeTypes = { provenance: GraphNodeCard };

function layoutNodes(
  graph: ProvenanceGraph,
  visibleNodes: ProvenanceNode[],
  selectedId: string | null,
  edges: ProvenanceEdge[]
): Node<GraphNodeData>[] {
  const stageIndex = new Map(graph.stages.map((stage, index) => [stage.id, index]));
  const rows = new Map<string, number>();
  const connected = connectedNodeIds(selectedId, edges);

  return visibleNodes.map((node) => {
    const row = rows.get(node.stage) ?? 0;
    rows.set(node.stage, row + 1);
    const selected = selectedId === node.id;
    const related = connected.has(node.id) && !selected;
    return {
      id: node.id,
      type: "provenance",
      position: {
        x: (stageIndex.get(node.stage) ?? 0) * 310,
        y: row * 142
      },
      data: {
        label: node.label,
        nodeType: node.type,
        confidence: node.confidence,
        selected,
        related,
        dimmed: Boolean(selectedId) && !selected && !related
      }
    };
  });
}

function layoutEdges(
  visibleEdges: ProvenanceEdge[],
  selectedId: string | null
): Edge[] {
  return visibleEdges.map((edge) => {
    const active = selectedId === edge.from || selectedId === edge.to;
    const color = evidenceColors[edge.evidenceType];
    return {
      id: edge.id,
      source: edge.from,
      target: edge.to,
      label: edge.relation.replaceAll("-", " "),
      animated: active && edge.evidenceType === "exact",
      markerEnd: { type: MarkerType.ArrowClosed, color },
      style: {
        stroke: color,
        strokeWidth: active ? 2.5 : 1.5,
        strokeDasharray: edge.conditional ? "7 5" : undefined,
        opacity: selectedId && !active ? 0.16 : 0.82
      },
      labelStyle: {
        fill: "#9eb1c8",
        fontSize: 10,
        fontWeight: 600
      },
      labelBgStyle: { fill: "#0b1727", fillOpacity: 0.92 }
    };
  });
}

export function GraphCanvas({
  graph,
  visibleNodes,
  visibleEdges,
  selectedId,
  onSelect
}: GraphCanvasProps) {
  const nodes = useMemo(
    () => layoutNodes(graph, visibleNodes, selectedId, visibleEdges),
    [graph, visibleNodes, selectedId, visibleEdges]
  );
  const edges = useMemo(
    () => layoutEdges(visibleEdges, selectedId),
    [visibleEdges, selectedId]
  );
  const handleNodeClick: NodeMouseHandler = (_, node) => {
    onSelect(node.id === selectedId ? null : node.id);
  };

  return (
    <div className="graph-canvas">
      <div className="stage-strip" aria-label="Graph stages">
        {graph.stages.map((stage) => (
          <span key={stage.id}>{stage.label}</span>
        ))}
      </div>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        onNodeClick={handleNodeClick}
        onPaneClick={() => onSelect(null)}
        minZoom={0.25}
        maxZoom={1.8}
        fitView
        fitViewOptions={{ padding: 0.18 }}
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={20}
          size={1}
          color="#25364c"
        />
        <Controls position="bottom-left" showInteractive={false} />
        <MiniMap
          position="bottom-right"
          nodeColor={(node) =>
            nodeColors[(node.data as GraphNodeData).nodeType] ?? "#8ca2bd"
          }
          maskColor="rgba(4, 11, 20, 0.75)"
          pannable
          zoomable
        />
      </ReactFlow>
    </div>
  );
}
