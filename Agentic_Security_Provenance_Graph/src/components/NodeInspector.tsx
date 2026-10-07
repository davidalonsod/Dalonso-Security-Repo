import {
  ArrowDownLeft,
  ArrowUpRight,
  CircleHelp,
  Database,
  ShieldCheck
} from "lucide-react";
import { evidenceColors, nodeColors } from "../lib/graph";
import type { ProvenanceGraph, ProvenanceNode } from "../types";

interface NodeInspectorProps {
  graph: ProvenanceGraph;
  node?: ProvenanceNode;
  onSelect: (id: string) => void;
}

export function NodeInspector({ graph, node, onSelect }: NodeInspectorProps) {
  if (!node) {
    return (
      <aside className="inspector empty-state">
        <CircleHelp size={28} aria-hidden="true" />
        <p className="eyebrow">Selection</p>
        <h2>Choose a node</h2>
        <p>Select a node to inspect its evidence, confidence, and direct relationships.</p>
      </aside>
    );
  }

  const relations = graph.edges.filter(
    (edge) => edge.from === node.id || edge.to === node.id
  );

  return (
    <aside
      className="inspector"
      style={{ "--node-color": nodeColors[node.type] ?? "#8ca2bd" } as React.CSSProperties}
    >
      <p className="eyebrow">Selected node</p>
      <h2>{node.label}</h2>
      <div className="chip-row">
        <span className="chip">{node.type}</span>
        <span className="chip">
          <ShieldCheck size={13} /> {node.confidence}
        </span>
        <span className="chip">{node.stage}</span>
      </div>
      <p>{node.description}</p>

      <section className="inspector-section">
        <h3>
          <Database size={15} /> Evidence
        </h3>
        <ul>
          {node.evidence.map((evidence) => (
            <li key={evidence}>{evidence}</li>
          ))}
        </ul>
      </section>

      <section className="inspector-section">
        <h3>Direct relationships</h3>
        <div className="relation-list">
          {relations.map((edge) => {
            const outgoing = edge.from === node.id;
            const otherId = outgoing ? edge.to : edge.from;
            const other = graph.nodes.find((candidate) => candidate.id === otherId);
            return (
              <button
                key={edge.id}
                type="button"
                className="relation-card"
                onClick={() => onSelect(otherId)}
                style={
                  {
                    "--evidence-color": evidenceColors[edge.evidenceType]
                  } as React.CSSProperties
                }
              >
                <span className="relation-card__title">
                  {outgoing ? <ArrowUpRight size={14} /> : <ArrowDownLeft size={14} />}
                  {edge.relation.replaceAll("-", " ")}
                </span>
                <strong>{other?.label ?? otherId}</strong>
                <small>
                  {edge.evidenceType}
                  {edge.conditional ? " · conditional" : ""}
                </small>
              </button>
            );
          })}
          {relations.length === 0 && <p>No direct relationships.</p>}
        </div>
      </section>
    </aside>
  );
}
