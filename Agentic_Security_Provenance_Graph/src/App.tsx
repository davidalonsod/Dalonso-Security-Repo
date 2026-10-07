import { useEffect, useMemo, useRef, useState } from "react";
import {
  BookOpen,
  Download,
  FileJson,
  Info,
  Network,
  RotateCcw,
  Search,
  ShieldAlert,
  TableProperties,
  Upload
} from "lucide-react";
import evidenceGraphJson from "../graph-data.json";
import actionGraphJson from "../action-provenance-finance-agent.json";
import { GraphCanvas } from "./components/GraphCanvas";
import { NodeInspector } from "./components/NodeInspector";
import { TableCatalog } from "./components/TableCatalog";
import { downloadJson, nodeColors, searchableNode, validateGraph } from "./lib/graph";
import type { ProvenanceGraph } from "./types";

type View = "graph" | "tables" | "about";
type BuiltInGraph = "evidence" | "action";

const evidenceGraph = evidenceGraphJson as ProvenanceGraph;
const actionGraph = actionGraphJson as ProvenanceGraph;
const importedStorageKey = "agent-provenance.imported-graph.v1";

function loadImportedGraph(): ProvenanceGraph | null {
  try {
    const stored = localStorage.getItem(importedStorageKey);
    if (!stored) return null;
    const graph = JSON.parse(stored) as ProvenanceGraph;
    return validateGraph(graph).length === 0 ? graph : null;
  } catch {
    return null;
  }
}

function defaultGraphKey(): BuiltInGraph {
  return new URLSearchParams(location.search).get("graph")?.includes("action")
    ? "action"
    : "evidence";
}

export default function App() {
  const [activeView, setActiveView] = useState<View>("graph");
  const [selectedGraph, setSelectedGraph] = useState<BuiltInGraph | "imported">(
    defaultGraphKey
  );
  const [importedGraph, setImportedGraph] = useState<ProvenanceGraph | null>(
    loadImportedGraph
  );
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [enabledTypes, setEnabledTypes] = useState<Set<string>>(new Set());
  const [message, setMessage] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);

  const graph =
    selectedGraph === "action"
      ? actionGraph
      : selectedGraph === "imported" && importedGraph
        ? importedGraph
        : evidenceGraph;

  useEffect(() => {
    setEnabledTypes(new Set(graph.nodes.map((node) => node.type)));
    setSelectedId(null);
    setSearch("");
    document.title = `${graph.metadata.title} · Agentic Security`;
  }, [graph]);

  const typeCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const node of graph.nodes) {
      counts.set(node.type, (counts.get(node.type) ?? 0) + 1);
    }
    return [...counts.entries()].sort(([left], [right]) => left.localeCompare(right));
  }, [graph]);

  const visibleNodes = useMemo(() => {
    const term = search.trim().toLowerCase();
    return graph.nodes.filter(
      (node) =>
        enabledTypes.has(node.type) && (!term || searchableNode(node).includes(term))
    );
  }, [graph, enabledTypes, search]);
  const visibleIds = useMemo(
    () => new Set(visibleNodes.map((node) => node.id)),
    [visibleNodes]
  );
  const visibleEdges = useMemo(
    () =>
      graph.edges.filter(
        (edge) => visibleIds.has(edge.from) && visibleIds.has(edge.to)
      ),
    [graph, visibleIds]
  );
  const selectedNode = graph.nodes.find((node) => node.id === selectedId);

  const importGraph = async (file?: File) => {
    if (!file) return;
    try {
      const value = JSON.parse(await file.text()) as unknown;
      const issues = validateGraph(value);
      if (issues.length > 0) throw new Error(issues.join(" "));
      const next = value as ProvenanceGraph;
      setImportedGraph(next);
      setSelectedGraph("imported");
      localStorage.setItem(importedStorageKey, JSON.stringify(next));
      setMessage(`Loaded ${file.name} locally. No data was uploaded.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to load graph.");
    }
  };

  const selectBuiltInGraph = (key: BuiltInGraph) => {
    setSelectedGraph(key);
    setMessage("");
    const url = new URL(location.href);
    if (key === "action") {
      url.searchParams.set("graph", "action-provenance-finance-agent.json");
    } else {
      url.searchParams.delete("graph");
    }
    history.replaceState(null, "", url);
  };

  const toggleType = (type: string) => {
    setEnabledTypes((current) => {
      const next = new Set(current);
      if (next.has(type)) next.delete(type);
      else next.add(type);
      return next;
    });
  };

  return (
    <div className="app-shell">
      <aside className="app-nav">
        <a className="brand" href="/" aria-label="Agentic Security home">
          <span className="brand-mark">
            <Network size={20} />
          </span>
          <span>
            <strong>Agentic Security</strong>
            <small>Provenance Graph</small>
          </span>
        </a>
        <nav aria-label="Primary">
          <button
            className={activeView === "graph" ? "active" : ""}
            onClick={() => setActiveView("graph")}
          >
            <Network size={17} /> Graph explorer
          </button>
          <button
            className={activeView === "tables" ? "active" : ""}
            onClick={() => setActiveView("tables")}
          >
            <TableProperties size={17} /> Telemetry tables
          </button>
          <button
            className={activeView === "about" ? "active" : ""}
            onClick={() => setActiveView("about")}
          >
            <Info size={17} /> About & offline
          </button>
        </nav>
        <div className="nav-footer">
          <span className="offline-dot" />
          <div>
            <strong>Local-first PWA</strong>
            <small>Files stay in this browser</small>
          </div>
        </div>
      </aside>

      <main className="app-main">
        <div className="validation-banner">
          <ShieldAlert size={17} aria-hidden="true" />
          <span>
            <strong>Not validated against tenant data.</strong> Sample graphs demonstrate
            provenance semantics; verify every source and query before acting.
          </span>
        </div>

        {activeView === "graph" && (
          <section className="graph-view">
            <header className="view-heading graph-heading">
              <div>
                <p className="eyebrow">Security evidence explorer</p>
                <h1>{graph.metadata.title}</h1>
                <p>{graph.metadata.description}</p>
              </div>
              <div className="deployment-card">
                <span>Deployment status</span>
                <strong>{graph.metadata.deploymentStatus.replaceAll("-", " ")}</strong>
                <small>{graph.metadata.statusReason}</small>
              </div>
            </header>

            <div className="graph-toolbar">
              <label className="search-control">
                <Search size={16} />
                <input
                  value={search}
                  onChange={(event) => setSearch(event.target.value)}
                  placeholder="Search nodes, evidence, IDs, stages"
                />
              </label>
              <select
                value={selectedGraph}
                onChange={(event) => {
                  const value = event.target.value as BuiltInGraph | "imported";
                  if (value === "imported") setSelectedGraph(value);
                  else selectBuiltInGraph(value);
                }}
              >
                <option value="evidence">Evidence provenance</option>
                <option value="action">Action provenance</option>
                {importedGraph && <option value="imported">Imported local graph</option>}
              </select>
              <button className="button secondary" onClick={() => fileRef.current?.click()}>
                <Upload size={16} /> Import JSON
              </button>
              <button
                className="button secondary"
                onClick={() => downloadJson("provenance-graph.json", graph)}
              >
                <Download size={16} /> Export
              </button>
              <input
                ref={fileRef}
                type="file"
                hidden
                accept=".json,application/json"
                onChange={(event) => void importGraph(event.target.files?.[0])}
              />
            </div>

            {message && <div className="inline-message">{message}</div>}

            <div className="metric-grid graph-metrics">
              <article className="metric-card">
                <strong>{graph.nodes.length}</strong>
                <span>nodes</span>
              </article>
              <article className="metric-card">
                <strong>{graph.edges.length}</strong>
                <span>relationships</span>
              </article>
              <article className="metric-card">
                <strong>{graph.stages.length}</strong>
                <span>stages</span>
              </article>
              <article className="metric-card">
                <strong>{visibleNodes.length}</strong>
                <span>visible</span>
              </article>
            </div>

            <div className="graph-workspace">
              <aside className="filter-panel">
                <div className="panel-title">
                  <div>
                    <p className="eyebrow">Explore</p>
                    <h2>Node types</h2>
                  </div>
                  <button
                    className="text-button"
                    onClick={() =>
                      setEnabledTypes(new Set(graph.nodes.map((node) => node.type)))
                    }
                  >
                    Show all
                  </button>
                </div>
                <div className="filter-list">
                  {typeCounts.map(([type, count]) => (
                    <label key={type} className="filter-row">
                      <input
                        type="checkbox"
                        checked={enabledTypes.has(type)}
                        onChange={() => toggleType(type)}
                      />
                      <span
                        className="type-dot"
                        style={{ background: nodeColors[type] ?? "#8ca2bd" }}
                      />
                      <span>{type.replaceAll("-", " ")}</span>
                      <strong>{count}</strong>
                    </label>
                  ))}
                </div>
                <div className="evidence-legend">
                  <h3>Evidence strength</h3>
                  <span><i className="legend-line exact" /> Exact native/shared ID</span>
                  <span><i className="legend-line correlated" /> Correlated identity + time</span>
                  <span><i className="legend-line contextual" /> Contextual inference</span>
                  <span><i className="legend-line conflict" /> Conflicting evidence</span>
                </div>
                <button
                  className="button ghost full-width"
                  onClick={() => {
                    setSearch("");
                    setSelectedId(null);
                  }}
                >
                  <RotateCcw size={15} /> Reset investigation
                </button>
              </aside>

              <GraphCanvas
                graph={graph}
                visibleNodes={visibleNodes}
                visibleEdges={visibleEdges}
                selectedId={selectedId}
                onSelect={setSelectedId}
              />
              <NodeInspector graph={graph} node={selectedNode} onSelect={setSelectedId} />
            </div>
          </section>
        )}

        {activeView === "tables" && <TableCatalog />}

        {activeView === "about" && (
          <section className="about-view">
            <div className="view-heading">
              <div>
                <p className="eyebrow">Local-first security investigation</p>
                <h1>About this PWA</h1>
                <p>
                  An installable, offline-capable React application for provenance,
                  identity, telemetry, and evidence exploration.
                </p>
              </div>
            </div>
            <div className="about-grid">
              <article>
                <Network size={22} />
                <h2>Two graph modes</h2>
                <p>
                  Evidence provenance explains why a conclusion is trusted. Action
                  provenance explains what happened during one agent execution.
                </p>
              </article>
              <article>
                <FileJson size={22} />
                <h2>Local JSON workflows</h2>
                <p>
                  Import a schema-compatible graph, investigate it, persist it in this
                  browser, and export it without uploading content to a service.
                </p>
              </article>
              <article>
                <TableProperties size={22} />
                <h2>Complete table catalog</h2>
                <p>
                  Search the monitoring estate and import a local volume, cost, and
                  freshness snapshot from Sentinel or another collection workflow.
                </p>
              </article>
              <article>
                <BookOpen size={22} />
                <h2>Offline installation</h2>
                <p>
                  Build once, serve the generated files, and install the PWA from a
                  supported browser. Cached assets continue to work without connectivity.
                </p>
              </article>
            </div>
            <div className="about-note">
              <h2>Privacy boundary</h2>
              <p>
                Imported graph and table-health files are parsed locally and stored in
                browser storage. Clear site data to remove them. The app has no API,
                telemetry collector, or cloud synchronization endpoint.
              </p>
            </div>
            <div className="about-note">
              <h2>Import examples</h2>
              <p>
                Download the synthetic files, then use <strong>Import JSON</strong> in
                Graph explorer or <strong>Import health snapshot</strong> in Telemetry
                tables.
              </p>
              <div className="example-links">
                <a
                  href="./examples/imports/mcp-data-exfiltration-provenance.json"
                  download
                >
                  <FileJson size={16} /> MCP exfiltration graph
                </a>
                <a href="./examples/imports/table-health-snapshot.json" download>
                  <TableProperties size={16} /> Table health snapshot
                </a>
              </div>
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
