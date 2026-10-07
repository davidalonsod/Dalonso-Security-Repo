import { useMemo, useRef, useState } from "react";
import {
  Database,
  Download,
  FileUp,
  Search,
  ShieldAlert,
  TimerReset
} from "lucide-react";
import { telemetryPlanes, telemetryTables } from "../data/telemetryTables";
import { deriveFreshness, downloadJson } from "../lib/graph";
import type { TableHealthSnapshot } from "../types";

const SNAPSHOT_KEY = "agent-provenance.table-health.v1";

function loadSnapshots(): TableHealthSnapshot[] {
  try {
    const value = localStorage.getItem(SNAPSHOT_KEY);
    return value ? (JSON.parse(value) as TableHealthSnapshot[]) : [];
  } catch {
    return [];
  }
}

function formatNumber(value?: number): string {
  return value === undefined ? "—" : new Intl.NumberFormat().format(value);
}

function formatGigabytes(value?: number): string {
  return value === undefined ? "—" : `${value.toFixed(3)} GB`;
}

export function TableCatalog() {
  const [search, setSearch] = useState("");
  const [plane, setPlane] = useState("All");
  const [snapshots, setSnapshots] = useState<TableHealthSnapshot[]>(loadSnapshots);
  const [message, setMessage] = useState("");
  const fileRef = useRef<HTMLInputElement>(null);
  const snapshotByTable = useMemo(
    () => new Map(snapshots.map((snapshot) => [snapshot.table, snapshot])),
    [snapshots]
  );
  const filtered = useMemo(() => {
    const term = search.trim().toLowerCase();
    return telemetryTables.filter((table) => {
      const matchesPlane = plane === "All" || table.plane === plane;
      const matchesTerm =
        !term ||
        [
          table.name,
          table.plane,
          table.product,
          table.purpose,
          table.tier,
          table.requirement,
          ...table.keyFields
        ]
          .join(" ")
          .toLowerCase()
          .includes(term);
      return matchesPlane && matchesTerm;
    });
  }, [search, plane]);

  const active = telemetryTables.filter((table) => {
    const snapshot = snapshotByTable.get(table.name);
    return deriveFreshness(snapshot?.lastSeen).tone === "good";
  }).length;
  const sensitive = telemetryTables.filter((table) => table.sensitive).length;
  const preview = telemetryTables.filter((table) => table.preview).length;

  const importSnapshot = async (file?: File) => {
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text()) as unknown;
      if (!Array.isArray(parsed)) {
        throw new Error("Snapshot must be a JSON array.");
      }
      const next = parsed.map((item) => {
        if (!item || typeof item !== "object" || !("table" in item)) {
          throw new Error("Every snapshot row requires a table property.");
        }
        return item as TableHealthSnapshot;
      });
      setSnapshots(next);
      localStorage.setItem(SNAPSHOT_KEY, JSON.stringify(next));
      setMessage(`Loaded ${next.length} local table-health records.`);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Unable to import snapshot.");
    }
  };

  return (
    <section className="catalog-view">
      <div className="view-heading">
        <div>
          <p className="eyebrow">Monitoring data estate</p>
          <h1>Telemetry tables</h1>
          <p>
            Complete local catalog of the tables used across the AI-agent workbook,
            provenance graph, and identity-security views.
          </p>
        </div>
        <div className="heading-actions">
          <button className="button secondary" onClick={() => fileRef.current?.click()}>
            <FileUp size={16} /> Import health snapshot
          </button>
          <button
            className="button secondary"
            onClick={() =>
              downloadJson(
                "table-health-template.json",
                telemetryTables.map((table) => ({
                  table: table.name,
                  events: 0,
                  gigabytes: 0,
                  lastSeen: new Date().toISOString()
                }))
              )
            }
          >
            <Download size={16} /> Template
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".json,application/json"
            hidden
            onChange={(event) => void importSnapshot(event.target.files?.[0])}
          />
        </div>
      </div>

      {message && <div className="inline-message">{message}</div>}

      <div className="metric-grid">
        <article className="metric-card">
          <Database size={18} />
          <strong>{telemetryTables.length}</strong>
          <span>cataloged tables</span>
        </article>
        <article className="metric-card">
          <TimerReset size={18} />
          <strong>{active}</strong>
          <span>active in local snapshot</span>
        </article>
        <article className="metric-card">
          <ShieldAlert size={18} />
          <strong>{sensitive}</strong>
          <span>sensitive-data tables</span>
        </article>
        <article className="metric-card">
          <span className="metric-icon">P</span>
          <strong>{preview}</strong>
          <span>preview schemas</span>
        </article>
      </div>

      <div className="catalog-toolbar">
        <label className="search-control">
          <Search size={16} />
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder="Search table, product, purpose, or key field"
          />
        </label>
        <select value={plane} onChange={(event) => setPlane(event.target.value)}>
          <option>All</option>
          {telemetryPlanes.map((value) => (
            <option key={value}>{value}</option>
          ))}
        </select>
        <span className="result-count">{filtered.length} tables</span>
      </div>

      <div className="table-shell">
        <table>
          <thead>
            <tr>
              <th>Table</th>
              <th>Plane</th>
              <th>Purpose</th>
              <th>Requirement</th>
              <th>Tier / cost</th>
              <th>Events</th>
              <th>Volume</th>
              <th>Freshness</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((table) => {
              const snapshot = snapshotByTable.get(table.name);
              const freshness = deriveFreshness(snapshot?.lastSeen);
              return (
                <tr key={table.name}>
                  <td>
                    <strong>{table.name}</strong>
                    <span>{table.product}</span>
                    <small>{table.keyFields.join(" · ")}</small>
                  </td>
                  <td>{table.plane}</td>
                  <td>{table.purpose}</td>
                  <td>
                    <span className={`status-badge requirement-${table.requirement.toLowerCase()}`}>
                      {table.requirement}
                    </span>
                    {table.sensitive && <small>Sensitive</small>}
                  </td>
                  <td>
                    <strong>{table.tier}</strong>
                    <span>{table.costModel}</span>
                  </td>
                  <td>{formatNumber(snapshot?.events)}</td>
                  <td>{formatGigabytes(snapshot?.gigabytes)}</td>
                  <td>
                    <span className={`freshness freshness-${freshness.tone}`}>
                      {freshness.label}
                    </span>
                    <small>{snapshot?.lastSeen ?? `Target ${table.freshnessTarget}`}</small>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </section>
  );
}
