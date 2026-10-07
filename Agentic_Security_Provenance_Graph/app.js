const NS = "http://www.w3.org/2000/svg";

const TYPE_COLORS = {
  source: "#71a7ff",
  behavior: "#ae8cff",
  action: "#ff8faf",
  control: "#ffb45c",
  entity: "#8bc8ff",
  telemetry: "#54e1c1",
  parameter: "#f0cf65",
  detection: "#4be48e",
  validation: "#55d3ff",
  finding: "#ff7b83",
  output: "#c5f467",
  technique: "#d7a5ff"
};

const EVIDENCE_COLORS = {
  exact: "#4be48e",
  correlated: "#f0cf65",
  contextual: "#55b6ff",
  conflict: "#ff5d6c"
};

const EVIDENCE_LABELS = {
  exact: "Exact",
  correlated: "Correlated",
  contextual: "Contextual",
  conflict: "Conflict"
};

const state = {
  graph: null,
  selectedId: null,
  enabledTypes: new Set(),
  search: "",
  viewBox: { x: 0, y: 0, width: 1800, height: 900 },
  baseViewBox: { x: 0, y: 0, width: 1800, height: 900 },
  drag: null
};

const svg = document.querySelector("#graph-svg");
const details = document.querySelector("#details");
const message = document.querySelector("#graph-message");

async function loadDefaultGraph() {
  const requestedFile = new URLSearchParams(location.search).get("graph") || "graph-data.json";
  // Only allow a bare filename in this folder -- reject paths that could escape it (e.g. "../secret.json", "/etc/passwd").
  const safeFile = /^[\w.-]+\.json$/.test(requestedFile) ? requestedFile : "graph-data.json";
  try {
    const response = await fetch(safeFile);
    if (!response.ok) {
      throw new Error(`${safeFile} returned ${response.status}`);
    }
    loadGraph(await response.json());
  } catch (error) {
    showError(
      `Unable to load ${safeFile}: ${error.message}. Serve this folder with a local web server or open the published GitHub Pages site.`
    );
  }
}

function loadGraph(graph) {
  const issues = validateGraph(graph);
  if (issues.length) {
    throw new Error(issues.join(" "));
  }

  state.graph = graph;
  state.selectedId = null;
  state.enabledTypes = new Set(graph.nodes.map((node) => node.type));
  state.search = "";
  document.querySelector("#search").value = "";
  message.hidden = true;
  updateMetadata();
  buildFilters();
  renderGraph();
  renderEmptyDetails();
}

function validateGraph(graph) {
  const issues = [];
  if (!graph || typeof graph !== "object") return ["Graph must be an object."];
  if (!Array.isArray(graph.stages) || !graph.stages.length) issues.push("At least one stage is required.");
  if (!Array.isArray(graph.nodes) || !graph.nodes.length) issues.push("At least one node is required.");
  if (!Array.isArray(graph.edges)) issues.push("Edges must be an array.");
  if (issues.length) return issues;

  const stageIds = new Set(graph.stages.map((stage) => stage.id));
  const nodeIds = new Set();
  for (const node of graph.nodes) {
    if (!node.id || !node.type || !node.stage || !node.label) {
      issues.push("Every node requires id, type, stage, and label.");
    }
    if (nodeIds.has(node.id)) issues.push(`Duplicate node ID: ${node.id}.`);
    nodeIds.add(node.id);
    if (!stageIds.has(node.stage)) issues.push(`Node ${node.id} references unknown stage ${node.stage}.`);
  }
  const edgeIds = new Set();
  for (const edge of graph.edges) {
    if (edgeIds.has(edge.id)) issues.push(`Duplicate edge ID: ${edge.id}.`);
    edgeIds.add(edge.id);
    if (!nodeIds.has(edge.from) || !nodeIds.has(edge.to)) {
      issues.push(`Edge ${edge.id} references an unknown node.`);
    }
  }
  return issues;
}

function updateMetadata() {
  const { metadata, nodes, edges, stages } = state.graph;
  document.querySelector("#subtitle").textContent = metadata.description;
  document.querySelector("#deployment-status").textContent = metadata.deploymentStatus.replaceAll("-", " ");
  document.querySelector("#status-reason").textContent = metadata.statusReason || "";
  document.querySelector("#node-count").textContent = nodes.length;
  document.querySelector("#edge-count").textContent = edges.length;
  document.querySelector("#stage-count").textContent = stages.length;
  document.title = metadata.title;
}

function buildFilters() {
  const container = document.querySelector("#filter-list");
  container.replaceChildren();
  const counts = Map.groupBy(state.graph.nodes, (node) => node.type);

  for (const [type, nodes] of [...counts].sort(([a], [b]) => a.localeCompare(b))) {
    const label = document.createElement("label");
    label.className = "filter-item";
    label.style.setProperty("--node-color", colorFor(type));
    label.innerHTML = `
      <input type="checkbox" value="${escapeHtml(type)}" checked>
      <span class="type-dot" aria-hidden="true"></span>
      <span>${escapeHtml(titleCase(type))}</span>
      <span>${nodes.length}</span>
    `;
    label.querySelector("input").addEventListener("change", (event) => {
      if (event.target.checked) state.enabledTypes.add(type);
      else state.enabledTypes.delete(type);
      applyVisibility();
    });
    container.append(label);
  }
}

function renderGraph() {
  const { nodes, edges, stages } = state.graph;
  const layout = calculateLayout(nodes, stages);
  const maxRows = Math.max(...[...layout.values()].map((item) => item.row + 1));
  const width = Math.max(1500, stages.length * 285);
  const height = Math.max(760, maxRows * 135 + 170);
  state.baseViewBox = { x: 0, y: 0, width, height };
  state.viewBox = { ...state.baseViewBox };

  svg.replaceChildren();
  appendSvgMetadata();
  appendDefs();

  const stageLayer = createSvg("g", { class: "stages" });
  stages.forEach((stage, index) => {
    const x = 50 + index * ((width - 100) / stages.length);
    stageLayer.append(
      createSvg("text", { x, y: 38, class: "stage-label" }, stage.label),
      createSvg("line", { x1: x, y1: 55, x2: x, y2: height - 40, class: "stage-line" })
    );
  });
  svg.append(stageLayer);

  const edgeLayer = createSvg("g", { class: "edges" });
  for (const edge of edges) {
    const from = layout.get(edge.from);
    const to = layout.get(edge.to);
    const path = createSvg("path", {
      id: `edge-${edge.id}`,
      class: `edge evidence-${edge.evidenceType}${edge.conditional ? " conditional" : ""}`,
      style: `--evidence-color:${evidenceColorFor(edge.evidenceType)}`,
      d: edgePath(from, to),
      "data-from": edge.from,
      "data-to": edge.to,
      "data-relation": edge.relation,
      "marker-end": "url(#arrow)"
    });
    path.append(createSvg("title", {}, `${edge.relation} [${EVIDENCE_LABELS[edge.evidenceType] ?? edge.evidenceType}]: ${edge.description}`));
    edgeLayer.append(path);
  }
  svg.append(edgeLayer);

  const nodeLayer = createSvg("g", { class: "nodes" });
  for (const node of nodes) {
    nodeLayer.append(renderNode(node, layout.get(node.id)));
  }
  svg.append(nodeLayer);
  setViewBox();
  applyVisibility();
}

function appendSvgMetadata() {
  svg.append(
    createSvg("title", { id: "graph-title" }, state.graph.metadata.title),
    createSvg(
      "desc",
      { id: "graph-description" },
      "A directed graph connecting source evidence, threat behavior, agent actions, telemetry, detection logic, findings, and security mappings."
    )
  );
}

function appendDefs() {
  const defs = createSvg("defs");
  const marker = createSvg("marker", {
    id: "arrow",
    viewBox: "0 0 10 10",
    refX: 9,
    refY: 5,
    markerWidth: 6,
    markerHeight: 6,
    orient: "auto-start-reverse"
  });
  marker.append(createSvg("path", { d: "M 0 0 L 10 5 L 0 10 z", fill: "context-stroke" }));
  defs.append(marker);
  svg.append(defs);
}

function calculateLayout(nodes, stages) {
  const stageOrder = new Map(stages.map((stage, index) => [stage.id, index]));
  const grouped = Map.groupBy(nodes, (node) => node.stage);
  const width = Math.max(1500, stages.length * 285);
  const columnWidth = (width - 100) / stages.length;
  const layout = new Map();

  for (const [stageId, stageNodes] of grouped) {
    const column = stageOrder.get(stageId);
    stageNodes.forEach((node, row) => {
      layout.set(node.id, {
        x: 50 + column * columnWidth + 18,
        y: 75 + row * 135,
        width: Math.min(225, columnWidth - 36),
        height: 88,
        row,
        column
      });
    });
  }
  return layout;
}

function edgePath(from, to) {
  const startX = from.x + from.width;
  const startY = from.y + from.height / 2;
  const endX = to.x;
  const endY = to.y + to.height / 2;

  if (to.column > from.column) {
    const control = Math.max(45, (endX - startX) * 0.52);
    return `M ${startX} ${startY} C ${startX + control} ${startY}, ${endX - control} ${endY}, ${endX} ${endY}`;
  }

  const arcX = Math.max(startX, endX) + 38 + Math.abs(from.row - to.row) * 10;
  return `M ${startX} ${startY} C ${arcX} ${startY}, ${arcX} ${endY}, ${endX} ${endY}`;
}

function renderNode(node, position) {
  const group = createSvg("g", {
    id: `node-${node.id}`,
    class: "node",
    transform: `translate(${position.x} ${position.y})`,
    tabindex: "0",
    role: "button",
    "aria-label": `${node.label}, ${node.type}, ${node.confidence} confidence`,
    "data-id": node.id,
    "data-type": node.type,
    style: `--node-color:${colorFor(node.type)}`
  });
  group.append(
    createSvg("rect", { width: position.width, height: position.height, rx: 12 }),
    createSvg("rect", { class: "node-accent", width: 4, height: position.height, rx: 2 }),
    createSvg("text", { class: "node-type", x: 16, y: 20 }, node.type),
    ...wrappedText(node.label, position.width - 30, 13).map((line, index) =>
      createSvg("text", { class: "node-label", x: 16, y: 43 + index * 16 }, line)
    ),
    createSvg("text", { class: "node-confidence", x: 16, y: position.height - 10 }, `${node.confidence} confidence`)
  );
  group.addEventListener("click", (event) => {
    event.stopPropagation();
    selectNode(node.id);
  });
  group.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      selectNode(node.id);
    }
  });
  return group;
}

function wrappedText(text, maxWidth, fontSize) {
  const maxCharacters = Math.max(12, Math.floor(maxWidth / (fontSize * 0.58)));
  const words = text.split(/\s+/);
  const lines = [];
  let line = "";
  for (const word of words) {
    const candidate = line ? `${line} ${word}` : word;
    if (candidate.length > maxCharacters && line) {
      lines.push(line);
      line = word;
    } else {
      line = candidate;
    }
  }
  if (line) lines.push(line);
  if (lines.length > 2) {
    lines[1] = `${lines.slice(1).join(" ").slice(0, maxCharacters - 1)}…`;
    return lines.slice(0, 2);
  }
  return lines;
}

function applyVisibility() {
  if (!state.graph) return;
  const term = state.search.trim().toLowerCase();
  const visibleIds = new Set();

  for (const node of state.graph.nodes) {
    const searchable = [node.label, node.description, node.type, ...node.evidence].join(" ").toLowerCase();
    const visible = state.enabledTypes.has(node.type) && (!term || searchable.includes(term));
    document.querySelector(`#node-${CSS.escape(node.id)}`).classList.toggle("hidden", !visible);
    if (visible) visibleIds.add(node.id);
  }

  for (const edge of state.graph.edges) {
    const visible = visibleIds.has(edge.from) && visibleIds.has(edge.to);
    document.querySelector(`#edge-${CSS.escape(edge.id)}`).classList.toggle("hidden", !visible);
  }

  document.querySelector("#visible-count").textContent = visibleIds.size;
  if (state.selectedId && !visibleIds.has(state.selectedId)) clearSelection();
  else updateHighlights();
}

function selectNode(id) {
  state.selectedId = state.selectedId === id ? null : id;
  updateHighlights();
  if (state.selectedId) renderDetails(state.graph.nodes.find((node) => node.id === id));
  else renderEmptyDetails();
}

function clearSelection() {
  state.selectedId = null;
  updateHighlights();
  renderEmptyDetails();
}

function updateHighlights() {
  const related = new Set();
  if (state.selectedId) {
    related.add(state.selectedId);
    for (const edge of state.graph.edges) {
      if (edge.from === state.selectedId) related.add(edge.to);
      if (edge.to === state.selectedId) related.add(edge.from);
    }
  }

  document.querySelectorAll(".node").forEach((element) => {
    const id = element.dataset.id;
    element.classList.toggle("selected", id === state.selectedId);
    element.classList.toggle("dimmed", Boolean(state.selectedId) && !related.has(id));
  });
  document.querySelectorAll(".edge").forEach((element) => {
    const active = element.dataset.from === state.selectedId || element.dataset.to === state.selectedId;
    element.classList.toggle("active", active);
    element.classList.toggle("dimmed", Boolean(state.selectedId) && !active);
  });
}

function renderDetails(node) {
  const relations = state.graph.edges.filter((edge) => edge.from === node.id || edge.to === node.id);
  details.style.setProperty("--node-color", colorFor(node.type));
  details.innerHTML = `
    <p class="eyebrow">Selection</p>
    <h2>${escapeHtml(node.label)}</h2>
    <span class="badge">${escapeHtml(node.type)} · ${escapeHtml(node.confidence)} confidence</span>
    <p>${escapeHtml(node.description)}</p>
    <h3>Evidence</h3>
    <ul>${node.evidence.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    <h3>Direct relations</h3>
    <ul class="relation-list">
      ${relations.map((edge) => relationMarkup(edge, node.id)).join("") || "<li>No direct relations.</li>"}
    </ul>
  `;
}

function relationMarkup(edge, selectedId) {
  const outgoing = edge.from === selectedId;
  const otherId = outgoing ? edge.to : edge.from;
  const other = state.graph.nodes.find((node) => node.id === otherId);
  const arrow = outgoing ? "→" : "←";
  const evidenceLabel = EVIDENCE_LABELS[edge.evidenceType] ?? edge.evidenceType;
  return `
    <li style="--evidence-color:${evidenceColorFor(edge.evidenceType)}">
      <strong>${arrow} ${escapeHtml(edge.relation)}</strong>
      <span class="evidence-chip">${escapeHtml(evidenceLabel)}</span>
      ${edge.conditional ? '<span class="evidence-chip conditional-chip">Conditional</span>' : ""}
      <span>${escapeHtml(other.label)} · ${escapeHtml(edge.evidence)}</span>
    </li>
  `;
}

function renderEmptyDetails() {
  details.removeAttribute("style");
  details.innerHTML = `
    <p class="eyebrow">Selection</p>
    <h2>Choose a node</h2>
    <p>Select any node to inspect its evidence and direct relationships.</p>
    <h3>How to read this graph</h3>
    <p>Follow arrows from the source claim through observed actions and telemetry. Dashed relations depend on an unobserved condition. Red findings expose evidence gaps or conflicting conclusions.</p>
  `;
}

function setViewBox() {
  const box = state.viewBox;
  svg.setAttribute("viewBox", `${box.x} ${box.y} ${box.width} ${box.height}`);
}

function zoom(factor, centerX = 0.5, centerY = 0.5) {
  const old = state.viewBox;
  const nextWidth = Math.min(state.baseViewBox.width * 2, Math.max(420, old.width * factor));
  const nextHeight = nextWidth * (old.height / old.width);
  state.viewBox = {
    x: old.x + (old.width - nextWidth) * centerX,
    y: old.y + (old.height - nextHeight) * centerY,
    width: nextWidth,
    height: nextHeight
  };
  setViewBox();
}

function showError(text) {
  message.textContent = text;
  message.hidden = false;
}

function createSvg(name, attributes = {}, text = "") {
  const element = document.createElementNS(NS, name);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, value);
  if (text) element.textContent = text;
  return element;
}

function colorFor(type) {
  return TYPE_COLORS[type] || "#94a9c2";
}

function evidenceColorFor(evidenceType) {
  return EVIDENCE_COLORS[evidenceType] || "#94a9c2";
}

function titleCase(value) {
  return value.replaceAll("-", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

document.querySelector("#search").addEventListener("input", (event) => {
  state.search = event.target.value;
  applyVisibility();
});

document.querySelector("#show-all").addEventListener("click", () => {
  state.enabledTypes = new Set(state.graph.nodes.map((node) => node.type));
  document.querySelectorAll("#filter-list input").forEach((input) => {
    input.checked = true;
  });
  applyVisibility();
});

document.querySelector("#zoom-in").addEventListener("click", () => zoom(0.8));
document.querySelector("#zoom-out").addEventListener("click", () => zoom(1.25));
document.querySelector("#reset-view").addEventListener("click", () => {
  state.viewBox = { ...state.baseViewBox };
  setViewBox();
});

document.querySelector("#load-trigger").addEventListener("click", () => document.querySelector("#file-input").click());
document.querySelector("#file-input").addEventListener("change", async (event) => {
  const [file] = event.target.files;
  if (!file) return;
  try {
    loadGraph(JSON.parse(await file.text()));
  } catch (error) {
    showError(`Unable to load ${file.name}: ${error.message}`);
  } finally {
    event.target.value = "";
  }
});

document.querySelector("#download").addEventListener("click", () => {
  if (!state.graph) return;
  const blob = new Blob([`${JSON.stringify(state.graph, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = "graph-data.json";
  anchor.click();
  URL.revokeObjectURL(url);
});

svg.addEventListener("click", clearSelection);
svg.addEventListener("wheel", (event) => {
  event.preventDefault();
  const rect = svg.getBoundingClientRect();
  zoom(event.deltaY > 0 ? 1.1 : 0.9, (event.clientX - rect.left) / rect.width, (event.clientY - rect.top) / rect.height);
}, { passive: false });

svg.addEventListener("pointerdown", (event) => {
  if (event.target.closest(".node")) return;
  svg.setPointerCapture(event.pointerId);
  state.drag = { x: event.clientX, y: event.clientY, viewBox: { ...state.viewBox } };
  svg.classList.add("dragging");
});

svg.addEventListener("pointermove", (event) => {
  if (!state.drag) return;
  const rect = svg.getBoundingClientRect();
  state.viewBox.x = state.drag.viewBox.x - (event.clientX - state.drag.x) * (state.drag.viewBox.width / rect.width);
  state.viewBox.y = state.drag.viewBox.y - (event.clientY - state.drag.y) * (state.drag.viewBox.height / rect.height);
  setViewBox();
});

function endDrag() {
  state.drag = null;
  svg.classList.remove("dragging");
}

svg.addEventListener("pointerup", endDrag);
svg.addEventListener("pointercancel", endDrag);

loadDefaultGraph();
