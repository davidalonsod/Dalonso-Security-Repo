// Phase 2: deterministic Agent Effective Access evaluator.
//
// Reads a Phase 1 canonical access model (access-graph/schema/access-model-schema.json)
// and computes an evaluation report (access-graph/schema/access-model-evaluation-schema.json):
//   - resolved EFFECTIVE permissions per agent identity, with provenance (which grant
//     types contributed), status (effective / blocked / incomplete-resource-grant),
//     and three reach tiers (theoretical / configured / observed) with a utilization
//     verdict (observed-used / carried-not-proven-used / not-observed / unknown)
//   - sensitive-resource exposure per agent
//   - blueprint-baseline vs. effective-privilege drift findings, with severity
//   - blast-radius simulation for each changeProposal in the input file
//
// This script never treats "the permission exists" as "the permission is effective":
// only materialized, non-blocked grants count, and reach is narrowed by resource-specific
// constraints before anything is reported as reachable. See the README in this folder for
// the full rule set.
//
// Usage:
//   node access-graph/scripts/evaluate-access.mjs
//   node access-graph/scripts/evaluate-access.mjs access-graph/examples/procurement-agent.access.json --windowDays 90 --out access-graph/examples/procurement-agent.evaluation.json

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

const args = process.argv.slice(2);
const positional = args.filter((arg) => !arg.startsWith("--"));
const flags = Object.fromEntries(
  args
    .filter((arg) => arg.startsWith("--"))
    .map((arg) => {
      const [key, value] = arg.replace(/^--/, "").split("=");
      return [key, value ?? args[args.indexOf(arg) + 1]];
    })
);

const defaultInput = path.resolve(new URL("../examples/procurement-agent.access.json", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));
const inputPath = positional[0] ? path.resolve(positional[0]) : defaultInput;
const windowDays = Number(flags.windowDays ?? 90);
const outPath = flags.out
  ? path.resolve(flags.out)
  : path.join(path.dirname(inputPath), `${path.basename(inputPath, ".json")}.evaluation.json`);

const model = JSON.parse(await readFile(inputPath, "utf8"));
const report = evaluate(model, { windowDays, inputSource: path.relative(process.cwd(), inputPath) });

await writeFile(outPath, JSON.stringify(report, null, 2) + "\n", "utf8");
printSummary(report, outPath);

// ---------------------------------------------------------------------------

function evaluate(model, { windowDays, inputSource }) {
  const idx = buildIndex(model);
  const nowMs = Date.parse(model.metadata.generatedAt);

  const agents = [];
  const allDriftFindings = [];
  const resolvedByAgent = new Map(); // agentId -> resolvedPermissions (with internal fields), for blast-radius use

  for (const agent of model.agentIdentities) {
    const blueprint = idx.blueprintsById.get(agent.blueprintId);
    const resolved = resolveAgentPermissions(model, agent, idx, windowDays, nowMs);
    resolvedByAgent.set(agent.id, resolved);

    const sensitiveExposure = computeSensitiveExposure(model, resolved, idx);
    const driftFindings = computeDriftFindings(blueprint, agent, resolved);
    allDriftFindings.push(...driftFindings);

    agents.push({
      agentIdentityId: agent.id,
      blueprintId: agent.blueprintId,
      resolvedPermissions: resolved.map(stripInternal),
      sensitiveExposure
    });
  }

  const blastRadiusResults = computeBlastRadius(model, idx, resolvedByAgent);

  return {
    version: "1.0.0",
    evaluatedAt: new Date().toISOString(),
    inputSource,
    windowDays,
    telemetryCoveragePercent: model.metadata.telemetryCoveragePercent,
    agents,
    driftFindings: allDriftFindings,
    blastRadiusResults
  };
}

function buildIndex(model) {
  const blueprintsById = new Map(model.blueprints.map((b) => [b.id, b]));
  const agentsById = new Map(model.agentIdentities.map((a) => [a.id, a]));
  const resourcesById = new Map((model.resources ?? []).map((r) => [r.id, r]));
  const entitlementsByAgent = groupBy(model.entitlements ?? [], (e) => e.agentIdentityId);
  const constraintsByAgent = new Map();
  for (const constraint of model.constraints ?? []) {
    if (!constraint.appliesToAgentIdentityId) continue;
    const list = constraintsByAgent.get(constraint.appliesToAgentIdentityId) ?? [];
    list.push(constraint);
    constraintsByAgent.set(constraint.appliesToAgentIdentityId, list);
  }
  const executionsByAgent = groupBy(model.executions ?? [], (e) => e.agentIdentityId);
  return { blueprintsById, agentsById, resourcesById, entitlementsByAgent, constraintsByAgent, executionsByAgent };
}

function groupBy(items, keyFn) {
  const map = new Map();
  for (const item of items) {
    const key = keyFn(item);
    const list = map.get(key) ?? [];
    list.push(item);
    map.set(key, list);
  }
  return map;
}

// --- Resolution: raw entitlements -> effective permissions -----------------

function resolveAgentPermissions(model, agent, idx, windowDays, nowMs) {
  const entitlements = idx.entitlementsByAgent.get(agent.id) ?? [];
  const materialized = entitlements.filter((e) => e.consentState === "materialized");

  const grouped = new Map(); // "resourceApp|permission|permissionType" -> accumulator
  for (const entitlement of materialized) {
    const key = `${entitlement.resourceApp}|${entitlement.permission}|${entitlement.permissionType}`;
    if (!grouped.has(key)) {
      grouped.set(key, {
        resourceApp: entitlement.resourceApp,
        permission: entitlement.permission,
        permissionType: entitlement.permissionType,
        grantTypes: new Set(),
        entitlements: []
      });
    }
    const group = grouped.get(key);
    group.grantTypes.add(entitlement.grantType);
    group.entitlements.push(entitlement);
  }

  const constraintsForAgent = idx.constraintsByAgent.get(agent.id) ?? [];
  const execsInWindow = (idx.executionsByAgent.get(agent.id) ?? []).filter((e) => withinWindow(e.timestamp, nowMs, windowDays));
  const telemetryKnown = typeof model.metadata.telemetryCoveragePercent === "number";

  const resolved = [];
  for (const group of grouped.values()) {
    const applicableConstraints = constraintsForAgent.filter(
      (c) => !c.appliesToPermission || (c.appliesToPermission.resourceApp === group.resourceApp && c.appliesToPermission.permission === group.permission)
    );

    let status = "effective";
    const blockedBy = [];
    if (agent.status !== "active") {
      status = "blocked";
      blockedBy.push(`agentIdentity.status=${agent.status}`);
    }
    for (const constraint of applicableConstraints) {
      if (["conditionalAccessBlock", "denyAssignment", "disabledIdentity", "credentialExpired", "pimEligibleNotActive"].includes(constraint.kind)) {
        status = "blocked";
        blockedBy.push(constraint.id);
      }
    }

    const aclConstraint = applicableConstraints.find((c) => c.kind === "resourceSpecificAcl");
    let theoretical = "tenant-wide";
    let configured = "tenant-wide";
    let configuredResourceIds = null;
    if (aclConstraint) {
      const scopeIds = aclConstraint.scopeResourceIds ?? [];
      if (scopeIds.length === 0) {
        if (status === "effective") status = "incomplete-resource-grant";
        theoretical = "tenant-wide (pending per-resource grants)";
        configured = "0 resources granted yet";
        configuredResourceIds = [];
      } else {
        theoretical = "tenant-wide (resource-specific consent model)";
        const names = scopeIds.map((id) => idx.resourcesById.get(id)?.displayName ?? id);
        configured = `${scopeIds.length} resource-specific-consent resource(s): ${names.join(", ")}`;
        configuredResourceIds = scopeIds;
      }
    }

    const successMatches = execsInWindow.filter(
      (e) => e.resultType === "success" && e.permissionUsed === group.permission && e.resourceApp === group.resourceApp
    );
    const claimMatches = execsInWindow.filter((e) => e.resourceApp === group.resourceApp && (e.permissionClaims ?? []).includes(group.permission));

    let utilization;
    let observedResourceIds = [];
    if (successMatches.length > 0) {
      utilization = "observed-used";
      observedResourceIds = [...new Set(successMatches.map((e) => e.resourceId).filter(Boolean))];
    } else if (claimMatches.length > 0) {
      utilization = "carried-not-proven-used";
    } else if (telemetryKnown) {
      utilization = "not-observed";
    } else {
      utilization = "unknown";
    }

    const confidence = status === "blocked" ? "high" : utilization === "unknown" ? "low" : "high";

    resolved.push({
      resourceApp: group.resourceApp,
      permission: group.permission,
      permissionType: group.permissionType,
      grantTypes: [...group.grantTypes],
      status,
      blockedBy: blockedBy.length ? blockedBy : undefined,
      reach: {
        theoretical,
        configured,
        observedResourceIds,
        observedCount: observedResourceIds.length,
        utilization
      },
      confidence,
      _configuredResourceIds: configuredResourceIds
    });
  }
  return resolved;
}

function withinWindow(timestamp, nowMs, windowDays) {
  const t = Date.parse(timestamp);
  if (Number.isNaN(t)) return false;
  return t <= nowMs && nowMs - t <= windowDays * 86400000;
}

function stripInternal(resolvedPermission) {
  const { _configuredResourceIds, ...rest } = resolvedPermission;
  return rest;
}

// --- Sensitive-resource exposure --------------------------------------------

function permissionAppliesToResourceType(resourceApp, permission, resourceType) {
  const perm = permission.toLowerCase();
  if (resourceApp === "Microsoft Graph") {
    if (perm.startsWith("sites.")) return resourceType === "sharepointSite";
    if (perm.startsWith("files.")) return resourceType === "sharepointSite" || resourceType === "oneDriveAccount";
    if (perm.startsWith("mail.")) return resourceType === "exchangeMailbox";
  }
  return false;
}

function accessLevel(permission) {
  return /readwrite|write|fullcontrol|manage/i.test(permission) ? "readWrite" : "read";
}

function computeSensitiveExposure(model, resolvedPermissions, idx) {
  const reachable = new Map(); // resourceId -> { access, viaPermission }

  for (const resource of model.resources ?? []) {
    if (resource.classification === "public") continue;
    let access = "none";
    let viaPermission;

    for (const rp of resolvedPermissions) {
      if (rp.status === "blocked") continue;

      if (rp._configuredResourceIds) {
        // Resource-specific-consent permission: only reaches resources explicitly granted.
        if (rp._configuredResourceIds.includes(resource.id)) {
          const level = accessLevel(rp.permission);
          if (access === "none" || level === "readWrite") {
            access = level;
            viaPermission = rp.permission;
          }
        }
        continue;
      }

      if (permissionAppliesToResourceType(rp.resourceApp, rp.permission, resource.resourceType)) {
        const level = accessLevel(rp.permission);
        if (access === "none" || (access === "read" && level === "readWrite")) {
          access = level;
          viaPermission = rp.permission;
        }
      }
    }

    reachable.set(resource.id, { access, viaPermission });
  }

  const reachableIds = new Set([...reachable.entries()].filter(([, v]) => v.access !== "none").map(([id]) => id));
  const adjacentIds = new Set();
  for (const resource of model.resources ?? []) {
    if (reachableIds.has(resource.id) || resource.classification === "public") continue;
    const sharesProcess = (resource.businessProcessIds ?? []).some((processId) =>
      [...reachableIds].some((reachableId) => (idx.resourcesById.get(reachableId)?.businessProcessIds ?? []).includes(processId))
    );
    if (sharesProcess) adjacentIds.add(resource.id);
  }

  const exposure = [];
  for (const resourceId of new Set([...reachableIds, ...adjacentIds])) {
    const resource = idx.resourcesById.get(resourceId);
    if (!resource) continue;
    const info = reachable.get(resourceId) ?? { access: "none" };
    exposure.push({ resourceId, classification: resource.classification, access: info.access, viaPermission: info.viaPermission });
  }
  return exposure;
}

// --- Blueprint-baseline vs. effective-privilege drift -----------------------

function computeDriftFindings(blueprint, agent, resolvedPermissions) {
  const findings = [];
  const baselinePermissions = blueprint?.baselinePermissions ?? [];
  const baselineKeys = new Set(baselinePermissions.map((b) => `${b.resourceApp}|${b.permission}`));
  const baselineResourceApps = new Set(baselinePermissions.map((b) => b.resourceApp));
  const baselineHasReadOnly = baselinePermissions.some((b) => accessLevel(b.permission) === "read");

  for (const baseline of baselinePermissions.filter((b) => b.inheritancePattern === "allAllowedScopes")) {
    findings.push({
      agentIdentityId: agent.id,
      kind: "all-allowed-scopes-unbounded-baseline",
      severity: "medium",
      description:
        `Blueprint baseline permission ${baseline.resourceApp} ${baseline.permission} uses the 'allAllowedScopes' inheritance pattern: ` +
        `any future delegated scope granted to the blueprint for ${baseline.resourceApp} -- not just ${baseline.permission} -- will flow to ` +
        `this agent identity automatically, without a separate consent or review step.`,
      baselinePermissions: [...baselineKeys],
      effectivePermissions: resolvedPermissions.filter((p) => p.status !== "blocked").map((p) => `${p.resourceApp} ${p.permission}`)
    });
  }

  for (const rp of resolvedPermissions) {
    if (rp.status === "blocked") continue;
    const key = `${rp.resourceApp}|${rp.permission}`;
    if (baselineKeys.has(key)) continue;

    const grantedBeyondInheritance = rp.grantTypes.some((gt) => gt !== "inherited");
    if (!grantedBeyondInheritance) continue; // consistency guard; inherited-only entitlements should always match baseline

    const level = accessLevel(rp.permission);
    const isNewResourceApp = !baselineResourceApps.has(rp.resourceApp);

    let kind;
    let severity;
    if (!isNewResourceApp && level === "readWrite" && baselineHasReadOnly) {
      kind = "write-beyond-read-baseline";
      if (rp.permissionType === "application" && rp.reach.utilization === "observed-used") severity = "critical";
      else if (rp.permissionType === "application") severity = "high";
      else severity = "medium";
    } else {
      kind = "new-resource-app-beyond-baseline";
      const narrowlyScoped = Array.isArray(rp._configuredResourceIds) && rp._configuredResourceIds.length > 0 && level === "read";
      if (narrowlyScoped) severity = "low";
      else if (level === "readWrite") severity = "high";
      else severity = "medium";
    }

    findings.push({
      agentIdentityId: agent.id,
      kind,
      severity,
      description: describeDrift(rp, kind, severity),
      baselinePermissions: [...baselineKeys],
      effectivePermissions: [key]
    });
  }

  return findings;
}

function describeDrift(resolvedPermission, kind, severity) {
  const grantSummary = resolvedPermission.grantTypes.join("+");
  const utilizationSummary =
    resolvedPermission.reach.utilization === "observed-used"
      ? `actively used (${resolvedPermission.reach.observedCount} observed call(s) in the evaluation window)`
      : resolvedPermission.reach.utilization === "carried-not-proven-used"
        ? "present in token claims but not yet proven exercised"
        : resolvedPermission.reach.utilization === "not-observed"
          ? "not observed in the evaluation window despite full telemetry coverage"
          : "utilization unknown (telemetry coverage not established)";

  if (kind === "write-beyond-read-baseline") {
    return (
      `${resolvedPermission.resourceApp} ${resolvedPermission.permission} (${resolvedPermission.permissionType}, via ${grantSummary}) ` +
      `grants write access on a blueprint whose baseline is read-only. This grant is ${utilizationSummary}. Severity: ${severity}.`
    );
  }
  return (
    `${resolvedPermission.resourceApp} ${resolvedPermission.permission} (${resolvedPermission.permissionType}, via ${grantSummary}) ` +
    `targets a resource application outside the blueprint's declared baseline. This grant is ${utilizationSummary}. Severity: ${severity}.`
  );
}

// --- Blast-radius simulation -------------------------------------------------

function computeBlastRadius(model, idx, resolvedByAgent) {
  const results = [];
  const telemetryKnown = typeof model.metadata.telemetryCoveragePercent === "number";

  for (const proposal of model.changeProposals ?? []) {
    if (proposal.kind === "removeEntitlement" && proposal.targetPermission) {
      const matches = [];
      for (const [agentId, resolved] of resolvedByAgent) {
        const hit = resolved.find(
          (rp) =>
            rp.resourceApp === proposal.targetPermission.resourceApp &&
            rp.permission === proposal.targetPermission.permission &&
            rp.status !== "blocked" &&
            rp.grantTypes.some((gt) => gt !== "inherited")
        );
        if (hit) matches.push({ agentId, utilization: hit.reach.utilization });
      }
      const confirmed = matches.filter((m) => m.utilization === "observed-used");
      const unknown = matches.filter((m) => m.utilization === "unknown");
      const affectedBlueprintIds = [...new Set(matches.map((m) => idx.agentsById.get(m.agentId).blueprintId))];
      const affectedBusinessProcessIds = (model.businessProcesses ?? [])
        .filter((bp) => (bp.dependentAgentIds ?? []).some((agentId) => matches.some((m) => m.agentId === agentId)))
        .map((bp) => bp.id);

      results.push({
        changeProposalId: proposal.id,
        confirmedAffectedAgentCount: confirmed.length,
        potentiallyAffectedAgentCount: matches.length - confirmed.length,
        affectedBlueprintIds,
        affectedBusinessProcessIds,
        unknownDependencyCount: unknown.length,
        confidence: blastConfidence(telemetryKnown, model.metadata.telemetryCoveragePercent, unknown.length, matches.length),
        dataAsOf: model.metadata.generatedAt
      });
    } else if (proposal.kind === "disableAgentIdentity" && proposal.targetAgentIdentityId) {
      const agent = idx.agentsById.get(proposal.targetAgentIdentityId);
      const affectedBusinessProcessIds = (model.businessProcesses ?? [])
        .filter((bp) => (bp.dependentAgentIds ?? []).includes(agent.id))
        .map((bp) => bp.id);
      results.push({
        changeProposalId: proposal.id,
        confirmedAffectedAgentCount: 1,
        potentiallyAffectedAgentCount: 0,
        affectedBlueprintIds: [agent.blueprintId],
        affectedBusinessProcessIds,
        unknownDependencyCount: 0,
        confidence: telemetryKnown ? "high" : "medium",
        dataAsOf: model.metadata.generatedAt
      });
    }
    // disableBlueprint / downscopeToResourceSpecific: left for a future iteration; not required by the sample scenario.
  }
  return results;
}

function blastConfidence(telemetryKnown, coveragePercent, unknownCount, totalCount) {
  if (!telemetryKnown) return "low";
  if (unknownCount === 0 && coveragePercent >= 90) return "high";
  if (totalCount === 0 || unknownCount / totalCount < 0.5) return "medium";
  return "low";
}

// --- CLI summary --------------------------------------------------------------

function printSummary(report, outPath) {
  const agentsExceedingBaseline = new Set(report.driftFindings.map((f) => f.agentIdentityId)).size;
  const sensitiveReachable = new Set(
    report.agents.flatMap((a) =>
      a.sensitiveExposure
        .filter((e) => e.access !== "none" && (e.classification === "confidential" || e.classification === "highlyConfidential"))
        .map((e) => `${a.agentIdentityId}|${e.resourceId}`)
    )
  ).size;
  const criticalOrHigh = report.driftFindings.filter((f) => f.severity === "critical" || f.severity === "high").length;

  console.log(`Evaluated ${report.agents.length} agent identities (window: ${report.windowDays} days, telemetry coverage: ${report.telemetryCoveragePercent ?? "unknown"}%).`);
  console.log(`- Agents exceeding blueprint baseline: ${agentsExceedingBaseline}`);
  console.log(`- Drift findings (critical/high): ${criticalOrHigh} of ${report.driftFindings.length} total`);
  console.log(`- Agent-resource sensitive-reachable pairs (confidential+): ${sensitiveReachable}`);
  for (const result of report.blastRadiusResults) {
    console.log(
      `- Blast radius [${result.changeProposalId}]: ${result.confirmedAffectedAgentCount} confirmed + ${result.potentiallyAffectedAgentCount} potential agent(s), ` +
      `${result.affectedBlueprintIds.length} blueprint(s), ${result.affectedBusinessProcessIds.length} business process(es), confidence ${result.confidence}.`
    );
  }
  console.log(`Wrote evaluation report to ${outPath}`);
}
