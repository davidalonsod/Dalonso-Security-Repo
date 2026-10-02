// No-dependency validator for the Phase 1 canonical access model
// (access-graph/schema/access-model-schema.json). Mirrors the style of
// scripts/validate.mjs and scripts/validate-case.mjs: structural/enum checks
// plus cross-reference checks (every id an entitlement/execution/constraint/
// resource points at must actually exist), so a malformed instance fails
// fast and loudly before it ever reaches the Phase 2 evaluator.
//
// Usage:
//   node access-graph/scripts/validate-access-model.mjs
//   node access-graph/scripts/validate-access-model.mjs access-graph/examples/procurement-agent.access.json

import { readFile } from "node:fs/promises";
import path from "node:path";

const targetPath = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.resolve(new URL("../examples/procurement-agent.access.json", import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, "$1"));

const model = JSON.parse(await readFile(targetPath, "utf8"));

const identifier = /^[a-z][a-z0-9-]*$/;
const allowedConfidence = new Set(["low", "medium", "high"]);
const allowedPermissionType = new Set(["application", "delegated"]);
const allowedExecutionContext = new Set(["application", "delegatedObo", "managedIdentity", "federatedWorkload", "unknown"]);
const allowedGrantType = new Set(["inherited", "direct", "group", "accessPackage", "resourceSpecificConsent", "azureRbacRole"]);
const allowedConsentState = new Set(["declared", "consented", "inheritable", "materialized"]);
const allowedConstraintKind = new Set([
  "resourceSpecificAcl", "conditionalAccessBlock", "rbacCondition", "denyAssignment",
  "dlpPolicy", "networkBoundary", "pimEligibleNotActive", "credentialExpired", "disabledIdentity"
]);
const allowedResourceType = new Set(["sharepointSite", "oneDriveAccount", "exchangeMailbox", "sqlDatabase", "vectorIndex", "mcpTool", "other"]);
const allowedClassification = new Set(["public", "internal", "confidential", "highlyConfidential"]);
const allowedResultType = new Set(["success", "denied", "throttled", "error"]);
const allowedChangeKind = new Set(["removeEntitlement", "disableAgentIdentity", "disableBlueprint", "downscopeToResourceSpecific"]);
const allowedDeploymentStatus = new Set(["draft", "requires-tuning", "ready", "deployed", "retired"]);

const errors = [];
const requireId = (value, label) => {
  if (!identifier.test(value ?? "")) errors.push(`${label} is not a valid identifier: ${value}`);
};
const checkObservation = (observation, label) => {
  if (!observation) { errors.push(`${label} is missing observation`); return; }
  if (!observation.source) errors.push(`${label}.observation is missing source`);
  if (!allowedConfidence.has(observation.confidence)) errors.push(`${label}.observation has invalid confidence: ${observation.confidence}`);
};

for (const key of ["version", "metadata", "blueprints", "agentIdentities", "entitlements", "resources"]) {
  if (!(key in model)) errors.push(`Missing top-level property: ${key}`);
}
if (!/^\d+\.\d+\.\d+$/.test(model.version ?? "")) errors.push("version must use semantic version format");
if (!allowedDeploymentStatus.has(model.metadata?.deploymentStatus)) {
  errors.push(`metadata.deploymentStatus has invalid value: ${model.metadata?.deploymentStatus}`);
}

const blueprintIds = new Set();
for (const blueprint of model.blueprints ?? []) {
  requireId(blueprint.id, "blueprint.id");
  if (blueprintIds.has(blueprint.id)) errors.push(`Duplicate blueprint id: ${blueprint.id}`);
  blueprintIds.add(blueprint.id);
  checkObservation(blueprint.observation, `blueprint ${blueprint.id}`);
  for (const [index, baseline] of (blueprint.baselinePermissions ?? []).entries()) {
    if (!allowedPermissionType.has(baseline.permissionType)) {
      errors.push(`blueprint ${blueprint.id} baselinePermissions[${index}] has invalid permissionType: ${baseline.permissionType}`);
    }
    if (!["enumeratedScopes", "allAllowedScopes"].includes(baseline.inheritancePattern)) {
      errors.push(`blueprint ${blueprint.id} baselinePermissions[${index}] has invalid inheritancePattern: ${baseline.inheritancePattern}`);
    }
  }
}

const agentIds = new Set();
for (const agent of model.agentIdentities ?? []) {
  requireId(agent.id, "agentIdentity.id");
  if (agentIds.has(agent.id)) errors.push(`Duplicate agentIdentity id: ${agent.id}`);
  agentIds.add(agent.id);
  if (!blueprintIds.has(agent.blueprintId)) errors.push(`agentIdentity ${agent.id} references unknown blueprintId: ${agent.blueprintId}`);
  if (!["active", "disabled", "deleted"].includes(agent.status)) errors.push(`agentIdentity ${agent.id} has invalid status: ${agent.status}`);
  checkObservation(agent.observation, `agentIdentity ${agent.id}`);
}

for (const credential of model.credentials ?? []) {
  requireId(credential.id, "credential.id");
  if (!blueprintIds.has(credential.blueprintId)) errors.push(`credential ${credential.id} references unknown blueprintId: ${credential.blueprintId}`);
  if (!["managedIdentity", "federatedIdentityCredential", "certificate", "clientSecret", "sdkSidecar"].includes(credential.type)) {
    errors.push(`credential ${credential.id} has invalid type: ${credential.type}`);
  }
  checkObservation(credential.observation, `credential ${credential.id}`);
}

const entitlementIds = new Set();
for (const entitlement of model.entitlements ?? []) {
  requireId(entitlement.id, "entitlement.id");
  if (entitlementIds.has(entitlement.id)) errors.push(`Duplicate entitlement id: ${entitlement.id}`);
  entitlementIds.add(entitlement.id);
  if (!agentIds.has(entitlement.agentIdentityId)) errors.push(`entitlement ${entitlement.id} references unknown agentIdentityId: ${entitlement.agentIdentityId}`);
  if (!allowedPermissionType.has(entitlement.permissionType)) errors.push(`entitlement ${entitlement.id} has invalid permissionType: ${entitlement.permissionType}`);
  if (!allowedGrantType.has(entitlement.grantType)) errors.push(`entitlement ${entitlement.id} has invalid grantType: ${entitlement.grantType}`);
  if (!allowedExecutionContext.has(entitlement.executionContext)) errors.push(`entitlement ${entitlement.id} has invalid executionContext: ${entitlement.executionContext}`);
  if (!allowedConsentState.has(entitlement.consentState)) errors.push(`entitlement ${entitlement.id} has invalid consentState: ${entitlement.consentState}`);
  checkObservation(entitlement.observation, `entitlement ${entitlement.id}`);
}

const constraintIds = new Set();
for (const constraint of model.constraints ?? []) {
  requireId(constraint.id, "constraint.id");
  if (constraintIds.has(constraint.id)) errors.push(`Duplicate constraint id: ${constraint.id}`);
  constraintIds.add(constraint.id);
  if (constraint.appliesToAgentIdentityId && !agentIds.has(constraint.appliesToAgentIdentityId)) {
    errors.push(`constraint ${constraint.id} references unknown appliesToAgentIdentityId: ${constraint.appliesToAgentIdentityId}`);
  }
  if (!allowedConstraintKind.has(constraint.kind)) errors.push(`constraint ${constraint.id} has invalid kind: ${constraint.kind}`);
  checkObservation(constraint.observation, `constraint ${constraint.id}`);
}

const resourceIds = new Set();
const businessProcessIds = new Set((model.businessProcesses ?? []).map((process) => process.id));
for (const resource of model.resources ?? []) {
  requireId(resource.id, "resource.id");
  if (resourceIds.has(resource.id)) errors.push(`Duplicate resource id: ${resource.id}`);
  resourceIds.add(resource.id);
  if (!allowedResourceType.has(resource.resourceType)) errors.push(`resource ${resource.id} has invalid resourceType: ${resource.resourceType}`);
  if (!allowedClassification.has(resource.classification)) errors.push(`resource ${resource.id} has invalid classification: ${resource.classification}`);
  for (const processId of resource.businessProcessIds ?? []) {
    if (!businessProcessIds.has(processId)) errors.push(`resource ${resource.id} references unknown businessProcessId: ${processId}`);
  }
}

// constraints may reference resources via scopeResourceIds; checked after resourceIds is built
for (const constraint of model.constraints ?? []) {
  for (const resourceId of constraint.scopeResourceIds ?? []) {
    if (!resourceIds.has(resourceId)) errors.push(`constraint ${constraint.id} references unknown resource in scopeResourceIds: ${resourceId}`);
  }
}

for (const execution of model.executions ?? []) {
  requireId(execution.id, "execution.id");
  if (!agentIds.has(execution.agentIdentityId)) errors.push(`execution ${execution.id} references unknown agentIdentityId: ${execution.agentIdentityId}`);
  if (!allowedExecutionContext.has(execution.executionContext)) errors.push(`execution ${execution.id} has invalid executionContext: ${execution.executionContext}`);
  if (!allowedResultType.has(execution.resultType)) errors.push(`execution ${execution.id} has invalid resultType: ${execution.resultType}`);
  if (execution.resourceId && !resourceIds.has(execution.resourceId)) {
    errors.push(`execution ${execution.id} references unknown resourceId: ${execution.resourceId}`);
  }
  checkObservation(execution.observation, `execution ${execution.id}`);
}

for (const process of model.businessProcesses ?? []) {
  requireId(process.id, "businessProcess.id");
  for (const resourceId of process.dependentResourceIds ?? []) {
    if (!resourceIds.has(resourceId)) errors.push(`businessProcess ${process.id} references unknown dependentResourceId: ${resourceId}`);
  }
  for (const agentId of process.dependentAgentIds ?? []) {
    if (!agentIds.has(agentId)) errors.push(`businessProcess ${process.id} references unknown dependentAgentId: ${agentId}`);
  }
}

for (const proposal of model.changeProposals ?? []) {
  requireId(proposal.id, "changeProposal.id");
  if (!allowedChangeKind.has(proposal.kind)) errors.push(`changeProposal ${proposal.id} has invalid kind: ${proposal.kind}`);
  if (proposal.targetAgentIdentityId && !agentIds.has(proposal.targetAgentIdentityId)) {
    errors.push(`changeProposal ${proposal.id} references unknown targetAgentIdentityId: ${proposal.targetAgentIdentityId}`);
  }
  if (proposal.targetBlueprintId && !blueprintIds.has(proposal.targetBlueprintId)) {
    errors.push(`changeProposal ${proposal.id} references unknown targetBlueprintId: ${proposal.targetBlueprintId}`);
  }
}

if (errors.length) {
  console.error(`Validation failed with ${errors.length} error(s):`);
  errors.forEach((error) => console.error(`- ${error}`));
  process.exit(1);
}

console.log(
  `Validated ${path.basename(targetPath)} v${model.version}: ` +
  `${blueprintIds.size} blueprints, ${agentIds.size} agent identities, ${entitlementIds.size} entitlements, ` +
  `${constraintIds.size} constraints, ${resourceIds.size} resources, ${(model.executions ?? []).length} executions, ` +
  `${businessProcessIds.size} business processes, ${(model.changeProposals ?? []).length} change proposals.`
);
