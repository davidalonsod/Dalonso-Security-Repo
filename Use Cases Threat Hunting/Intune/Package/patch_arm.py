"""Patch mainTemplate.direct.json for IntuneLogs:
- Add params: enableAnalyticRules, watchlistAlias, functionAlias, watchlistRawContent
- Prepend NetworkAllowlist watchlist + ExcludeAllowlistedIPs_Intune scalar function
- Parameterize alertRules.enabled
- Threshold uplift: Bulk wipe Count >=5 -> >=10; Mass enrollment EnrollCount >=5 -> >=10
- Wrap the 15 alertRules in a nested Microsoft.Resources/deployments (scope=inner)
- Leave inline _GetWatchlist('NetworkAllowlist') usages as-is (they already work)
"""
import json, copy, pathlib, shutil

P = pathlib.Path(__file__).parent / "mainTemplate.direct.json"
BAK = P.with_suffix(".direct.json.bak")
if not BAK.exists():
    shutil.copy(P, BAK)

d = json.loads(P.read_text(encoding="utf-8-sig"))

# Params
d["parameters"]["enableAnalyticRules"] = {
    "type": "bool", "defaultValue": True,
    "metadata": {"description": "If false, all alert rules deploy disabled."},
}
d["parameters"]["watchlistAlias"] = {
    "type": "string", "defaultValue": "NetworkAllowlist",
    "metadata": {"description": "Trusted IP allowlist watchlist alias."},
}
d["parameters"]["functionAlias"] = {
    "type": "string", "defaultValue": "ExcludeAllowlistedIPs_Intune",
    "metadata": {"description": "savedSearches scalar function (ip:string -> bool)."},
}
d["parameters"]["watchlistRawContent"] = {
    "type": "string", "defaultValue": "",
    "metadata": {"description": "Optional CSV override for watchlist seed."},
}

# Variables
d.setdefault("variables", {})
d["variables"]["watchlistHeader"] = "IPOrRange,Description,Owner,AddedDate"
d["variables"]["watchlistDefaultRows"] = "10.0.0.0/8,RFC1918 Class A,Network,2026-01-01\r\n172.16.0.0/12,RFC1918 Class B,Network,2026-01-01\r\n192.168.0.0/16,RFC1918 Class C,Network,2026-01-01"
d["variables"]["watchlistEffectiveContent"] = "[if(empty(parameters('watchlistRawContent')), concat(variables('watchlistHeader'), '\r\n', variables('watchlistDefaultRows')), concat(variables('watchlistHeader'), '\r\n', parameters('watchlistRawContent')))]"

# Watchlist resource
watchlist_res = {
    "type": "Microsoft.OperationalInsights/workspaces/providers/watchlists",
    "apiVersion": "2023-02-01-preview",
    "name": "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', parameters('watchlistAlias'))]",
    "properties": {
        "displayName": "[parameters('watchlistAlias')]",
        "description": "Trusted/sanctioned IPs and CIDR ranges to exclude from Intune/identity detections.",
        "provider": "Customer",
        "source": "Local file",
        "itemsSearchKey": "IPOrRange",
        "contentType": "text/csv",
        "numberOfLinesToSkip": 0,
        "rawContent": "[variables('watchlistEffectiveContent')]"
    }
}

func_query = (
    "let _ips = _GetWatchlist('NetworkAllowlist') | summarize Ranges = make_list(IPOrRange);\n"
    "let _allowed = toscalar(_ips);\n"
    "iif(isempty(ip) or array_length(_allowed) == 0, false, ipv4_is_in_any_range(ip, _allowed))"
)
function_res = {
    "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
    "apiVersion": "2020-08-01",
    "name": "[concat(parameters('workspace'), '/', parameters('functionAlias'))]",
    "properties": {
        "etag": "*",
        "displayName": "ExcludeAllowlistedIPs_Intune",
        "category": "Functions",
        "query": func_query,
        "functionAlias": "[parameters('functionAlias')]",
        "functionParameters": "ip:string",
        "version": 2
    }
}

# Patch rules
alertRules = []
others = []
thresholds_raised = 0
rules_enabled_param = 0
for r in d["resources"]:
    t = r.get("type","")
    if t.endswith("/alertRules"):
        props = r["properties"]
        props["enabled"] = "[parameters('enableAnalyticRules')]"
        rules_enabled_param += 1
        q = props["query"]
        new_q = q.replace("| where Count >= 5", "| where Count >= 10").replace("| where EnrollCount >= 5", "| where EnrollCount >= 10")
        if new_q != q: thresholds_raised += 1
        props["query"] = new_q
        alertRules.append(r)
    else:
        others.append(r)

# Build nested deployment with the 15 alertRules
inner_rules = []
for r in alertRules:
    rr = copy.deepcopy(r)
    rr.pop("dependsOn", None)
    inner_rules.append(rr)

nested = {
    "type": "Microsoft.Resources/deployments",
    "apiVersion": "2022-09-01",
    "name": "deploy-Intune-AnalyticRules",
    "dependsOn": [
        "[resourceId('Microsoft.OperationalInsights/workspaces/providers/watchlists', parameters('workspace'), 'Microsoft.SecurityInsights', parameters('watchlistAlias'))]",
        "[resourceId('Microsoft.OperationalInsights/workspaces/savedSearches', parameters('workspace'), parameters('functionAlias'))]"
    ],
    "properties": {
        "mode": "Incremental",
        "expressionEvaluationOptions": {"scope": "inner"},
        "parameters": {
            "workspace": {"value": "[parameters('workspace')]"},
            "location": {"value": "[parameters('location')]"},
            "enableAnalyticRules": {"value": "[parameters('enableAnalyticRules')]"}
        },
        "template": {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                "workspace": {"type": "string"},
                "location": {"type": "string"},
                "enableAnalyticRules": {"type": "bool"}
            },
            "resources": inner_rules
        }
    }
}

# New resource order: watchlist, function, all non-alertRule resources (savedSearches/workbooks/etc.), nested deployment
d["resources"] = [watchlist_res, function_res] + others + [nested]

P.write_text(json.dumps(d, indent=2), encoding="utf-8")
print(f"rules: {len(alertRules)} (enabled param applied to {rules_enabled_param})")
print(f"thresholds raised: {thresholds_raised}")
print(f"non-alertRule resources kept: {len(others)}")
print(f"total outer resources: {len(d['resources'])}")
