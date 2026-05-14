"""Patch Netskope azuredeploy.json:
- Add params: enableAnalyticRules, watchlistAlias, functionAlias, watchlistRawContent
- Prepend NetworkAllowlist watchlist + ExcludeAllowlistedIPs_Netskope scalar function
- Parameterize alertRules.enabled
- Inject IP filter where rules/hunts reference srcip_s/dstip_s (post-union)
- Threshold uplift (May 2026): targeted noise reduction
- Wrap 21 alertRules in nested deployment (scope=inner)
"""
import json, re, copy, pathlib, shutil

P = pathlib.Path(__file__).parent / "azuredeploy.json"
BAK = P.with_suffix(".json.bak")
if not BAK.exists():
    shutil.copy(P, BAK)

d = json.loads(P.read_text(encoding="utf-8-sig"))

d["parameters"]["enableAnalyticRules"] = {"type": "bool", "defaultValue": True,
    "metadata": {"description": "If false, all alert rules deploy disabled."}}
d["parameters"]["watchlistAlias"] = {"type": "string", "defaultValue": "NetworkAllowlist",
    "metadata": {"description": "Trusted IP allowlist watchlist alias."}}
d["parameters"]["functionAlias"] = {"type": "string", "defaultValue": "ExcludeAllowlistedIPs_Netskope",
    "metadata": {"description": "savedSearches scalar function (ip:string -> bool)."}}
d["parameters"]["watchlistRawContent"] = {"type": "string", "defaultValue": "",
    "metadata": {"description": "Optional CSV override for watchlist seed."}}

d.setdefault("variables", {})
d["variables"]["watchlistHeader"] = "IPOrRange,Description,Owner,AddedDate"
d["variables"]["watchlistDefaultRows"] = "10.0.0.0/8,RFC1918 Class A,Network,2026-01-01\r\n172.16.0.0/12,RFC1918 Class B,Network,2026-01-01\r\n192.168.0.0/16,RFC1918 Class C,Network,2026-01-01"
d["variables"]["watchlistEffectiveContent"] = "[if(empty(parameters('watchlistRawContent')), concat(variables('watchlistHeader'), '\r\n', variables('watchlistDefaultRows')), concat(variables('watchlistHeader'), '\r\n', parameters('watchlistRawContent')))]"

watchlist_res = {
    "type": "Microsoft.OperationalInsights/workspaces/providers/watchlists",
    "apiVersion": "2023-02-01-preview",
    "name": "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', parameters('watchlistAlias'))]",
    "properties": {
        "displayName": "[parameters('watchlistAlias')]",
        "description": "Trusted/sanctioned IPs and CIDR ranges to exclude from Netskope detections.",
        "provider": "Customer", "source": "Local file",
        "itemsSearchKey": "IPOrRange", "contentType": "text/csv",
        "numberOfLinesToSkip": 0,
        "rawContent": "[variables('watchlistEffectiveContent')]"
    }
}

function_res = {
    "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
    "apiVersion": "2020-08-01",
    "name": "[concat(parameters('workspace'), '/', parameters('functionAlias'))]",
    "properties": {
        "etag": "*",
        "displayName": "ExcludeAllowlistedIPs_Netskope",
        "category": "Functions",
        "query": ("let _ips = _GetWatchlist('NetworkAllowlist') | summarize Ranges = make_list(IPOrRange);\n"
                  "let _allowed = toscalar(_ips);\n"
                  "iif(isempty(ip) or array_length(_allowed) == 0, false, ipv4_is_in_any_range(ip, _allowed))"),
        "functionAlias": "[parameters('functionAlias')]",
        "functionParameters": "ip:string",
        "version": 2
    }
}

# Threshold uplift map (rule index -> [(old_substr, new_substr), ...])
threshold_map = {
    3:  [("| where TotalMBUploaded > 100", "| where TotalMBUploaded > 250"),
         ("| where TotalMBDownload > 500", "| where TotalMBDownload > 1000"),
         ("| where RequestCount > 5000", "| where RequestCount > 10000")],
    4:  [("UniqueUsers >= 3", "UniqueUsers >= 5")],
    9:  [("| where RequestCount > 100", "| where RequestCount > 250")],
    11: [("| where ActiveDays >= 5", "| where ActiveDays >= 7"),
         ("| where TotalMBSent > 100", "| where TotalMBSent > 250")],
    13: [("| where QueryCount > 10", "| where QueryCount > 25")],
    14: [("UniqueApps >= 3", "UniqueApps >= 5"),
         ("| where TotalMBUploaded > 50", "| where TotalMBUploaded > 150")],
    18: [("| where TotalMBUploaded > 100", "| where TotalMBUploaded > 250"),
         ("| where UploadCount > 50", "| where UploadCount > 100")],
    19: [("RequestCount >= 5", "RequestCount >= 15")],
    20: [("RequestCount >= 20", "RequestCount >= 50")],
}

# IP filter injection — runs immediately after the first union statement.
# Filters on both srcip_s and dstip_s when present.
filter_inject = (
    "\n| extend _SrcIP = tostring(srcip_s), _DstIP = tostring(dstip_s)\n"
    "| where (isempty(_SrcIP) or not(ExcludeAllowlistedIPs_Netskope(_SrcIP)))\n"
    "  and (isempty(_DstIP) or not(ExcludeAllowlistedIPs_Netskope(_DstIP)))"
)

# Indices of IP-bearing rules (from audit): 3,7,9,10,13,14,15,16,17,18,19,20
ip_rule_idx = {3,7,9,10,13,14,15,16,17,18,19,20}
# IP-bearing hunts (offset by alertRules count = 21): hunt 24,25,28,30,31 in absolute index
ip_hunt_idx = {24,25,28,30,31}

alertRules = []; others = []
rules_patched = hunts_patched = thresholds_raised = 0

for i, r in enumerate(d["resources"]):
    t = r.get("type","")
    p = r["properties"]
    q = p.get("query","")
    if t.endswith("/alertRules"):
        p["enabled"] = "[parameters('enableAnalyticRules')]"
        # Thresholds
        if i in threshold_map:
            for old,new in threshold_map[i]:
                if old in q:
                    q = q.replace(old, new, 1); thresholds_raised += 1
        # IP filter inject
        if i in ip_rule_idx and "ExcludeAllowlistedIPs_Netskope" not in q:
            # inject after first union statement (NetskopeWebTx_CL line)
            m = re.search(r"(union isfuzzy=true [^\n]+_CL[^\n]*)", q)
            if m:
                q = q[:m.end()] + filter_inject + q[m.end():]
                rules_patched += 1
        p["query"] = q
        alertRules.append(r)
    elif t.endswith("/savedSearches"):
        if i in ip_hunt_idx and "ExcludeAllowlistedIPs_Netskope" not in q:
            m = re.search(r"(union isfuzzy=true [^\n]+_CL[^\n]*)", q) or \
                re.search(r"(NetskopeWebTx_CL\s*\n\s*\|\s*where\s+TimeGenerated\s*>\s*ago\([^)]+\))", q)
            if m:
                q = q[:m.end()] + filter_inject + q[m.end():]
                hunts_patched += 1
        p["query"] = q
        others.append(r)
    else:
        others.append(r)

inner_rules = []
for r in alertRules:
    rr = copy.deepcopy(r)
    rr.pop("dependsOn", None)
    inner_rules.append(rr)

nested = {
    "type": "Microsoft.Resources/deployments",
    "apiVersion": "2022-09-01",
    "name": "deploy-Netskope-AnalyticRules",
    "dependsOn": [
        "[resourceId('Microsoft.OperationalInsights/workspaces/providers/watchlists', parameters('workspace'), 'Microsoft.SecurityInsights', parameters('watchlistAlias'))]",
        "[resourceId('Microsoft.OperationalInsights/workspaces/savedSearches', parameters('workspace'), parameters('functionAlias'))]"
    ],
    "properties": {
        "mode": "Incremental",
        "expressionEvaluationOptions": {"scope": "inner"},
        "parameters": {
            "workspace": {"value": "[parameters('workspace')]"},
            "enableAnalyticRules": {"value": "[parameters('enableAnalyticRules')]"}
        },
        "template": {
            "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
            "contentVersion": "1.0.0.0",
            "parameters": {
                "workspace": {"type": "string"},
                "enableAnalyticRules": {"type": "bool"}
            },
            "resources": inner_rules
        }
    }
}

d["resources"] = [watchlist_res, function_res] + others + [nested]
P.write_text(json.dumps(d, indent=2), encoding="utf-8")
print(f"alertRules: {len(alertRules)} | IP-filter injected: {rules_patched}")
print(f"hunts (savedSearches): {len(others)} | IP-filter injected in hunts: {hunts_patched}")
print(f"thresholds raised: {thresholds_raised}")
print(f"total outer resources: {len(d['resources'])}")
