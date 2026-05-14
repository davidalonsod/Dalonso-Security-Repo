"""Append 6 new Zscaler hunts (Q32-Q37)."""
import json, pathlib

P = pathlib.Path(r"C:\Users\dalonso\CommonSecurityLog-ThreatHunting\Zscaler\Analytic-Rules\azuredeploy.json")
d = json.loads(P.read_text(encoding="utf-8-sig"))
ws_param = "workspace"

F = (
    "\n| where not(ExcludeAllowlistedIPs_Zscaler(tostring(column_ifexists(\"SourceIP\",\"\"))))"
    "\n| where not(ExcludeAllowlistedIPs_Zscaler(tostring(column_ifexists(\"DestinationIP\",\"\"))))"
)

def hunt(name, dn, q, tactics="Discovery"):
    return {
        "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
        "apiVersion": "2020-08-01",
        "name": f"[concat(parameters('{ws_param}'), '/{name}')]",
        "properties": {
            "etag": "*", "displayName": dn, "category": "Hunting Queries",
            "query": q, "version": 2,
            "tags": [
                {"name": "description", "value": dn},
                {"name": "tactics", "value": tactics},
                {"name": "createdBy", "value": ""},
                {"name": "createdTimeUtc", "value": ""}
            ]
        }
    }

Q32 = (
    "// Q32 - ZIA DoH Egress to Non-Sanctioned Resolvers\n"
    "let SanctionedDoH = dynamic([\"cloudflare-dns.com\",\"dns.google\",\"dns.quad9.net\"]);\n"
    "CommonSecurityLog\n"
    "| where TimeGenerated > ago(1d)" + F + "\n"
    "| where DeviceVendor == \"Zscaler\"\n"
    "| where DestinationPort == 443\n"
    "| where RequestURL has_any (\"/dns-query\",\"dns-message\",\"application/dns\") or DeviceCustomString5 has \"doh\"\n"
    "| where not(RequestURL has_any (SanctionedDoH))\n"
    "| summarize Hits = count(), Hosts = make_set(RequestURL, 20), Users = make_set(SourceUserName, 10)\n"
    "    by SourceIP\n"
    "| where Hits >= 20\n"
    "| order by Hits desc"
)

Q33 = (
    "// Q33 - ZIA - Browser-Push Notification Phishing (push-style toolkits)\n"
    "CommonSecurityLog\n"
    "| where TimeGenerated > ago(1d)" + F + "\n"
    "| where DeviceVendor == \"Zscaler\"\n"
    "| where DeviceAction !in (\"block\",\"BLOCK\",\"Blocked\",\"blocked\")\n"
    "| where RequestURL has_any (\"/push.js\",\"pushnotif\",\"subscribePush\",\"notification.permission\")\n"
    "    or DeviceCustomString2 has_any (\"PHISH\",\"NEWLY_REGISTERED\",\"SUSPICIOUS\")\n"
    "| summarize Hits = count(), URLs = make_set(RequestURL, 25), Users = dcount(SourceUserName), UsersList = make_set(SourceUserName, 20)\n"
    "    by RequestClientApplication, DeviceCustomString2\n"
    "| where Users >= 3\n"
    "| order by Users desc, Hits desc"
)

Q34 = (
    "// Q34 - ZPA - Application Discovery Sweep (first-time access to >N internal apps)\n"
    "let Window = 7d;\n"
    "let Recent = 1d;\n"
    "let Baseline = CommonSecurityLog\n"
    "| where TimeGenerated between (ago(Window) .. ago(Recent))" + F + "\n"
    "| where DeviceVendor == \"Zscaler\" and AdditionalExtensions has \"ZPA\"\n"
    "| summarize KnownApps = make_set(DeviceCustomString1, 500) by SourceUserName;\n"
    "CommonSecurityLog\n"
    "| where TimeGenerated > ago(Recent)" + F + "\n"
    "| where DeviceVendor == \"Zscaler\" and AdditionalExtensions has \"ZPA\"\n"
    "| join kind=leftouter Baseline on SourceUserName\n"
    "| extend IsNew = isempty(KnownApps) or not(set_has_element(KnownApps, DeviceCustomString1))\n"
    "| where IsNew\n"
    "| summarize NewAppCount = dcount(DeviceCustomString1), NewApps = make_set(DeviceCustomString1, 50),\n"
    "    FirstSeen = min(TimeGenerated) by SourceUserName, SourceIP\n"
    "| where NewAppCount >= 10\n"
    "| order by NewAppCount desc"
)

Q35 = (
    "// Q35 - ZIA - HTTP Method Anomaly: Bulk PUT/DELETE from User Agent\n"
    "CommonSecurityLog\n"
    "| where TimeGenerated > ago(1d)" + F + "\n"
    "| where DeviceVendor == \"Zscaler\"\n"
    "| where RequestMethod in (\"PUT\",\"DELETE\",\"PROPFIND\",\"PROPPATCH\",\"MKCOL\")\n"
    "| where DeviceAction !in (\"block\",\"BLOCK\",\"Blocked\",\"blocked\")\n"
    "| summarize Count = count(), Methods = make_set(RequestMethod, 10), Hosts = make_set(RequestURL, 25)\n"
    "    by SourceUserName, SourceIP, RequestClientApplication\n"
    "| where Count >= 50\n"
    "| order by Count desc"
)

Q36 = (
    "// Q36 - ZIA - Off-Hours Cloud Storage Upload Burst (insider/exfil window)\n"
    "let StoragePatterns = dynamic([\"dropbox\",\"box.com\",\"mega.nz\",\"wetransfer\",\"sendspace\",\"transfer.sh\",\"anonfiles\",\"file.io\"]);\n"
    "CommonSecurityLog\n"
    "| where TimeGenerated > ago(1d)" + F + "\n"
    "| where DeviceVendor == \"Zscaler\"\n"
    "| where DeviceAction !in (\"block\",\"BLOCK\",\"Blocked\",\"blocked\")\n"
    "| where RequestURL has_any (StoragePatterns) or DeviceCustomString2 in (\"FILE_STORAGE\",\"PERSONAL_STORAGE\")\n"
    "| extend Hour = hourofday(TimeGenerated), Dow = dayofweek(TimeGenerated)\n"
    "| where (Hour >= 20 or Hour < 6) or (Dow == 6d or Dow == 0d)\n"
    "| summarize UploadMB = sum(SentBytes)/1024.0/1024.0, Reqs = count(), Sites = make_set(RequestURL, 25)\n"
    "    by SourceUserName, SourceIP\n"
    "| where UploadMB >= 100\n"
    "| order by UploadMB desc"
)

Q37 = (
    "// Q37 - ZPA + EDR: ZPA Auth Failures Followed by DeviceLogon Failures\n"
    "let Window = 6h;\n"
    "let ZPAFails = CommonSecurityLog\n"
    "    | where TimeGenerated > ago(Window)" + F + "\n"
    "    | where DeviceVendor == \"Zscaler\" and AdditionalExtensions has \"ZPA\"\n"
    "    | where DeviceAction in (\"FAILED\",\"failure\",\"DENY\",\"deny\")\n"
    "    | summarize ZPAFailCount = count(), ZPAFirst = min(TimeGenerated), ZPALast = max(TimeGenerated),\n"
    "        Apps = make_set(DeviceCustomString1, 25) by SourceUserName, SourceIP;\n"
    "let EDRFails = SecurityAlert\n"
    "    | where TimeGenerated > ago(Window)\n"
    "    | where AlertName has_any (\"logon\",\"failed sign-in\",\"brute\",\"credential\")\n"
    "    | extend ParsedEntities = parse_json(Entities)\n"
    "    | mv-expand E = ParsedEntities\n"
    "    | extend U = tostring(E.Name), I = tostring(E.Address)\n"
    "    | where isnotempty(U) or isnotempty(I)\n"
    "    | summarize EDRAlerts = count(), AlertNames = make_set(AlertName, 10) by U, I;\n"
    "ZPAFails\n"
    "| join kind=inner EDRFails on $left.SourceUserName == $right.U\n"
    "| order by ZPAFailCount desc"
)

new_hunts = [
    hunt("CSL_Hunt_Q32_Zscaler_DoH_Egress",         "CSL Hunt Q32 - Zscaler DoH Egress to Non-Sanctioned Resolvers",     Q32, "CommandAndControl"),
    hunt("CSL_Hunt_Q33_Zscaler_Push_Phishing",      "CSL Hunt Q33 - Zscaler Browser-Push Notification Phishing",         Q33, "InitialAccess"),
    hunt("CSL_Hunt_Q34_ZPA_App_Discovery_Sweep",    "CSL Hunt Q34 - ZPA Application Discovery Sweep (first-time)",       Q34, "Discovery"),
    hunt("CSL_Hunt_Q35_Zscaler_HTTP_Method_Anom",   "CSL Hunt Q35 - Zscaler HTTP Method Anomaly: Bulk PUT/DELETE",       Q35, "Exfiltration, Impact"),
    hunt("CSL_Hunt_Q36_OffHours_CloudStorage_Burst","CSL Hunt Q36 - Off-Hours Cloud Storage Upload Burst",               Q36, "Exfiltration"),
    hunt("CSL_Hunt_Q37_ZPA_EDR_AuthFail_Combo",     "CSL Hunt Q37 - ZPA + EDR Auth-Failure Correlation",                 Q37, "CredentialAccess"),
]

nested_idx = next(i for i, r in enumerate(d['resources']) if r.get('type') == 'Microsoft.Resources/deployments')
d['resources'] = d['resources'][:nested_idx] + new_hunts + d['resources'][nested_idx:]
P.write_text(json.dumps(d, indent=2), encoding="utf-8")
print(f"Added {len(new_hunts)} new hunts. Total resources: {len(d['resources'])}")
