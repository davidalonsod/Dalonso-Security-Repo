# NetworkAllowlist — IP / CIDR / Range Exclusion

A single Sentinel **watchlist** that every SigninLogs analytic rule and hunting
query consults to suppress false positives from trusted source networks
(corporate egress, VPN concentrators, NAT gateways, test ranges, partner IPs,
etc.).

---

## 1. Watchlist schema

| Column       | Example              | Notes                                                       |
|--------------|----------------------|-------------------------------------------------------------|
| `IPOrRange`  | `163.10.0.0/16`     | **Required.** Single IP, CIDR or `start-end` hyphen range.  |
| `Description`| `Corporate egress`   | Free text — who/what this represents.                       |
| `Owner`      | `SOC`                | Accountable team.                                           |
| `AddedDate`  | `2026-04-20`         | ISO date the entry was added.                               |

Supported `IPOrRange` formats:

- Single IPv4          → `203.0.113.45`
- CIDR subnet          → `10.0.0.0/8`, `163.10.0.0/16`
- Hyphenated range     → `10.20.30.1-10.20.30.50`

IPv6 entries are passed through unchanged (the KQL filter only suppresses IPv4
matches — IPv6 rows are never falsely excluded).

---

## 2. One-time deployment

### Portal
1. Microsoft Sentinel → **Configuration → Watchlists → + New**
2. **Alias:** `NetworkAllowlist`
3. **Search key:** `IPOrRange`
4. Upload `NetworkAllowlist.csv`

### ARM
```powershell
$csv = [Convert]::ToBase64String([IO.File]::ReadAllBytes("NetworkAllowlist.csv"))
New-AzResourceGroupDeployment `
  -ResourceGroupName "sentinel-rg" `
  -TemplateFile      "azuredeploy-watchlist.json" `
  -workspaceName     "CyberSOC" `
  -watchlistItemsBase64 $csv
```

---

## 3. KQL pattern used by rules & hunting queries

Every analytic rule and hunting query embeds this block at the top:

```kql
// ---- Network Allowlist (exclude trusted IPs / CIDR / ranges) ----
let _allow = materialize(
    union isfuzzy=true
        (print R = "" | take 0),
        (_GetWatchlist('NetworkAllowlist') | project R = tostring(IPOrRange))
    | where isnotempty(R));
let _allowCIDR  = toscalar(_allow
    | where R !matches regex @'^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$'
    | extend R = iff(R has '/', R, strcat(R, '/32'))
    | summarize make_list(R));
let _allowRange = toscalar(_allow
    | where R matches regex @'^\d+\.\d+\.\d+\.\d+-\d+\.\d+\.\d+\.\d+$'
    | summarize make_list(R));
let _ExcludeAllowlistedIPs = (T:(IPAddress:string)) {
    T
    | extend IPAddress = tostring(IPAddress)
    | where array_length(_allowCIDR) == 0
         or isnull(ipv4_is_in_any_range(IPAddress, _allowCIDR))
         or not(ipv4_is_in_any_range(IPAddress, _allowCIDR))
    | mv-apply _r = _allowRange to typeof(string) on (
        extend _lo = tostring(split(_r, '-')[0]),
               _hi = tostring(split(_r, '-')[1])
        | extend _inRange = ipv4_compare(IPAddress, _lo) >= 0
                        and ipv4_compare(IPAddress, _hi) <= 0
        | summarize _anyInRange = max(toint(_inRange)))
    | where isnull(_anyInRange) or _anyInRange == 0
    | project-away _anyInRange
};
```

Applied via:

```kql
SigninLogs
| invoke _ExcludeAllowlistedIPs()
| where TimeGenerated > ago(1h)
| ...
```

- `union isfuzzy=true` → rules don't fail if the watchlist hasn't been created
  yet; behavior gracefully degrades to "no exclusions".
- The UDF works on any table that exposes an `IPAddress` column
  (`SigninLogs`, `AADNonInteractiveUserSignInLogs`, `SigninLogs` subsets, etc.).
- Watchlist changes take effect within ~5 min — no rule redeploy needed.

---

## 4. Operational guidance

- **Do not** add threat-intel IOCs here — this list *suppresses* detections.
- Review quarterly. Old egress blocks expire as infra changes.
- For per-rule suppression (e.g. a specific IP only excluded from one rule),
  handle it via Sentinel **Automation rules** instead of this watchlist.
