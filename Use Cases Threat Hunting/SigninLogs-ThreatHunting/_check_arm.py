import json, re
arm = json.load(open(r'C:/Users/dalonso/SigninLogs-ThreatHunting/Analytic-Rules/azuredeploy.json'))
arm_str = json.dumps(arm)
sub = re.findall(r'"T\d{4}\.\d{3}"', arm_str)
periods = re.findall(r'"queryPeriod":\s*"(P\w+)"', arm_str)
bad_periods = [p for p in periods if re.match(r'P(\d+)D$', p) and int(re.match(r'P(\d+)D$', p).group(1)) > 14]
cd = [m for r in arm['resources'] for m in r['properties'].get('customDetails',{}).keys() if len(m) > 20]
print(f"Sub-techniques in ARM: {sub or 'none'}")
print(f"queryPeriod > P14D:    {bad_periods or 'none'}")
print(f"CustomDetails keys >20: {cd or 'none'}")
