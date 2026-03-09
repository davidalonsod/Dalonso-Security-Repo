import json
arm = json.load(open(r'C:/Users/dalonso/SigninLogs-ThreatHunting/Analytic-Rules/azuredeploy.json'))
issues = []
for r in arm['resources']:
    p = r['properties']
    cd = p.get('customDetails', {})
    q = p.get('query', '')
    for col in cd.keys():
        if col not in q:
            issues.append(f'MISSING [{col}] in: {p["displayName"][:60]}')
if issues:
    for i in issues: print(i)
else:
    print('All customDetails columns present in their queries.')
