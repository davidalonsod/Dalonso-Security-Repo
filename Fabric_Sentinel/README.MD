
Microsoft Sentinel + Microsoft Fabric — Better Together Lab
Sentinel tells you what happened. Fabric helps you understand why, how it's connected and what to look at next.

This repository contains everything needed to build an AI-powered SOC analytics layer in Microsoft Fabric on top of the Microsoft Sentinel data lake, without copying or re-ingesting your security data. It includes ready-to-import Real-Time Dashboards, KQL scripts, Fabric notebooks, a Fabric Graph model, a Power BI executive report, a Data Agent configuration and demo material.

Sentinel + Fabric

Table of contents
What is this?
Architecture
Capabilities
Benefits
Repository structure
Requirements
Step-by-step deployment
Dashboards and the tables they need
Demo walkthrough
Troubleshooting
Clean-up
Resources
Disclaimer
What is this?
Security teams collect more data than ever, but most of it sits unused for weeks or months. The Microsoft Sentinel data lake keeps security data at low cost for long periods (up to 12 years). With the Fabric integration, that same data is mirrored into Microsoft Fabric as shortcuts, so you can query it with Fabric's analytics engines without copying it.

On top of that single mirrored copy, this lab builds:

#	Demo	Fabric item	What it shows
1	Live Dashboard	Real-Time Dashboard (KQL)	Identity, MDE, MDO, alerts & incidents in real time
2	KQL Job	Data pipeline + KQL table	Scheduled detections (brute force, password spray, botnet, incident risk) stored as findings
3	Graph	Fabric Graph	Users ↔ IPs ↔ countries ↔ apps ↔ incidents as an interactive graph
4	Notebook	Spark notebook	Identity anomaly detection with machine learning
5	Power BI	Power BI report	Executive SOC KPIs, publishable in Teams
6	Data Agent	Fabric Data Agent	"SOC Analyst Agent": ask questions in natural language
Architecture
┌──────────────────────────────┐
│  Microsoft Sentinel          │  Detect & respond (SIEM / XDR)
│  + Sentinel data lake        │  Long-term, low-cost retention
└──────────────┬───────────────┘
               │  Mirror (shortcuts — no data copy)
               ▼
┌──────────────────────────────────────────────────────────────┐
│  Microsoft Fabric workspace                                   │
│                                                               │
│  Mirrored Sentinel DB (read-only) ──► Eventhouse SOC_Analytics│
│        (shortcuts, query acceleration)   (functions, findings │
│                                           tables, graph prep) │
│                                                               │
│  ┌────────────┐ ┌──────────┐ ┌────────┐ ┌────────┐ ┌────────┐ │
│  │ Real-Time  │ │ Pipelines│ │ Graph  │ │Notebook│ │ Data   │ │
│  │ Dashboards │ │ (KQL Job)│ │        │ │ (Spark)│ │ Agent  │ │
│  └────────────┘ └──────────┘ └────────┘ └────────┘ └────────┘ │
│                         │                                     │
│                         ▼                                     │
│                  Power BI executive report ──► Teams          │
└──────────────────────────────────────────────────────────────┘
Key design rules

The mirrored Sentinel database is read-only. All writes (functions, tables, pipelines) go to your own Eventhouse KQL database (SOC_Analytics in this lab).
Mirrored tables are external tables / shortcuts: query them with external_table('TableName').
Turn on query acceleration on the shortcuts you query often, for performance.
Capabilities
1. Real-Time Dashboards (5 dashboards, ~200 tiles)
Identity Investigation: sign-ins over time, failures, top apps, geolocation, impossible travel, brute force, password spray, botnet patterns, per-user drill-down (MFA, devices, timeline).
MDO – BEC & AiTM Live: phishing, business email compromise and adversary-in-the-middle signals.
MDE – Endpoint Threat Live: processes, network, logons, registry, alerts and evidence per device.
Alerts, Incidents & Behaviors: alert trends per product, MITRE ATT&CK techniques, detection surface, noisiest incidents, open incidents, detection health.
Apps & Identity Correlation: cross-domain correlation of apps, identities and compromised entities.
Parameters (time range, user, IP, entity) and tiles you can modify in Fabric.
2. KQL Jobs as Fabric pipelines
Scheduled detections that write findings tables (for example EntraBruteForceFindings, DailyIncidentRiskFindings, InsiderRiskFindings).
Same concept as Sentinel data lake KQL jobs: run a use case over large tables and keep only the results.
Hourly or daily schedules, with history kept for trend analysis.
3. Fabric Graph
IdentityAttackGraph: user → signs in from → IP → located in → country; IP → attacked → user; user → uses → app.
IncidentEntityGraph: incident → involves → user / host / IP.
Query visually (Query builder) or with GQL (Code editor).
4. Identity anomaly detection notebook
Reads Sentinel sign-in data through the Spark Kusto connector.
Computes per-user behaviour (logons, failures, countries) and flags anomalies with ML.
Writes results to Delta tables and produces visuals.
5. Power BI executive report
KPIs: compromised IPs, failed logons, attacks per country, attack patterns (brute force / botnet), users at risk with risk score.
Built for CISOs and leadership; publish to Teams.
6. SOC Analyst Data Agent
Natural-language questions over the SOC data, for example:
"Give me a security summary for the last 7 days, with failures."
"Which IPs ran password spray attacks this week and who was targeted?"
"Where are the attacks coming from? Show countries, cities and IPs."
"Are there any impossible-travel sign-ins?"
Backed by KQL functions: AttackFindings(), ImpossibleTravel(), LogonFailureHistory(), UsersAtRisk().
Benefits
Benefit	Why it matters
One copy of the data	Mirroring uses shortcuts: no duplicate ingestion, no extra storage pipelines.
Lower cost	Keep long-term data in the low-cost data lake and analyse it in Fabric only when needed.
Long retention	Hunt and report over months or years of history (up to 12 years).
Richer analytics	Real-time dashboards, graph, ML notebooks and Power BI on the same data.
Your own detections	Pipelines run custom detections on your schedule and keep the findings.
AI for analysts	The Data Agent lets analysts ask questions in natural language instead of writing KQL.
Executive visibility	Power BI reports in Teams for leaders who never open Sentinel or Fabric.
Data science ready	The same data serves data scientists through notebooks and Delta tables.
Reuse existing capacity	If you already have Fabric, share the capacity with other workloads.
Repository structure
.
├── README.md
├── dashboards/                     # Real-Time Dashboard JSON (import into Fabric)
│   ├── dashboard-Identity Investigation-fixed.json
│   ├── dashboard-Identity Investigation-native.json
│   ├── dashboard-MDO - BEC & AiTM Live v3.json
│   ├── dashboard-MDO - BEC & AiTM Live v2.json   # needs UrlClickEvents / EmailPostDeliveryEvents
│   ├── dashboard-MDE - Endpoint Threat Live v3.json
│   ├── dashboard-Alerts Incidents & Behaviors.json
│   └── dashboard-Apps & Identity Correlation.json
├── kql/                            # Queries behind each dashboard and graph prep
│   ├── Identity-Investigation-queries.kql
│   ├── MDO-BEC-AiTM-queries.kql
│   ├── MDE-Endpoint-queries.kql
│   ├── Alerts-Behaviors-queries.kql
│   ├── Apps-Identity-queries.kql
│   └── Graph-Tables.kql
├── kql-jobs/                       # Findings tables + pipeline queries   [add your .kql files]
├── data-agent/                     # Agent instructions, example queries, KQL functions   [add]
├── notebooks/
│   ├── Identity-Anomaly-Detection-Fabric.ipynb
│   └── Fabric-Graph-Prep.ipynb
├── powerbi/
│   ├── SOC-Executive-Report.zip            # PBIP project (Power BI Desktop)
│   └── SOC-Executive-Report-M-queries-and-DAX.txt
├── docs/
│   ├── Deployment-Guide.docx
│   └── Article.docx
└── images/
    ├── sentinel-fabric-youtube-infographic.png
    └── sentinel-fabric-youtube-thumbnail-1280x720.png
⚠️ Before publishing, remove tenant-specific values (workspace IDs, Eventhouse URIs, user names, IPs) from JSON, notebooks and PBIP files and replace them with placeholders such as <YOUR_EVENTHOUSE_QUERY_URI>.

Requirements
Licensing and services
Microsoft Sentinel in the Microsoft Defender portal with the Sentinel data lake onboarded.
Microsoft Fabric capacity (F SKU, or a trial). Larger capacity = faster queries; F64 or higher recommended for Graph and Data Agent demos.
Power BI (Pro or PPU, or Fabric capacity) to publish the report.
Power BI Desktop (latest) to open the PBIP project.
Optional for data sources: Microsoft Entra ID, Defender for Endpoint, Defender for Office 365 connectors.
Fabric tenant settings (Fabric admin portal)
Users can create Fabric items.
Copilot and Azure OpenAI Service enabled (required for Data Agent).
Fabric data agent enabled.
Graph (preview) enabled if you deploy the Graph demo.
Cross-geo processing for AI enabled if your capacity region requires it.
Permissions
Who	Needs
Lab builder	Fabric capacity admin or workspace Admin; Sentinel data lake permissions to create the Fabric mirror (Security Administrator or equivalent).
Analysts	Viewer (or Contributor) on the Fabric workspace.
Executives	Access to the published Power BI report / Teams tab.
Sentinel tables used
Minimum set (all dashboards except MDO v2): SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, SecurityAlert, SecurityIncident, AlertInfo, AlertEvidence, DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, DeviceEvents, DeviceRegistryEvents, EmailEvents, EmailUrlInfo, EmailAttachmentInfo, IdentityLogonEvents, CloudAppEvents, BehaviorAnalytics.

Some Defender tables exist only in Advanced Hunting and are not in the data lake by default (for example CampaignInfo, UrlClickEvents, EmailPostDeliveryEvents, DeviceFileEvents, DeviceInfo). The v3 dashboards avoid them.

Step-by-step deployment
Step 1 — Create the Fabric capacity and workspace
In the Azure portal create a Microsoft Fabric capacity (choose the same region as your Sentinel workspace when possible).
In Fabric, create a workspace (for example Sentinel_Datalake) and assign it to the capacity.
Step 2 — Mirror the Sentinel data lake into Fabric
In the Defender portal go to Microsoft Sentinel → Data lake / Data connectors and enable the Fabric integration (federated connector).
Select the Fabric workspace and the tables to mirror. You don't need 100% of the tables — choose only what you'll use.
In Fabric, confirm a mirrored Sentinel database appears in the workspace (read-only).
Step 3 — Create the Eventhouse for your own objects
In the workspace create an Eventhouse (for example SOC_Analytics).
Inside its KQL database, add shortcuts to the mirrored Sentinel tables (New → OneLake shortcut → Microsoft OneLake → mirrored database) and turn Accelerate on.
Or enable acceleration with KQL:
.alter external table SigninLogs policy query_acceleration
'{"IsEnabled": true, "Hot": "30.00:00:00"}'
Test:
external_table('SigninLogs') | take 10
Step 4 — Import the Real-Time Dashboards
New item → Real-Time Dashboard → Import from file, select a JSON from /dashboards.
Open Manage → Data sources and point the data source to your SOC_Analytics KQL database (or the mirrored DB).
Save, set the time range and refresh. Repeat for each dashboard.
Step 5 — Create the KQL Jobs (findings + pipelines)
In SOC_Analytics create the findings tables (for example EntraBruteForceFindings, DailyIncidentRiskFindings, InsiderRiskFindings) with .create table.
Create a Data pipeline with a KQL activity that runs the detection query and appends the results:
.set-or-append EntraBruteForceFindings <| <detection query>
.set-or-append must start at column 1, without leading spaces or comments, and output columns must match the table types exactly.

Schedule the pipeline (hourly for brute force, daily for incident risk).
Step 6 — Build the Graph (optional)
Run kql/Graph-Tables.kql (or notebooks/Fabric-Graph-Prep.ipynb) to create the node and edge tables.
New item → Graph model, add nodes (User, IP, Country, App, Incident, Host) and edges (signsInFrom, locatedIn, attacked, uses, involves).
Save and wait for Data load completed. Query in the Query builder (diagram) or Code editor (GQL).
Properties become camelCase (UserId → userId). A node must exist before an edge that references it.

Step 7 — Run the identity anomaly notebook
Import notebooks/Identity-Anomaly-Detection-Fabric.ipynb.
Attach a Lakehouse (OneLake catalog → Lakehouse) as default.
Set the configuration cell:
KUSTO_URI = "<YOUR_EVENTHOUSE_QUERY_URI>"
KUSTO_DB  = "<YOUR_KQL_DATABASE>"
Connect → Standard session → Run all. Results go to Delta tables plus visuals.
Step 8 — Create the SOC Analyst Data Agent
New item → Data agent (for example SOC_Analyst_Agent).
Add the SOC_Analytics KQL database as a source (up to five sources).
Create the helper functions in SOC_Analytics (AttackFindings(), ImpossibleTravel(), LogonFailureHistory(), UsersAtRisk()).
Paste the agent instructions and example queries from /data-agent.
Test with the demo questions and Publish.
Step 9 — Power BI executive report
Extract powerbi/SOC-Executive-Report.zip to a local folder (for example C:\PBI, not a syncing OneDrive folder).
Open the .pbip file in Power BI Desktop.
Set the parameters ClusterUri (Eventhouse query URI) and Database.
Refresh and sign in with your organizational account.
Publish to the workspace and add it as a tab in Teams.
Step 10 — (Optional) Generate demo data
Simulations for brute force, password spray and botnet can be appended to the findings tables, tagged with Apps == "SIMULATION".
Real test activity: GTUBE test email (MDO), EICAR file and the Defender detection test (MDE), Attack simulation training.
Dashboards and the tables they need
Dashboard	Tables
Identity Investigation	SigninLogs, AADNonInteractiveUserSignInLogs, AuditLogs, BehaviorAnalytics, SecurityAlert
MDO – BEC & AiTM Live v3	EmailEvents, EmailUrlInfo, EmailAttachmentInfo, CloudAppEvents, SigninLogs, AlertInfo, AlertEvidence
MDO – BEC & AiTM Live v2	v3 tables + UrlClickEvents, EmailPostDeliveryEvents
MDE – Endpoint Threat Live v3	DeviceProcessEvents, DeviceNetworkEvents, DeviceLogonEvents, DeviceEvents, DeviceRegistryEvents, AlertInfo, AlertEvidence
Alerts, Incidents & Behaviors	SecurityAlert, SecurityIncident, AlertInfo, AlertEvidence, BehaviorAnalytics
Apps & Identity Correlation	SigninLogs, AuditLogs, CloudAppEvents, IdentityLogonEvents, SecurityAlert
Check the exact list in the header of each .kql file before deploying.


Troubleshooting
Symptom	Fix
"Not authorized to write" / FollowerDatabaseWriteProtection	The mirrored DB is read-only. Create tables/functions in your own KQL database.
Materialized view not supported on shortcuts	Use stored functions instead; external tables don't support materialized views or update policies.
Query acceleration was not applied for <Table>	Add the shortcut with Accelerate on, or run .alter external table … policy query_acceleration.
Entity ID … not found on a dashboard	Update the dashboard data source to your current database.
Dashboard tile empty	The table isn't mirrored or has no data in the time range; widen the range.
Column not found (LocationDetails, Status, DeviceDetail)	The data lake schema differs from Log Analytics; use Location and geo_info_from_ip_address().
Pipeline timeout (520)	Make the query lighter (project early, shorter range, summarize first).
Notebook NameError	New session — run the configuration cell first.
Spark write SAS token error	Attach a default Lakehouse and use readMode = ForceSingleMode, or build tables with KQL.
Graph shows no diagram	Diagrams render only in the Query builder, not the Code editor. Save and wait for Data load completed.
Power BI layoutOptimization missing / stale files	Use the latest zip and extract to a local, non-syncing folder.
Power BI report blank	Click Refresh and sign in.
Clean-up
Remove simulated data after a demo:

.delete table EntraBruteForceFindings records <| EntraBruteForceFindings | where Apps == "SIMULATION"
Pause or scale down the Fabric capacity when not in use to save cost.

Resources
Microsoft Sentinel data lake — Microsoft Learn
Microsoft Fabric Real-Time Intelligence — Microsoft Learn
Fabric Data agent — Microsoft Learn
Graph in Microsoft Fabric — Microsoft Learn
Disclaimer
This is a community lab provided as is, without warranty. Test in a non-production environment first. Some features used here (Sentinel data lake integration, Fabric Graph, Data agent) may be in preview and can change. Review costs and data-protection requirements before using real security data.

Author: David Alonso Dominguez
