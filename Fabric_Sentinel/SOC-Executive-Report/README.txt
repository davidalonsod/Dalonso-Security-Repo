SOC Executive Report - Power BI project (PBIP)
1. Unzip the folder.
2. Open SOC-Executive-Report.pbip with Power BI Desktop (recent version; enable 'Power BI Project (.pbip) save option' and 'Store reports using enhanced metadata format (PBIR)' in Options > Preview features if asked).
3. When prompted, sign in with your organizational account (Azure Data Explorer / Kusto connector) and select Refresh.
4. Publish to the Sentinel_Datalake workspace.
Data source parameters (Transform data > Edit parameters): ClusterUri = SOC_Analytics Eventhouse Query URI, Database = SOC_Analytics.
Tables: Findings (EntraBruteForceFindings), SignIns (SigninGeo7d), UsersAtRisk (UsersAtRisk()), Incidents (DailyIncidentRiskFindings).
If a source table/function does not exist yet, delete that table in Model view and refresh.
Map: add an Azure Map visual with Findings[Latitude], Findings[Longitude], size = Attack Failures, legend = Pattern.
