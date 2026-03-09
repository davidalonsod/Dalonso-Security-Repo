"""
Build script: SigninLogs Analytic Rules (10 rules)
Creates YAML files + azuredeploy.json ARM template
"""
import json, re, os

BASE = "C:/Users/dalonso/SigninLogs-ThreatHunting/Analytic-Rules"
RULES_DIR = f"{BASE}/rules"
ARM_PATH  = f"{BASE}/azuredeploy.json"

WORKSPACE_PARAM = "parameters('workspace')"

# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------
RULES = [
  {
    "id": "c1d2e3f4-a5b6-4c7d-8e9f-0a1b2c3d4e5f",
    "num": "01",
    "slug": "PasswordSpray",
    "name": "SigninLogs — Password Spray Attack (Single IP, Many Accounts)",
    "desc": (
        "Detects password spray attacks where a single IP address targets 10 or more "
        "distinct user accounts with authentication failures within a 1-hour window. "
        "Attackers deliberately stay under per-user lockout thresholds. "
        "MITRE ATT&CK: T1110.003 (Password Spraying)."
    ),
    "severity": "High",
    "freq": "PT1H", "period": "PT1H",
    "tactics": ["CredentialAccess"],
    "techniques": ["T1110"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "query": """\
let timeframe = 1h;
let userThreshold = 10;
let failureThreshold = 5;
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType != "0"
| summarize
    FailedAttempts = count(),
    UniqueUsers    = dcount(UserPrincipalName),
    TargetedUsers  = make_set(UserPrincipalName, 50),
    StartTime      = min(TimeGenerated),
    EndTime        = max(TimeGenerated),
    Apps           = make_set(AppDisplayName, 5),
    Locations      = make_set(Location, 3)
  by IPAddress
| where UniqueUsers >= userThreshold and FailedAttempts >= failureThreshold
| project
    TimeGenerated  = StartTime,
    IPAddress, UniqueUsers, FailedAttempts,
    TargetedUsers, EndTime, Apps, Locations""",
    "entities": [
      {"type": "IP", "field": "Address", "col": "IPAddress"},
    ],
    "custom": {"UniqueUsers": "UniqueUsers", "FailedAttempts": "FailedAttempts"},
    "ado_title":  "Password Spray from {{IPAddress}} — {{UniqueUsers}} accounts targeted",
    "ado_desc": "{{FailedAttempts}} failures from {{IPAddress}} targeting {{UniqueUsers}} accounts in 1 hour.",
    "group_by": ["IP"],
  },
  {
    "id": "d2e3f4a5-b6c7-4d8e-9f0a-1b2c3d4e5f6a",
    "num": "02",
    "slug": "BruteForceSuccessChain",
    "name": "SigninLogs — Brute Force Success Chain (Possible Account Breach)",
    "desc": (
        "Detects a successful sign-in occurring within 30 minutes of 5 or more failed "
        "attempts from the same IP against the same user. This pattern is a strong "
        "indicator of a successful breach following a brute force attack. "
        "MITRE ATT&CK: T1110 (Brute Force), T1078 (Valid Accounts)."
    ),
    "severity": "High",
    "freq": "PT1H", "period": "PT1H",
    "tactics": ["CredentialAccess", "InitialAccess"],
    "techniques": ["T1110", "T1078"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "query": """\
let timeframe        = 1h;
let failureThreshold = 5;
let successWindow    = 30m;
let FailedLogins =
    SigninLogs
    | where TimeGenerated > ago(timeframe)
    | where ResultType != "0"
    | summarize
        FailureCount   = count(),
        LastFailure    = max(TimeGenerated),
        FailureReasons = make_set(ResultDescription, 5)
      by UserPrincipalName, IPAddress
    | where FailureCount >= failureThreshold;
let SuccessfulLogins =
    SigninLogs
    | where TimeGenerated > ago(timeframe)
    | where ResultType == "0"
    | project
        UserPrincipalName, IPAddress,
        SuccessTime = TimeGenerated,
        Location, AppDisplayName,
        RiskLevelDuringSignIn;
FailedLogins
| join kind=inner SuccessfulLogins on UserPrincipalName, IPAddress
| where SuccessTime > LastFailure
| where SuccessTime - LastFailure <= successWindow
| extend
    TimeSinceLastFailure = datetime_diff("minute", SuccessTime, LastFailure)
| project
    TimeGenerated        = SuccessTime,
    UserPrincipalName, IPAddress, Location,
    AppDisplayName, FailureCount,
    TimeSinceLastFailure, FailureReasons,
    RiskLevelDuringSignIn""",
    "entities": [
      {"type": "Account", "field": "FullName", "col": "UserPrincipalName"},
      {"type": "IP",      "field": "Address",  "col": "IPAddress"},
    ],
    "custom": {"FailureCount": "FailureCount", "TimeSinceLastFailure": "TimeSinceLastFailure"},
    "ado_title":  "Brute Force Breach — {{UserPrincipalName}} ({{FailureCount}} failures then success)",
    "ado_desc": "Sign-in from {{IPAddress}} succeeded after {{FailureCount}} failures — possible account compromise.",
    "group_by": ["Account", "IP"],
  },
  {
    "id": "e3f4a5b6-c7d8-4e9f-0a1b-2c3d4e5f6a7b",
    "num": "03",
    "slug": "CredentialStuffing",
    "name": "SigninLogs — Credential Stuffing Attack (High-Velocity Invalid Credentials)",
    "desc": (
        "Detects credential stuffing attacks: a single IP generating 50 or more "
        "ResultType 50126 errors (invalid username or password) against multiple "
        "accounts. Attackers use credential lists from previous data breaches. "
        "MITRE ATT&CK: T1110.004 (Credential Stuffing)."
    ),
    "severity": "High",
    "freq": "PT6H", "period": "P7D",
    "tactics": ["CredentialAccess"],
    "techniques": ["T1110"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "query": """\
let velocityThreshold = 50;
SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == "50126"
| summarize
    InvalidCredAttempts = count(),
    UniqueUsers         = dcount(UserPrincipalName),
    Users               = make_set(UserPrincipalName, 50),
    StartTime           = min(TimeGenerated),
    EndTime             = max(TimeGenerated),
    Locations           = make_set(Location, 5)
  by IPAddress
| where InvalidCredAttempts >= velocityThreshold
| project
    TimeGenerated = StartTime,
    IPAddress, InvalidCredAttempts, UniqueUsers,
    Users, EndTime, Locations""",
    "entities": [
      {"type": "IP", "field": "Address", "col": "IPAddress"},
    ],
    "custom": {"InvalidCredAttempts": "InvalidCredAttempts", "UniqueUsers": "UniqueUsers"},
    "ado_title":  "Credential Stuffing from {{IPAddress}} — {{InvalidCredAttempts}} attempts",
    "ado_desc": "{{UniqueUsers}} accounts targeted with invalid credentials (50126) from {{IPAddress}} over 7 days.",
    "group_by": ["IP"],
  },
  {
    "id": "f4a5b6c7-d8e9-4f0a-1b2c-3d4e5f6a7b8c",
    "num": "04",
    "slug": "ImpossibleTravel",
    "name": "SigninLogs — Impossible Travel (3+ Countries in 1 Hour)",
    "desc": (
        "Detects users authenticating from 3 or more distinct geographic locations "
        "within a 1-hour window — physically impossible travel. Indicates account "
        "compromise, credential sharing, or VPN/proxy abuse. "
        "MITRE ATT&CK: T1078 (Valid Accounts)."
    ),
    "severity": "Medium",
    "freq": "PT6H", "period": "P7D",
    "tactics": ["InitialAccess"],
    "techniques": ["T1078"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "query": """\
SigninLogs
| where TimeGenerated > ago(7d)
| where isnotempty(Location) and isnotempty(IPAddress)
| summarize
    UniqueLocations = dcount(Location),
    Locations       = make_set(Location),
    IPs             = make_set(IPAddress),
    FailedCount     = countif(ResultType != "0"),
    SuccessCount    = countif(ResultType == "0"),
    StartTime       = min(TimeGenerated),
    EndTime         = max(TimeGenerated)
  by UserPrincipalName
| where UniqueLocations >= 3
| project
    TimeGenerated = StartTime,
    UserPrincipalName, UniqueLocations,
    Locations, IPs, FailedCount, SuccessCount, EndTime""",
    "entities": [
      {"type": "Account", "field": "FullName", "col": "UserPrincipalName"},
    ],
    "custom": {"UniqueLocations": "UniqueLocations", "FailedCount": "FailedCount"},
    "ado_title":  "Impossible Travel — {{UserPrincipalName}} across {{UniqueLocations}} countries",
    "ado_desc": "User authenticated from {{UniqueLocations}} distinct countries — impossible physical travel detected.",
    "group_by": ["Account"],
  },
  {
    "id": "a5b6c7d8-e9f0-4a1b-2c3d-4e5f6a7b8c9d",
    "num": "05",
    "slug": "LegacyAuthBruteForce",
    "name": "SigninLogs — Legacy Authentication Brute Force (IMAP/POP/SMTP)",
    "desc": (
        "Detects brute force attacks using legacy authentication protocols (IMAP, POP3, "
        "SMTP, Exchange ActiveSync). Legacy auth bypasses MFA and Conditional Access — "
        "any sustained attack via these protocols warrants immediate investigation. "
        "MITRE ATT&CK: T1110 (Brute Force), T1550 (Use Alternate Authentication Material)."
    ),
    "severity": "High",
    "freq": "PT1H", "period": "PT1H",
    "tactics": ["CredentialAccess", "DefenseEvasion"],
    "techniques": ["T1110", "T1550"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "query": """\
let failureThreshold = 10;
let legacyProtocols  = dynamic([
    "IMAP", "POP", "SMTP", "Authenticated SMTP",
    "Exchange ActiveSync", "Other clients"]);
SigninLogs
| where TimeGenerated > ago(1h)
| where ClientAppUsed in (legacyProtocols)
| where ResultType != "0"
| summarize
    FailedAttempts = count(),
    UniqueUsers    = dcount(UserPrincipalName),
    TargetedUsers  = make_set(UserPrincipalName, 50),
    Protocols      = make_set(ClientAppUsed),
    StartTime      = min(TimeGenerated),
    EndTime        = max(TimeGenerated),
    Locations      = make_set(Location, 5)
  by IPAddress
| where FailedAttempts >= failureThreshold
| project
    TimeGenerated = StartTime,
    IPAddress, FailedAttempts, UniqueUsers,
    TargetedUsers, Protocols, Locations, EndTime""",
    "entities": [
      {"type": "IP", "field": "Address", "col": "IPAddress"},
    ],
    "custom": {"FailedAttempts": "FailedAttempts", "UniqueUsers": "UniqueUsers"},
    "ado_title":  "Legacy Auth Brute Force from {{IPAddress}} — {{UniqueUsers}} accounts",
    "ado_desc": "{{FailedAttempts}} failed legacy auth attempts (IMAP/POP/SMTP) from {{IPAddress}}.",
    "group_by": ["IP"],
  },
  {
    "id": "b6c7d8e9-f0a1-4b2c-3d4e-5f6a7b8c9d0e",
    "num": "06",
    "slug": "PrivilegedAccountAttack",
    "name": "SigninLogs — Privileged Account Under Attack (Low-Threshold Failures)",
    "desc": (
        "Detects authentication failures against accounts with admin or privileged naming "
        "conventions. Uses a lower threshold (3 failures) than standard brute force rules "
        "because any attack against privileged accounts is high-priority. "
        "MITRE ATT&CK: T1110 (Brute Force), T1078 (Valid Accounts — Privileged)."
    ),
    "severity": "High",
    "freq": "PT1H", "period": "PT1H",
    "tactics": ["CredentialAccess", "PrivilegeEscalation"],
    "techniques": ["T1110", "T1078"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "query": """\
let failureThreshold  = 3;
let privilegedKeywords = dynamic([
    "admin", "administrator", "root", "global", "security",
    "privileged", "svc", "elevated", "tier0",
    "da-", "ea-", "ga-", "pa-"]);
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"
| where UserPrincipalName has_any (privilegedKeywords)
    or UserPrincipalName contains "_adm"
    or UserPrincipalName startswith "adm"
| summarize
    FailedAttempts = count(),
    UniqueIPs      = dcount(IPAddress),
    SourceIPs      = make_set(IPAddress, 20),
    StartTime      = min(TimeGenerated),
    EndTime        = max(TimeGenerated),
    Locations      = make_set(Location, 5),
    Apps           = make_set(AppDisplayName, 5),
    FailureReasons = make_set(ResultDescription, 5)
  by UserPrincipalName
| where FailedAttempts >= failureThreshold
| project
    TimeGenerated = StartTime,
    UserPrincipalName, FailedAttempts, UniqueIPs,
    SourceIPs, Locations, Apps, FailureReasons, EndTime""",
    "entities": [
      {"type": "Account", "field": "FullName",  "col": "UserPrincipalName"},
    ],
    "custom": {"FailedAttempts": "FailedAttempts", "UniqueIPs": "UniqueIPs"},
    "ado_title":  "Privileged Account Attack — {{UserPrincipalName}}",
    "ado_desc": "{{FailedAttempts}} sign-in failures from {{UniqueIPs}} IPs against privileged account.",
    "group_by": ["Account"],
  },
  {
    "id": "c7d8e9f0-a1b2-4c3d-4e5f-6a7b8c9d0e1f",
    "num": "07",
    "slug": "NationStateIP",
    "name": "SigninLogs — Nation State IP Sign-In Detected",
    "desc": (
        "Detects sign-ins where Azure AD Identity Protection tagged the source IP as "
        "affiliated with a nation-state threat actor (estsNationStateIP risk event type). "
        "Requires Entra ID P2 and Microsoft Defender for Identity. "
        "MITRE ATT&CK: T1078 (Valid Accounts)."
    ),
    "severity": "High",
    "freq": "PT6H", "period": "P7D",
    "tactics": ["InitialAccess"],
    "techniques": ["T1078"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "query": """\
SigninLogs
| where TimeGenerated > ago(7d)
| extend V2Risk = tostring(RiskEventTypes_V2)
| where V2Risk contains "estsNationStateIP"
| project
    TimeGenerated,
    UserPrincipalName, IPAddress,
    Location, AppDisplayName,
    ResultType, ResultDescription,
    RiskLevel = RiskLevelDuringSignIn,
    RiskEventTypes_V2""",
    "entities": [
      {"type": "Account", "field": "FullName", "col": "UserPrincipalName"},
      {"type": "IP",      "field": "Address",  "col": "IPAddress"},
    ],
    "custom": {"Location": "Location", "RiskLevel": "RiskLevel"},
    "ado_title":  "Nation State IP Sign-In — {{UserPrincipalName}} from {{IPAddress}}",
    "ado_desc": "Sign-in from {{IPAddress}} flagged as nation-state IP — {{RiskLevel}} risk level.",
    "group_by": ["Account", "IP"],
  },
  {
    "id": "d8e9f0a1-b2c3-4d4e-5f6a-7b8c9d0e1f2a",
    "num": "08",
    "slug": "AttackerInTheMiddle",
    "name": "SigninLogs — Attacker in the Middle (AiTM) Token Theft Detected",
    "desc": (
        "Detects AiTM proxy attacks (Evilginx, Modlishka) that steal session cookies "
        "after MFA. Correlates SecurityAlert 'Anomalous Token' events with "
        "AADUserRiskEvents where RiskEventType == attackerinTheMiddle. "
        "Requires Entra ID P2. MITRE ATT&CK: T1557 (Adversary-in-the-Middle), "
        "T1539 (Steal Web Session Cookie)."
    ),
    "severity": "High",
    "freq": "PT1H", "period": "P7D",
    "tactics": ["CredentialAccess", "Collection"],
    "techniques": ["T1557", "T1539"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "query": """\
let AnomalousTokenRequestIds =
    SecurityAlert
    | where TimeGenerated > ago(7d)
    | where AlertName == "Anomalous Token"
    | mv-expand todynamic(Entities)
    | project Entities
    | extend RequestId = tostring(Entities.RequestId)
    | distinct RequestId;
AADUserRiskEvents
| where TimeGenerated > ago(7d)
| where RequestId has_any (AnomalousTokenRequestIds)
| where RiskEventType == "attackerinTheMiddle"
| join kind=leftouter (
    SigninLogs
    | where TimeGenerated > ago(7d)
    | project
        UserPrincipalName, CorrelationId,
        Location, AppDisplayName, IPAddress,
        RiskLevelDuringSignIn
  ) on $left.CorrelationId == $right.CorrelationId
| project
    TimeGenerated,
    UserPrincipalName,
    RiskEventType, IPAddress,
    Location, AppDisplayName,
    RiskLevelDuringSignIn""",
    "entities": [
      {"type": "Account", "field": "FullName", "col": "UserPrincipalName"},
      {"type": "IP",      "field": "Address",  "col": "IPAddress"},
    ],
    "custom": {"AppDisplayName": "AppDisplayName", "RiskEventType": "RiskEventType"},
    "ado_title":  "AiTM Token Theft — {{UserPrincipalName}} from {{IPAddress}}",
    "ado_desc": "Attacker-in-the-Middle session hijack detected — {{AppDisplayName}} session token stolen post-MFA.",
    "group_by": ["Account", "IP"],
  },
  {
    "id": "e9f0a1b2-c3d4-4e5f-6a7b-8c9d0e1f2a3b",
    "num": "09",
    "slug": "DistributedCoordinatedAttack",
    "name": "SigninLogs — Distributed Coordinated Attack (Botnet, 10+ IPs per User)",
    "desc": (
        "Detects highly distributed attacks where a single user is targeted from 10 or "
        "more unique IP addresses over 30 days. This pattern indicates botnet "
        "infrastructure or a coordinated campaign targeting high-value accounts. "
        "MITRE ATT&CK: T1110 (Brute Force)."
    ),
    "severity": "Medium",
    "freq": "PT12H", "period": "P14D",
    "tactics": ["CredentialAccess"],
    "techniques": ["T1110"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "query": """\
let ipThreshold = 10;
SigninLogs
| where TimeGenerated > ago(14d)
| where ResultType != "0"
| summarize
    UniqueIPs      = dcount(IPAddress),
    FailedAttempts = count(),
    SourceIPs      = make_set(IPAddress, 100),
    StartTime      = min(TimeGenerated),
    EndTime        = max(TimeGenerated),
    Locations      = make_set(Location, 20)
  by UserPrincipalName
| where UniqueIPs >= ipThreshold
| project
    TimeGenerated  = StartTime,
    UserPrincipalName, UniqueIPs,
    FailedAttempts, SourceIPs,
    EndTime, Locations""",
    "entities": [
      {"type": "Account", "field": "FullName", "col": "UserPrincipalName"},
    ],
    "custom": {"UniqueIPs": "UniqueIPs", "FailedAttempts": "FailedAttempts"},
    "ado_title":  "Coordinated Attack — {{UserPrincipalName}} targeted from {{UniqueIPs}} IPs",
    "ado_desc": "{{FailedAttempts}} failures from {{UniqueIPs}} distinct IPs — botnet or coordinated campaign.",
    "group_by": ["Account"],
  },
  {
    "id": "f0a1b2c3-d4e5-4f6a-7b8c-9d0e1f2a3b4c",
    "num": "10",
    "slug": "MFAFatigue",
    "name": "SigninLogs — MFA Fatigue Attack (Push Bombardment)",
    "desc": (
        "Detects MFA fatigue attacks where an attacker repeatedly triggers MFA push "
        "notifications hoping the user approves one out of frustration. Identified by "
        "5 or more MFA result codes (50074, 50076, 50079, 50158) in a 1-hour window "
        "for a single user. MITRE ATT&CK: T1621 (MFA Request Generation)."
    ),
    "severity": "Medium",
    "freq": "PT1H", "period": "PT1H",
    "tactics": ["CredentialAccess"],
    "techniques": ["T1621"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "query": """\
let mfaBombardThreshold = 5;
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType in ("50074", "50076", "50079", "50158")
| summarize
    MFAInterruptCount = count(),
    FirstInterrupt    = min(TimeGenerated),
    LastInterrupt     = max(TimeGenerated),
    SourceIPs         = make_set(IPAddress, 10),
    Locations         = make_set(Location, 5),
    Apps              = make_set(AppDisplayName, 5)
  by UserPrincipalName
| where MFAInterruptCount >= mfaBombardThreshold
| extend
    InterruptDurationMin = datetime_diff("minute", LastInterrupt, FirstInterrupt)
| project
    TimeGenerated         = FirstInterrupt,
    UserPrincipalName,
    MFAInterruptCount,
    InterruptDurationMin,
    SourceIPs, Locations, Apps,
    LastInterrupt""",
    "entities": [
      {"type": "Account", "field": "FullName", "col": "UserPrincipalName"},
    ],
    "custom": {"MFAInterruptCount": "MFAInterruptCount", "InterruptDurationMin": "InterruptDurationMin"},
    "ado_title":  "MFA Fatigue Attack — {{UserPrincipalName}} ({{MFAInterruptCount}} pushes)",
    "ado_desc": "{{MFAInterruptCount}} MFA push notifications in 1 hour for {{UserPrincipalName}} — possible MFA bombardment.",
    "group_by": ["Account"],
  },
  # ── 12 new rules ──────────────────────────────────────────────────────────
  {
    "id": "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d",
    "num": "11",
    "slug": "SlowLowPasswordSpray",
    "name": "SigninLogs \u2014 Slow & Low Password Spray (Multi-Day Evasion)",
    "desc": (
        "Detects password spray campaigns deliberately spread over multiple days to evade "
        "per-hour detection thresholds. Identifies a single IP targeting 3+ distinct "
        "accounts per day across 3+ separate days. Classic TTP from adversary groups "
        "using purchased credential lists at low throttle rates. "
        "MITRE ATT&CK: T1110.003 (Password Spraying)."
    ),
    "severity": "High",
    "freq": "P1D", "period": "P7D",
    "tactics": ["CredentialAccess"],
    "techniques": ["T1110"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "lookback_dur": "P1D",
    "query": """\
let lookback          = 7d;
let minAccountsPerDay = 3;
let minActiveDays     = 3;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType != "0"
| where isnotempty(IPAddress)
| extend Day = bin(TimeGenerated, 1d)
| summarize
    AccountsOnDay = dcount(UserPrincipalName),
    FailuresOnDay = count()
  by IPAddress, Day
| where AccountsOnDay >= minAccountsPerDay
| summarize
    DaysActive    = dcount(Day),
    TotalAccounts = sum(AccountsOnDay),
    TotalFailures = sum(FailuresOnDay),
    ActiveDays    = make_set(Day, 10),
    StartDay      = min(Day),
    EndDay        = max(Day)
  by IPAddress
| where DaysActive >= minActiveDays
| project
    TimeGenerated = EndDay,
    IPAddress,
    DaysActive,
    TotalAccounts,
    TotalFailures,
    StartDay,
    EndDay,
    ActiveDays""",
    "entities": [
      {"type": "IP", "field": "Address", "col": "IPAddress"},
    ],
    "custom": {"DaysActive": "DaysActive", "TotalAccounts": "TotalAccounts", "TotalFailures": "TotalFailures"},
    "ado_title":  "Slow & Low Spray from {{IPAddress}} \u2014 {{DaysActive}} active days, {{TotalAccounts}} accounts",
    "ado_desc": "IP {{IPAddress}} spread {{TotalAccounts}} targeted accounts across {{DaysActive}} active days \u2014 multi-day evasion of per-hour spray detection.",
    "group_by": ["IP"],
  },
  {
    "id": "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e",
    "num": "12",
    "slug": "AccountEnumeration",
    "name": "SigninLogs \u2014 Account Enumeration via Error Code Fingerprinting",
    "desc": (
        "Detects attackers performing user enumeration by analysing sign-in error codes. "
        "Error 50034 (UserNotFound) reveals non-existent accounts; error 50126 confirms "
        "the account exists. A high ratio of 50034 errors indicates systematic enumeration "
        "of valid users before a targeted spray. "
        "MITRE ATT&CK: T1087.002 (Domain Account Discovery), T1110 (Brute Force)."
    ),
    "severity": "High",
    "freq": "PT6H", "period": "PT6H",
    "tactics": ["Discovery", "CredentialAccess"],
    "techniques": ["T1087", "T1110"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "lookback_dur": "PT6H",
    "query": """\
let lookback      = 6h;
let minAttempts   = 20;
let enumRatioMin  = 0.40;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType in ("50034", "50126", "50057", "70011")
| where isnotempty(IPAddress)
| summarize
    TotalAttempts   = count(),
    UserNotFound    = countif(ResultType == "50034"),
    InvalidPassword = countif(ResultType == "50126"),
    AccountDisabled = countif(ResultType == "50057"),
    UniqueTargets   = dcount(UserPrincipalName),
    TargetedUsers   = make_set(UserPrincipalName, 30),
    Locations       = make_set(Location, 3),
    FirstAttempt    = min(TimeGenerated),
    LastAttempt     = max(TimeGenerated)
  by IPAddress
| where TotalAttempts >= minAttempts
| extend EnumRatio = round(todouble(UserNotFound) / TotalAttempts, 2)
| where EnumRatio >= enumRatioMin
| project
    TimeGenerated   = FirstAttempt,
    IPAddress,
    TotalAttempts,
    UserNotFound,
    InvalidPassword,
    UniqueTargets,
    EnumRatio,
    TargetedUsers,
    Locations,
    LastAttempt""",
    "entities": [
      {"type": "IP", "field": "Address", "col": "IPAddress"},
    ],
    "custom": {"TotalAttempts": "TotalAttempts", "UserNotFound": "UserNotFound", "EnumRatio": "EnumRatio"},
    "ado_title":  "Account Enumeration from {{IPAddress}} \u2014 {{EnumRatio}} UserNotFound ratio ({{TotalAttempts}} probes)",
    "ado_desc": "IP {{IPAddress}} probed accounts with {{EnumRatio}} UserNotFound ratio \u2014 user enumeration pattern before a targeted spray attack.",
    "group_by": ["IP"],
  },
  {
    "id": "c3d4e5f6-a7b8-4c9d-0e1f-2a3b4c5d6e7f",
    "num": "13",
    "slug": "ServiceAccountInteractiveLogin",
    "name": "SigninLogs \u2014 Service Account Interactive Browser Sign-In",
    "desc": (
        "Detects service accounts and non-human identities performing interactive "
        "browser-based sign-ins. Service accounts should only authenticate via "
        "client credentials or managed identity flows. Interactive sessions indicate "
        "credential theft or an attacker manually leveraging stolen service account creds. "
        "MITRE ATT&CK: T1078 (Valid Accounts), T1078.004 (Cloud Accounts)."
    ),
    "severity": "High",
    "freq": "PT4H", "period": "PT4H",
    "tactics": ["InitialAccess", "Persistence"],
    "techniques": ["T1078"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "lookback_dur": "PT4H",
    "query": """\
let serviceAccountKeywords = dynamic([
    "svc", "svc-", "svc.", "-svc", "_svc",
    "app-", "app_", "api-", "api_",
    "bot-", "bot_", "sys-", "sys_",
    "func-", "func_", "daemon", "automation",
    "robot", "service_", "service-", "noreply",
    "pipeline", "cicd", "ci-", "cd-"
]);
SigninLogs
| where TimeGenerated > ago(4h)
| where ResultType == "0"
| where IsInteractive == true
| where ClientAppUsed == "Browser"
| where UserPrincipalName has_any (serviceAccountKeywords)
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    RiskLevel = RiskLevelDuringSignIn,
    CAStatus = ConditionalAccessStatus,
    UserAgent""",
    "entities": [
      {"type": "Account", "field": "FullName", "col": "UserPrincipalName"},
      {"type": "IP",      "field": "Address",  "col": "IPAddress"},
    ],
    "custom": {"AppDisplayName": "AppDisplayName", "CAStatus": "CAStatus"},
    "ado_title":  "Service Account Interactive Login \u2014 {{UserPrincipalName}} from {{IPAddress}}",
    "ado_desc": "Service account {{UserPrincipalName}} used a browser session from {{IPAddress}} \u2014 service accounts should never authenticate interactively. Possible credential theft.",
    "group_by": ["Account", "IP"],
  },
  {
    "id": "d4e5f6a7-b8c9-4d0e-1f2a-3b4c5d6e7f8a",
    "num": "14",
    "slug": "PasswordResetThenForeignSignIn",
    "name": "SigninLogs \u2014 Password Reset Followed by New-Country Sign-In (Account Takeover)",
    "desc": (
        "Detects a high-confidence account takeover pattern: a password reset followed "
        "within 2 hours by a successful sign-in from a country not seen in the prior 30 days. "
        "This chain strongly indicates an attacker reset the victim password via a "
        "phishing-obtained session and immediately used the new credential. "
        "MITRE ATT&CK: T1078 (Valid Accounts), T1098 (Account Manipulation)."
    ),
    "severity": "High",
    "freq": "PT2H", "period": "P1D",
    "tactics": ["InitialAccess", "Persistence"],
    "techniques": ["T1078", "T1098"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "lookback_dur": "PT4H",
    "query": """\
let lookback       = 2h;
let baselinePeriod = 30d;
let resetWindow    = 2h;
let ResetEvents =
    AuditLogs
    | where TimeGenerated > ago(lookback + resetWindow)
    | where OperationName in (
          "Reset password (self-service)",
          "Reset user password",
          "Admin reset user password"
      )
    | extend TargetUPN = tolower(tostring(TargetResources[0].userPrincipalName))
    | where isnotempty(TargetUPN)
    | project ResetTime = TimeGenerated, TargetUPN;
let KnownLocations =
    SigninLogs
    | where TimeGenerated between (ago(baselinePeriod) .. ago(lookback))
    | where ResultType == "0"
    | where isnotempty(Location) and Location != "Unknown"
    | distinct UserPrincipalName, Location;
ResetEvents
| join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(lookback + resetWindow)
    | where ResultType == "0"
    | where isnotempty(Location) and Location != "Unknown"
    | extend UserPrincipalName = tolower(UserPrincipalName)
    | project
        UserPrincipalName, SignInTime = TimeGenerated,
        IPAddress, Location, AppDisplayName,
        RiskLevelDuringSignIn
  ) on $left.TargetUPN == $right.UserPrincipalName
| where SignInTime > ResetTime
| where SignInTime - ResetTime <= resetWindow
| join kind=leftanti KnownLocations on UserPrincipalName, Location
| extend MinutesSinceReset = datetime_diff("minute", SignInTime, ResetTime)
| project
    TimeGenerated        = SignInTime,
    UserPrincipalName, IPAddress, Location,
    AppDisplayName, RiskLevelDuringSignIn,
    ResetTime, MinutesSinceReset""",
    "entities": [
      {"type": "Account", "field": "FullName", "col": "UserPrincipalName"},
      {"type": "IP",      "field": "Address",  "col": "IPAddress"},
    ],
    "custom": {"Location": "Location", "MinutesSinceReset": "MinutesSinceReset"},
    "ado_title":  "Account Takeover \u2014 {{UserPrincipalName}} signed in from {{Location}} {{MinutesSinceReset}}m after reset",
    "ado_desc": "Account {{UserPrincipalName}} authenticated from a new country ({{Location}}) only {{MinutesSinceReset}} minutes after a password reset \u2014 strong indicator of account takeover.",
    "group_by": ["Account", "IP"],
  },
  {
    "id": "e5f6a7b8-c9d0-4e1f-2a3b-4c5d6e7f8a9b",
    "num": "15",
    "slug": "OffHoursPrivilegedSignIn",
    "name": "SigninLogs \u2014 Off-Hours Sign-In by Privileged Account",
    "desc": (
        "Detects privileged accounts signing in between 22:00 and 05:00 UTC. "
        "Off-hours admin access is a key hunting signal for insider threats, "
        "living-off-the-land attackers, and compromised admin credentials. "
        "Investigate alongside concurrent AuditLogs activity. "
        "MITRE ATT&CK: T1078 (Valid Accounts), T1098 (Account Manipulation)."
    ),
    "severity": "Medium",
    "freq": "PT1H", "period": "PT1H",
    "tactics": ["InitialAccess", "Persistence"],
    "techniques": ["T1078", "T1098"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "query": """\
let privilegedKeywords = dynamic([
    "admin", "adm-", "adm.", "-adm", "_adm",
    "da-", "ea-", "ga-", "pa-",
    "tier0", "tier-0", "t0-",
    "priv", "svc.adm", "svc-adm",
    "globaladmin", "secadmin", "cloudadmin"
]);
let offHoursStart = 22;
let offHoursEnd   = 5;
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"
| where UserPrincipalName has_any (privilegedKeywords)
| extend HourOfDay = hourofday(TimeGenerated)
| where HourOfDay >= offHoursStart or HourOfDay < offHoursEnd
| project
    TimeGenerated, UserPrincipalName,
    IPAddress, Location,
    AppDisplayName, HourOfDay,
    RiskLevelDuringSignIn, ConditionalAccessStatus,
    IsInteractive""",
    "entities": [
      {"type": "Account", "field": "FullName", "col": "UserPrincipalName"},
      {"type": "IP",      "field": "Address",  "col": "IPAddress"},
    ],
    "custom": {"HourOfDay": "HourOfDay", "AppDisplayName": "AppDisplayName"},
    "ado_title":  "Off-Hours Privileged Sign-In \u2014 {{UserPrincipalName}} at {{HourOfDay}}:00 UTC from {{Location}}",
    "ado_desc": "Privileged account {{UserPrincipalName}} signed in at {{HourOfDay}}:00 UTC outside business hours. Investigate for unauthorized admin activity.",
    "group_by": ["Account"],
  },
  {
    "id": "f6a7b8c9-d0e1-4f2a-3b4c-5d6e7f8a9b0c",
    "num": "16",
    "slug": "ConcurrentMultiCountrySessions",
    "name": "SigninLogs \u2014 Concurrent Sessions from Multiple Countries (Same User)",
    "desc": (
        "Detects a single user successfully signing in from 2 or more distinct countries "
        "within a 30-minute window. Unlike ML-based impossible travel this is deterministic, "
        "requires no Entra ID P2, and catches concurrent attacker + victim sessions running "
        "in parallel from different geos. "
        "MITRE ATT&CK: T1078 (Valid Accounts)."
    ),
    "severity": "High",
    "freq": "PT1H", "period": "PT1H",
    "tactics": ["InitialAccess", "CredentialAccess"],
    "techniques": ["T1078"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "query": """\
let lookback   = 1h;
let maxWindowM = 30;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| where isnotempty(Location) and Location != "Unknown"
| summarize
    UniqueCountries = dcount(Location),
    Countries       = make_set(Location, 10),
    SourceIPs       = make_set(IPAddress, 10),
    Apps            = make_set(AppDisplayName, 5),
    FirstSignIn     = min(TimeGenerated),
    LastSignIn      = max(TimeGenerated)
  by UserPrincipalName
| where UniqueCountries >= 2
| extend WindowMinutes = datetime_diff("minute", LastSignIn, FirstSignIn)
| where WindowMinutes <= maxWindowM
| project
    TimeGenerated = FirstSignIn,
    UserPrincipalName, UniqueCountries,
    Countries, SourceIPs, WindowMinutes,
    Apps, LastSignIn""",
    "entities": [
      {"type": "Account", "field": "FullName", "col": "UserPrincipalName"},
    ],
    "custom": {"UniqueCountries": "UniqueCountries", "Countries": "Countries", "WindowMinutes": "WindowMinutes"},
    "ado_title":  "Concurrent Multi-Country Sessions \u2014 {{UserPrincipalName}} in {{UniqueCountries}} countries ({{WindowMinutes}}min)",
    "ado_desc": "User {{UserPrincipalName}} authenticated from {{UniqueCountries}} different countries within {{WindowMinutes}} minutes \u2014 possible concurrent attacker session.",
    "group_by": ["Account"],
  },
  {
    "id": "a7b8c9d0-e1f2-4a3b-4c5d-6e7f8a9b0c1d",
    "num": "17",
    "slug": "DeviceCodePhishing",
    "name": "SigninLogs \u2014 Device Code Flow Authentication (Phishing Vector)",
    "desc": (
        "Detects successful device code flow authentications where one IP collects tokens "
        "for 2 or more accounts. Attackers phish victims to device.microsoft.com to enter "
        "a code the attacker generated \u2014 bypassing password and MFA. Actively used by "
        "Storm-0539 and Midnight Blizzard. "
        "MITRE ATT&CK: T1566 (Phishing), T1528 (Steal Application Access Token)."
    ),
    "severity": "High",
    "freq": "PT4H", "period": "PT4H",
    "tactics": ["InitialAccess", "CredentialAccess"],
    "techniques": ["T1566", "T1528"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "lookback_dur": "PT4H",
    "query": """\
let lookback      = 4h;
let multiUserMin  = 2;
let highVolumeMin = 5;
SigninLogs
| where TimeGenerated > ago(lookback)
| where AuthenticationProtocol == "deviceCode"
| where ResultType == "0"
| summarize
    SuccessCount  = count(),
    UniqueUsers   = dcount(UserPrincipalName),
    TargetedUsers = make_set(UserPrincipalName, 20),
    Locations     = make_set(Location, 5),
    Apps          = make_set(AppDisplayName, 5),
    FirstSeen     = min(TimeGenerated),
    LastSeen      = max(TimeGenerated)
  by IPAddress
| where UniqueUsers >= multiUserMin or SuccessCount >= highVolumeMin
| project
    TimeGenerated = FirstSeen,
    IPAddress, SuccessCount, UniqueUsers,
    TargetedUsers, Locations, Apps, LastSeen""",
    "entities": [
      {"type": "IP", "field": "Address", "col": "IPAddress"},
    ],
    "custom": {"SuccessCount": "SuccessCount", "UniqueUsers": "UniqueUsers"},
    "ado_title":  "Device Code Phishing \u2014 {{IPAddress}} collected tokens for {{UniqueUsers}} accounts",
    "ado_desc": "IP {{IPAddress}} obtained {{SuccessCount}} device code flow tokens for {{UniqueUsers}} users \u2014 classic device-code phishing pattern (Storm-0539, Midnight Blizzard TTP).",
    "group_by": ["IP"],
  },
  {
    "id": "b8c9d0e1-f2a3-4b4c-5d6e-7f8a9b0c1d2e",
    "num": "18",
    "slug": "LegacyAuthFirstAppearance",
    "name": "SigninLogs \u2014 Legacy Auth First Appearance for Modern-Only Account",
    "desc": (
        "Detects accounts that used exclusively modern auth for the past 14 days but then "
        "suddenly appear using legacy protocols (IMAP4, POP3, SMTP Auth, Exchange ActiveSync). "
        "Legacy auth bypasses Conditional Access and MFA \u2014 this is a high-fidelity signal "
        "of credential theft or policy evasion. "
        "MITRE ATT&CK: T1550 (Use Alternate Auth Material), T1078 (Valid Accounts)."
    ),
    "severity": "High",
    "freq": "PT6H", "period": "P14D",
    "tactics": ["DefenseEvasion", "CredentialAccess"],
    "techniques": ["T1550", "T1078"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "lookback_dur": "PT6H",
    "query": """\
let lookback       = 1d;
let baselinePeriod = 14d;
let legacyClients  = dynamic([
    "Exchange ActiveSync", "IMAP4", "POP3",
    "Authenticated SMTP", "MAPI over HTTP",
    "Other clients; IMAP", "Other clients; POP",
    "Other clients; SMTP"
]);
let ModernOnlyAccounts =
    SigninLogs
    | where TimeGenerated between (ago(baselinePeriod) .. ago(lookback))
    | where ResultType == "0"
    | summarize LegacyCount = countif(ClientAppUsed has_any (legacyClients))
        by UserPrincipalName
    | where LegacyCount == 0
    | project UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| where ClientAppUsed has_any (legacyClients)
| where isnotempty(UserPrincipalName)
| join kind=inner ModernOnlyAccounts on UserPrincipalName
| project
    TimeGenerated, UserPrincipalName,
    IPAddress, Location,
    ClientAppUsed, AppDisplayName,
    RiskLevelDuringSignIn, ConditionalAccessStatus""",
    "entities": [
      {"type": "Account", "field": "FullName", "col": "UserPrincipalName"},
      {"type": "IP",      "field": "Address",  "col": "IPAddress"},
    ],
    "custom": {"ClientAppUsed": "ClientAppUsed", "AppDisplayName": "AppDisplayName"},
    "ado_title":  "Legacy Auth First Appearance \u2014 {{UserPrincipalName}} using {{ClientAppUsed}}",
    "ado_desc": "Account {{UserPrincipalName}} authenticated via {{ClientAppUsed}} from {{IPAddress}} \u2014 account exclusively used modern auth in the prior 14 days. Possible CA bypass.",
    "group_by": ["Account", "IP"],
  },
  {
    "id": "c9d0e1f2-a3b4-4c5d-6e7f-8a9b0c1d2e3f",
    "num": "19",
    "slug": "HighFrequencyAutomatedSignIns",
    "name": "SigninLogs \u2014 High-Frequency Repeated Sign-Ins (Automated Credential Abuse)",
    "desc": (
        "Detects accounts producing 10+ successful sign-in events per hour from the same IP. "
        "At that frequency, activity is almost certainly generated by an automated tool, "
        "a script, or a C2 framework maintaining stolen token freshness. "
        "MITRE ATT&CK: T1078 (Valid Accounts), T1539 (Steal Web Session Cookie)."
    ),
    "severity": "Medium",
    "freq": "PT1H", "period": "PT1H",
    "tactics": ["CredentialAccess", "Persistence"],
    "techniques": ["T1078", "T1539", "T1528"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "query": """\
let loginMinimum = 10;
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType == "0"
| where isnotempty(IPAddress) and isnotempty(UserPrincipalName)
| summarize
    LoginCount  = count(),
    UniqueApps  = dcount(AppDisplayName),
    Apps        = make_set(AppDisplayName, 10),
    Locations   = make_set(Location, 3),
    FirstLogin  = min(TimeGenerated),
    LastLogin   = max(TimeGenerated)
  by UserPrincipalName, IPAddress
| where LoginCount >= loginMinimum
| extend
    WindowMinutes   = datetime_diff("minute", LastLogin, FirstLogin),
    LoginFreqPerMin = round(
        todouble(LoginCount) /
        (todouble(datetime_diff("second", LastLogin, FirstLogin)) / 60.0 + 1.0), 2)
| project
    TimeGenerated = FirstLogin,
    UserPrincipalName, IPAddress,
    LoginCount, UniqueApps,
    LoginFreqPerMin, WindowMinutes,
    Apps, Locations, LastLogin""",
    "entities": [
      {"type": "Account", "field": "FullName", "col": "UserPrincipalName"},
      {"type": "IP",      "field": "Address",  "col": "IPAddress"},
    ],
    "custom": {"LoginCount": "LoginCount", "LoginFreqPerMin": "LoginFreqPerMin"},
    "ado_title":  "Automated Sign-Ins \u2014 {{UserPrincipalName}} from {{IPAddress}} \u2014 {{LoginCount}} logins/hr",
    "ado_desc": "Account {{UserPrincipalName}} produced {{LoginCount}} successful sign-ins/hour from {{IPAddress}} \u2014 automated tooling or C2 token refresh pattern.",
    "group_by": ["Account", "IP"],
  },
  {
    "id": "d0e1f2a3-b4c5-4d6e-7f8a-9b0c1d2e3f4a",
    "num": "20",
    "slug": "NewCountryPrivilegedAdmin",
    "name": "SigninLogs \u2014 First New Country Sign-In for Privileged Account (Deterministic)",
    "desc": (
        "Detects privileged accounts signing in from a country not seen in their 30-day "
        "history. Unlike the ML-based Unfamiliar Sign-in Properties rule this is "
        "deterministic, requires no Entra ID P2, and specifically targets privileged "
        "identities where the risk of compromise is highest. "
        "MITRE ATT&CK: T1078 (Valid Accounts), T1078.004 (Cloud Accounts)."
    ),
    "severity": "High",
    "freq": "PT6H", "period": "P14D",
    "tactics": ["InitialAccess", "PrivilegeEscalation"],
    "techniques": ["T1078"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "lookback_dur": "PT6H",
    "query": """\
let lookback           = 6h;
let baselinePeriod     = 14d;
let privilegedKeywords = dynamic([
    "admin", "adm-", "adm.", "-adm", "_adm",
    "da-", "ea-", "ga-", "pa-",
    "tier0", "tier-0", "t0-",
    "priv", "svc.adm", "svc-adm",
    "globaladmin", "secadmin", "cloudadmin"
]);
let KnownAdminLocations =
    SigninLogs
    | where TimeGenerated between (ago(baselinePeriod) .. ago(lookback))
    | where ResultType == "0"
    | where UserPrincipalName has_any (privilegedKeywords)
    | where isnotempty(Location) and Location != "Unknown"
    | distinct UserPrincipalName, Location;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| where UserPrincipalName has_any (privilegedKeywords)
| where isnotempty(Location) and Location != "Unknown"
| join kind=leftanti KnownAdminLocations on UserPrincipalName, Location
| project
    TimeGenerated, UserPrincipalName,
    IPAddress, Location, AppDisplayName,
    RiskLevel = RiskLevelDuringSignIn, ConditionalAccessStatus,
    IsInteractive""",
    "entities": [
      {"type": "Account", "field": "FullName", "col": "UserPrincipalName"},
      {"type": "IP",      "field": "Address",  "col": "IPAddress"},
    ],
    "custom": {"Location": "Location", "RiskLevel": "RiskLevel"},
    "ado_title":  "New Country Admin Sign-In \u2014 {{UserPrincipalName}} from {{Location}} (first time in 14d)",
    "ado_desc": "Privileged account {{UserPrincipalName}} authenticated from {{Location}} \u2014 country not in 14-day history. Investigate for compromised admin credentials.",
    "group_by": ["Account"],
  },
  {
    "id": "e1f2a3b4-c5d6-4e7f-8a9b-0c1d2e3f4a5b",
    "num": "21",
    "slug": "ConditionalAccessBypass",
    "name": "SigninLogs \u2014 Conditional Access Policy Blocked then Successful Bypass",
    "desc": (
        "Detects a user blocked by Conditional Access (ResultType 53003) who then "
        "achieves a successful sign-in within 4 hours \u2014 possibly via a legacy auth client "
        "that bypasses CA, an unmanaged device, or a CA policy gap. "
        "MITRE ATT&CK: T1078 (Valid Accounts), T1562.001 (Disable or Modify Tools)."
    ),
    "severity": "High",
    "freq": "PT4H", "period": "PT4H",
    "tactics": ["DefenseEvasion", "InitialAccess"],
    "techniques": ["T1078", "T1562"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "lookback_dur": "PT4H",
    "query": """\
let lookback     = 4h;
let bypassWindow = 4h;
let CABlockedUsers =
    SigninLogs
    | where TimeGenerated > ago(lookback)
    | where ResultType == "53003"
    | summarize
        BlockedCount = count(),
        LastBlocked  = max(TimeGenerated),
        BlockedIPs   = make_set(IPAddress, 5),
        BlockedApps  = make_set(AppDisplayName, 5)
      by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| join kind=inner CABlockedUsers on UserPrincipalName
| where TimeGenerated > LastBlocked
| where TimeGenerated - LastBlocked <= bypassWindow
| extend MinutesAfterBlock = datetime_diff("minute", TimeGenerated, LastBlocked)
| project
    TimeGenerated, UserPrincipalName,
    IPAddress, Location, AppDisplayName,
    ClientAppUsed, ConditionalAccessStatus,
    RiskLevelDuringSignIn, BlockedCount,
    BlockedIPs, LastBlocked, MinutesAfterBlock""",
    "entities": [
      {"type": "Account", "field": "FullName", "col": "UserPrincipalName"},
      {"type": "IP",      "field": "Address",  "col": "IPAddress"},
    ],
    "custom": {"BlockedCount": "BlockedCount", "MinutesAfterBlock": "MinutesAfterBlock"},
    "ado_title":  "CA Policy Bypass \u2014 {{UserPrincipalName}} succeeded {{MinutesAfterBlock}}m after {{BlockedCount}} CA blocks",
    "ado_desc": "User {{UserPrincipalName}} was CA-blocked {{BlockedCount}} times then authenticated successfully {{MinutesAfterBlock}} minutes later \u2014 possible legacy auth or unmanaged device bypass.",
    "group_by": ["Account", "IP"],
  },
  {
    "id": "f2a3b4c5-d6e7-4f8a-9b0c-1d2e3f4a5b6c",
    "num": "22",
    "slug": "FreshIPMultiAccountAuth",
    "name": "SigninLogs \u2014 Fresh IP Authenticating Multiple Accounts (Compromised Proxy)",
    "desc": (
        "Detects an IP not seen in the prior 14 days that successfully authenticates "
        "5 or more distinct user accounts within 2 hours. Indicates a newly-provisioned "
        "attack proxy or relay used with a purchased credential list. Complements the "
        "spray rule (failures) by catching pre-validated or successful spray runs. "
        "MITRE ATT&CK: T1110.003 (Password Spraying), T1078 (Valid Accounts)."
    ),
    "severity": "High",
    "freq": "PT2H", "period": "P14D",
    "tactics": ["CredentialAccess", "InitialAccess"],
    "techniques": ["T1110", "T1078"],
    "trigger_op": "gt", "trigger_thresh": 0,
    "lookback_dur": "PT2H",
    "query": """\
let lookback      = 2h;
let baselineDays  = 14d;
let minUsers      = 5;
let KnownIPs =
    SigninLogs
    | where TimeGenerated between (ago(baselineDays) .. ago(lookback))
    | where ResultType == "0"
    | distinct IPAddress;
SigninLogs
| where TimeGenerated > ago(lookback)
| where ResultType == "0"
| where isnotempty(IPAddress)
| join kind=leftanti KnownIPs on IPAddress
| summarize
    UniqueUsers        = dcount(UserPrincipalName),
    AuthenticatedUsers = make_set(UserPrincipalName, 30),
    TotalLogins        = count(),
    Apps               = make_set(AppDisplayName, 5),
    Locations          = make_set(Location, 3),
    ClientTypes        = make_set(ClientAppUsed, 5),
    FirstSeen          = min(TimeGenerated),
    LastSeen           = max(TimeGenerated)
  by IPAddress
| where UniqueUsers >= minUsers
| project
    TimeGenerated = FirstSeen,
    IPAddress, UniqueUsers, TotalLogins,
    AuthenticatedUsers, Apps,
    Locations, ClientTypes, LastSeen""",
    "entities": [
      {"type": "IP", "field": "Address", "col": "IPAddress"},
    ],
    "custom": {"UniqueUsers": "UniqueUsers", "TotalLogins": "TotalLogins"},
    "ado_title":  "Fresh IP Mass Auth \u2014 {{IPAddress}} authenticated {{UniqueUsers}} accounts (not seen in 14d)",
    "ado_desc": "IP {{IPAddress}} (first seen in a 2h window \u2014 not in 14d baseline) successfully authenticated {{UniqueUsers}} distinct accounts \u2014 strong indicator of a newly-deployed attack proxy.",
    "group_by": ["IP"],
  },
]

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def yaml_list(items, indent=2):
    pad = " " * indent
    return "\n".join(f"{pad}- {i}" for i in items)

def yaml_block(text, indent=4):
    pad = " " * indent
    lines = text.rstrip("\n").split("\n")
    return "\n".join(pad + l for l in lines)

def build_yaml(r):
    em_lines = []
    for em in r["entities"]:
        em_lines.append(f"  - entityType: {em['type']}")
        em_lines.append(f"    fieldMappings:")
        em_lines.append(f"      - identifier: {em['field']}")
        em_lines.append(f"        columnName: {em['col']}")
    em_block = "\n".join(em_lines)

    cd_lines = "\n".join(f"  {k}: {v}" for k, v in r["custom"].items())

    tactics_block    = yaml_list(r["tactics"])
    techniques_block = yaml_list(r["techniques"])
    groupby_block    = yaml_list(r["group_by"])

    query_indented = yaml_block(r["query"])

    return f"""id: {r['id']}
name: "{r['name']}"
version: 1.0.0
kind: Scheduled
description: |
  {r['desc']}
severity: {r['severity']}
requiredDataConnectors:
  - connectorId: AzureActiveDirectory
    dataTypes:
      - SigninLogs
queryFrequency: {r['freq']}
queryPeriod: {r['period']}
triggerOperator: {r['trigger_op']}
triggerThreshold: {r['trigger_thresh']}
tactics:
{tactics_block}
relevantTechniques:
{techniques_block}
query: |
{query_indented}
entityMappings:
{em_block}
customDetails:
{cd_lines}
alertDetailsOverride:
  alertDisplayNameFormat: "{r['ado_title']}"
  alertDescriptionFormat: "{r['ado_desc']}"
incidentConfiguration:
  createIncident: true
  groupingConfiguration:
    enabled: true
    reopenClosedIncident: false
    lookbackDuration: {r.get('lookback_dur', 'PT1H')}
    matchingMethod: AllEntities
    groupByEntities:
{groupby_block}
"""

def build_arm_resource(r):
    entity_mappings = []
    for em in r["entities"]:
        entity_mappings.append({
            "entityType": em["type"],
            "fieldMappings": [{"identifier": em["field"], "columnName": em["col"]}]
        })

    custom_details = {k: v for k, v in r["custom"].items()}

    ado_params = set(re.findall(r'\{\{(\w+)\}\}',
        r['ado_title'] + r['ado_desc']))
    assert len(ado_params) <= 3, f"Rule {r['num']}: ADO params={len(ado_params)}: {ado_params}"

    return {
        "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
        "apiVersion": "2022-11-01-preview",
        "name": f"[concat({WORKSPACE_PARAM},'/Microsoft.SecurityInsights/','{r['id']}')]",
        "kind": "Scheduled",
        "dependsOn": [],
        "properties": {
            "displayName": r["name"],
            "description": r["desc"],
            "severity": r["severity"],
            "enabled": True,
            "query": r["query"],
            "queryFrequency": r["freq"],
            "queryPeriod": r["period"],
            "triggerOperator": "GreaterThan",
            "triggerThreshold": r["trigger_thresh"],
            "suppressionDuration": "PT1H",
            "suppressionEnabled": False,
            "tactics": r["tactics"],
            "techniques": r["techniques"],
            "entityMappings": entity_mappings,
            "customDetails": custom_details,
            "alertDetailsOverride": {
                "alertDisplayNameFormat": r["ado_title"],
                "alertDescriptionFormat": r["ado_desc"]
            },
            "incidentConfiguration": {
                "createIncident": True,
                "groupingConfiguration": {
                    "enabled": True,
                    "reopenClosedIncident": False,
                    "lookbackDuration": r.get("lookback_dur", "PT1H"),
                    "matchingMethod": "AllEntities",
                    "groupByEntities": r["group_by"]
                }
            }
        }
    }

# ---------------------------------------------------------------------------
# Write YAML files
# ---------------------------------------------------------------------------
print("--- Writing YAML files ---")
for r in RULES:
    fname = f"{RULES_DIR}/{r['num']}-SIGNIN-{r['slug']}.yaml"
    content = build_yaml(r)
    with open(fname, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"  YAML  {fname.split('/')[-1]}")

# ---------------------------------------------------------------------------
# Write ARM template
# ---------------------------------------------------------------------------
print("--- Building ARM template ---")
resources = [build_arm_resource(r) for r in RULES]

arm = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "workspace": {
            "type": "string",
            "metadata": {"description": "Microsoft Sentinel Log Analytics workspace name"}
        }
    },
    "resources": resources
}

with open(ARM_PATH, "w", encoding="utf-8") as f:
    json.dump(arm, f, indent=2, ensure_ascii=False)
print(f"  ARM   {ARM_PATH.split('/')[-1]}  ({len(resources)} resources)")

# ---------------------------------------------------------------------------
# Validate
# ---------------------------------------------------------------------------
print("--- Validating ---")
errors = 0
for i, r in enumerate(arm["resources"]):
    p    = r["properties"]
    ado  = p.get("alertDetailsOverride", {})
    em   = p.get("entityMappings", [])
    params = set(re.findall(r'\{\{(\w+)\}\}',
        ado.get("alertDisplayNameFormat","") + ado.get("alertDescriptionFormat","")))
    issues = []
    if len(em) == 0:       issues.append("em=0")
    if len(params) > 3:    issues.append(f"ado={len(params)}: {params}")

    # Tactic/technique check
    TACTIC_TECHS = {
        "InitialAccess":       {"T1078","T1133","T1190","T1199","T1566"},
        "Persistence":         {"T1078","T1098","T1133","T1136","T1505","T1543","T1556","T1574"},
        "PrivilegeEscalation": {"T1078","T1098","T1134","T1484","T1543","T1546","T1547","T1548","T1574"},
        "DefenseEvasion":      {"T1027","T1036","T1055","T1070","T1078","T1090","T1197","T1550","T1553","T1562","T1574"},
        "CredentialAccess":    {"T1003","T1040","T1056","T1110","T1528","T1539","T1552","T1555","T1557","T1558","T1606","T1621"},
        "Discovery":           {"T1007","T1012","T1016","T1018","T1033","T1040","T1046","T1049","T1057","T1069","T1082","T1083","T1087","T1518"},
        "LateralMovement":     {"T1021","T1080","T1550","T1563","T1570"},
        "Collection":          {"T1005","T1025","T1039","T1056","T1074","T1113","T1114","T1213","T1530","T1557","T1560"},
        "Exfiltration":        {"T1011","T1020","T1048","T1567"},
        "CommandAndControl":   {"T1001","T1008","T1071","T1090","T1092","T1095","T1102","T1105","T1219","T1568","T1571","T1572","T1573"},
    }
    for tech in p.get("techniques", []):
        base = tech.split(".")[0]
        valid = [t for t, ts in TACTIC_TECHS.items() if base in ts]
        covered = [t for t in p.get("tactics",[]) if t in valid]
        if not covered:
            issues.append(f"TACTIC MISMATCH: {tech} valid in {valid} but rule has {p['tactics']}")

    status = "OK " if not issues else "ERR"
    print(f"  {status} {i+1:02d}. em={len(em)} ado={len(params)}  {p['displayName'][:60]}")
    for x in issues: print(f"       !! {x}")
    if issues: errors += 1

print(f"\nTotal: {len(arm['resources'])} | Errors: {errors}")
print("ALL RULES PASS" if errors == 0 else f"{errors} ERROR(S) -- FIX BEFORE DEPLOY")
