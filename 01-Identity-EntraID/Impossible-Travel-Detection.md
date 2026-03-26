# 🚨 Detection: Impossible Travel (Session Hijacking)

### 📝 Technical Description
This detection identifies user accounts that have successfully authenticated from two geographically distant locations within a timeframe that makes physical travel between them impossible. 

This behavior is a primary indicator of **Session Token Theft** or credential sharing, as it suggests that two different entities are using the same account from different parts of the world simultaneously.

### 🛠️ KQL Query
```kql
// Calculate users signing in from multiple locations in a short window
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0 // Only successful logins
| summarize 
    LocationCount = dcount(Location), 
    LocationList = make_set(Location), 
    IPList = make_set(IPAddress), 
    StartTime = min(TimeGenerated), 
    EndTime = max(TimeGenerated) 
    by UserPrincipalName
| where LocationCount > 1
| extend TimeDiff = EndTime - StartTime
// Filter for signs of travel that are physically impossible (e.g., < 6 hours between distant countries)
| where TimeDiff < 6h 
| project UserPrincipalName, LocationCount, LocationList, IPList, TimeDiff, StartTime, EndTime
| sort by LocationCount desc
````

### 🎯 MITRE ATT&CK Mapping
Tactic: Lateral Movement (TA0008)

Technique: Valid Accounts: Cloud Accounts (T1078.004)

### 💡 Analyst Notes
False Positives: Users connected to a Corporate VPN while their local machine also hits a local service, or users on long-haul flights with satellite Wi-Fi.

Triage: Check if one of the IP addresses belongs to a known hosting provider or a suspicious ASN. Correlate with OfficeActivity to see if there is an unusual volume of file downloads immediately after the second login.

### 🛡️ Remediation Steps
Revoke Sessions: Immediately revoke all active refresh tokens for the user in Entra ID.

Enforce Password Reset: Force a password change and re-registration of MFA methods if theft is suspected.

Check Mail Rules: Attackers often create "Forwarding Rules" right after an impossible travel event to stay persistent.
