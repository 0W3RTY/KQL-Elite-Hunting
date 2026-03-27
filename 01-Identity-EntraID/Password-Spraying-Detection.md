# 🚨 Detection: Distributed Password Spraying (Entra ID)

## 📝 Technical Description
This detection identifies a **Password Spraying** pattern where a single source IP attempts to authenticate against a high number of unique user accounts within a short timeframe. 

Unlike a traditional Brute Force attack (which targets one account with many passwords), Password Spraying targets many accounts with a few common passwords to stay under account lockout thresholds and evade simple detection logic.


## 🛠️ KQL Query
```kql
// Thresholds for detection - Adjust based on your organization's size
let timeframe = 20m;
let threshold = 20;
SigninLogs
| where TimeGenerated > ago(24h)
// Filter for Failed Authentication due to invalid credentials or account lockout
| where ResultType in ("50126", "50053") 
| summarize 
    FailedAccountsCount = dcount(UserPrincipalName), 
    TargetedAccountList = make_set(UserPrincipalName), 
    StartTime = min(TimeGenerated), 
    EndTime = max(TimeGenerated) 
    by IPAddress, Location, AppDisplayName
| where FailedAccountsCount >= threshold
| project StartTime, EndTime, IPAddress, Location, FailedAccountsCount, TargetedAccountList, AppDisplayName
| sort by FailedAccountsCount desc
```

## 🎯 MITRE ATT&CK Mapping

Tactic: Initial Access (TA0001)

Technique: Brute Force: Password Spraying (T1110.003)

## 💡 Analyst Notes (Triage Guide)
IP Reputation: Check if the IPAddress is associated with known TOR exit nodes, proxies, or VPNs.

User Impact: Review the TargetedAccountList. Are these high-value targets (Admins, Executives)?

Correlation: Check SigninLogs for any successful logins (ResultType == 0) from the same IP address immediately following the spray. This would indicate a compromised account.


## 🛡️ Remediation Steps
Block the offending IP address via Conditional Access or Network Firewall.

Enforce MFA (Multi-Factor Authentication) for all targeted users.

Trigger a password reset for any account that shows a successful login after the spraying attempts.
