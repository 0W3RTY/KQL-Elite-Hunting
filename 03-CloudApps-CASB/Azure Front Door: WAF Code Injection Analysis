# 🛡️ Azure Front Door: WAF Code Injection Analysis

```bash
# SYSTEM_LOG: /vault/detections/cloud/afd_waf_injection.kql
[✔] Category .......: Web Application Firewall (WAF)
[✔] Severity .......: 🔴 High
[✔] MITRE ATT&CK ...: T1190 - Exploit Public-Facing Application
[✔] DataSource ......: AzureDiagnostics (FrontDoor)

````
### 📜 Technical Description
This query is a specialized hunting tool designed to audit Code Injection attempts (SQLi, XSS, RFI) within Azure Front Door WAF logs.

By inputting a specific Target IP, the analyst can reconstruct the full attack timeline. The query is specifically tuned to show how the WAF reacted to each request, allowing you to distinguish between successfully blocked attempts and dangerous "bypass" scenarios where the attack was detected but allowed to pass.

### 🧪 Analyst Notes
WAF Status Triage: The query uses an extend operator to simplify the WAF's logic into three actionable states:

Blocked by WAF: The attack was stopped. No further action is needed on the backend, but the IP should be monitored.

Allowed: These are "Blind Spots." The request didn't trigger a rule. If you see XSS patterns here, your WAF policy needs tuning.

Detected but allowed (AnomalyScoring): CRITICAL. This means the WAF identified the attack (e.g., an XSS string) but was configured only to "Log" or "Score" it without dropping the packet. These require immediate log review on the web server to check for successful exploitation.

XSS Hunting: When investigating the results, filter the details_msg_s for "XSS". Look for tags like <script>, onerror, or alert() within the details_matches_s column. If an XSS attempt shows as "Allowed" or "Detected but allowed," verify if the web application sanitized that input.

### ⚔️ KQL Query
```KQL
// KQL HUNTING: Azure Front Door WAF Analysis
// Transcribed from image_11.png

AzureDiagnostics
| where Category =~ "FrontDoorWebApplicationFirewallLog"
| where clientIP_s == "Your IP"
| extend WAF_Status = case(
    action_s =~ "Block", "Blocked by WAF",
    action_s =~ "AnomalyScoring", "Detected but allowed",
    action_s =~ "Allow", "Allowed",
    "Unknown"
)
| project TimeGenerated,
          clientIP_s,
          host_s,
          requestUri_s,
          action_s,
          WAF_Status,
          details_msg_s,
          details_matches_s
| order by TimeGenerated desc
```

### 🛠️ Remediation Steps (SOC L2 Playbook)
Immediate IP Containment: If the query reveals persistent "Allowed" or "Detected" malicious payloads, block the clientIP_s at the Azure Front Door WAF level or via a Network Security Group (NSG).

Impact Assessment: For events marked as "Detected but allowed", correlate the TimeGenerated with your Web Server logs (IIS/Nginx/App Service). Check the HTTP response code; a 200 OK followed by a large data transfer suggests a successful exploit.

WAF Policy Tuning: If XSS/SQLi payloads are visible in the details_matches_s but the action_s was not "Block", switch the specific WAF rule from Detection to Prevention mode.

Application Hardening: Provide the identified payloads to the Development/AppSec team. Ensure input validation and output encoding are implemented to prevent future bypasses of the WAF.

Credential Reset: If a "Code Injection" was successful, assume the session or database might be compromised. Initiate a credential rotation for affected users or service accounts.
