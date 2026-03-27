## 🚨 Detection: BEC - Unauthorized External Forwarding Rule

## 📝 Technical Description

This detection identifies the creation of Inbox Rules that automatically forward incoming emails to external domains. This is a classic Business Email Compromise (BEC) tactic used by attackers to maintain persistence and exfiltrate sensitive data (invoices, credentials, or internal communications) without the user noticing.

Attackers often name these rules ".." or "RSS" and move the original emails to the "Deleted Items" folder to hide their tracks.

## 🛠️ KQL Query
```KQL
// BEC Hunting: Targeted Mailbox Rule Audit
OfficeActivity
| where TimeGenerated > ago(30d)          // 1. Range time
| where UserId =~ "Bill@yourcompany.com" // 2. Specified user
| where OfficeWorkload =~ "Exchange"
| where Operation in ("New-InboxRule", "Set-InboxRule")
| extend RuleName = tostring(parse_json(Parameters)[0].Value)
| extend ForwardTo = tostring(parse_json(Parameters)[1].Value)
| where ForwardTo contains "@" 
| where ForwardTo !contains "yourcompany.com" // 3.Your real domain
| project TimeGenerated, UserId, ClientIP, Operation, RuleName, ForwardTo, ExternalAccess
| sort by TimeGenerated desc
```

#### 🔍 Investigation Tips & Parameters
When an alert triggers, you should adjust these filters to refine your hunt:

* **`contains "@"`**: This acts as a global filter for email addresses. It automatically excludes "Move to Folder" or "Mark as Read" rules, showing only actions that involve **sending or redirecting mail** to an actual email account.
* **`!contains "yourcompany.com"`**: Use this to exclude internal noise. By filtering out your own corporate domain, you eliminate legitimate internal forwarding and isolate **External Exfiltration** (the primary goal of a BEC attacker).
* **`UserId =~ "Bill@yourcompany.com"`**: Always pivot to the specific user mentioned in your Identity alerts (e.g., Impossible Travel or MFA Fatigue) to see if they were compromised and "backdoored" with a mail rule.

---

### 🎯 MITRE ATT&CK Mapping
* **Tactic:** Persistence (TA0003), Exfiltration (TA0010)
* **Technique:** Email Forwarding Rule (T1137.005)

---

### 💡 Analyst Notes: The BEC Investigation Pillars
When this alert fires, an **L2 Analyst** must validate the "Context of the Creation" using these four analytical pillars:

| Pillar | Focus Area | Red Flags (High Risk) 🚩 |
| :--- | :--- | :--- |
| **1. Stealth Naming** | Rule Name analysis | Names like `.`, `..`, `RSS`, `System`, or a blank space `" "`. |
| **2. Timeline Correlation** | Login behavior | A "Successful login" from a new Country/ISP 30-60m before the rule creation. |
| **3. Silent Hijack** | Rule Bundling | A second rule created to move emails to `Deleted Items` or `Conversation History`. |
| **4. External Access** | Connectivity source | `ExternalAccess == true` or IP from a VPS (AWS, Azure, DigitalOcean). |

#### 🔍 Deep Dive Investigation
* **The "Stealth Naming" Rule:** Attackers use characters that are hard to see or click in the Outlook UI. If the name is a single character or a technical term unrelated to the user's role, **escalate immediately**.
* **Pivot to SigninLogs:** Never analyze a rule in isolation. Check the `UserId` for logins from suspicious ASNs or Hosting providers. If the login and the rule creation are linked, the account is **compromised**.
* **The Deletion Pattern:** Check for "Rule Bundles". Attackers forward mail to exfiltrate data and then create a "Delete" rule so the user never sees "Out of Office" replies or security warnings.

---

### 🛡️ Remediation Steps

> [!IMPORTANT]
> Time is critical. A BEC attacker can redirect a wire transfer in minutes. Follow these steps in order:

#### 1️⃣ Rule Eviction
Immediately delete the malicious rule via PowerShell to stop data exfiltration:
```powershell
Remove-InboxRule -Mailbox "user@company.com" -Identity "RuleID"
```
#### 2️⃣ Session Nuclear Option
Revoke all Refresh Tokens in Entra ID. This forces the attacker out of all active sessions (Web, Mobile, and Desktop) globally.

#### 3️⃣ MFA Integrity Check
Inspect AuditLogs for "MFA Method Changed" events.

Why? Attackers often add their own Authenticator app/phone number as a backup to maintain access after a password reset.

#### 4️⃣ Financial Impact Analysis
Audit the Sent Items folder. If the attacker has already sent emails to vendors with "updated bank details," notify the Legal and Finance departments immediately to halt pending payments.
