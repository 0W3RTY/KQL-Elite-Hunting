# 🛡️ KQL Elite Hunting Library

Welcome to **KQL-Elite-Hunting**. This repository is a specialized collection of high-fidelity detection queries and hunting logic designed for the Microsoft Security ecosystem. 



## 🎯 Project Objective
The focus of this library is to bridge the gap between raw telemetry and actionable security insights. Every query here is engineered to identify sophisticated adversary behaviors while maintaining a low false-positive rate in enterprise environments.

## 🏗️ Architecture & Framework
All detections are strictly mapped to the **MITRE ATT&CK®** framework to provide full visibility across the modern attack surface:

* **01-Identity-EntraID:** Focus on compromised accounts, session hijacking, and MFA bypass techniques.
* **02-Endpoint-Defender:** Monitoring for process injection, LOLDbins, and ransomware precursors.
* **03-CloudApps-CASB:** Detection of data exfiltration and anomalous SaaS resource interaction.
* **04-Information-Purview:** Data sensitivity monitoring and Insider Threat patterns.
* **05-Automation-LogicApps:** Workflow definitions for automated containment and response (SOAR).

## 🔍 Detection Engineering Methodology
Each contribution to this repository follows a structured "Detection Intelligence" format:
1. **Logic:** The optimized KQL code.
2. **Context:** Technical breakdown of the threat vector.
3. **False Positive Analysis:** Known edge cases to consider during triage.
4. **Response Playbook:** Recommended immediate actions for the incident responder.

---
**Maintained by:** [0w3rty]  
*Focus: Threat Hunting | Detection Engineering | Blue Teaming*
