# 🛡️ KQL Elite Hunting & Detection Engineering

Welcome to my personal **Threat Hunting** and **Advanced Detection** repository. This project is dedicated to centralizing high-fidelity detection logic for the Microsoft Security ecosystem, covering everything from Cloud Identity to complex Endpoint behavioral patterns.



## 🎯 Repository Philosophy
Unlike generic query collections, this repository is built on the principles of **Detection Engineering**. Every query shared here is engineered based on three core pillars:
1. **Alert Fatigue Reduction:** Optimized logic to minimize false positives in noisy enterprise environments.
2. **Operational Context:** We don't just provide code; we break down the threat vector and the expected adversary behavior.
3. **Strategic Mapping:** Direct alignment with **MITRE ATT&CK®** tactics and techniques.

---

## 📂 Hunting Library Structure

| Security Pillar | Technical Coverage | Status |
| :--- | :--- | :---: |
| 👤 **[01-Identity-EntraID](./01-Identity-EntraID)** | Modern identity attacks: MFA Fatigue, Targeted Password Spraying, Conditional Access bypass attempts, and Service Principal anomalies. | 🟢 Active |
| 💻 **[02-Endpoint-Defender](./02-Endpoint-Defender)** | Host-based hunting: Process injection, LOLDbins usage (certutil, powershell), Windows Registry persistence, and Ransomware precursors. | 🟡 In Progress |
| ☁️  **[03-CloudApps-CASB](./03-CloudApps-CASB)** | Shadow IT monitoring, mass SaaS data exfiltration, and anomalous access from suspicious egress nodes (Tor/VPN). | ⚪ Coming Soon |
| 🛡️ **[04-Defender-Cloud](./04-Defender-Cloud)** | Infrastructure Security (IaaS/PaaS): Internal port scanning, Azure SQL anomalies, and Public Storage Account exposure. | ⚪ Coming Soon |

---

## 🛠️ Implementation & Triage Guide

To get the most out of these detections, integrate them into your workflow as follows:

### 1. Deployment in Microsoft Sentinel
Most queries are designed to be deployed as **Hunting Queries** or **Analytics Rules**. Note that aggregate operators like `dcount` or `summarize` require adjusting thresholds based on your organization's unique traffic baseline.

### 2. Performance Optimization
In high-volume environments, query performance is critical. 
* I prioritize the use of indexed operators like `has` (token-based) over `contains` (substring-based) to reduce CPU cycles.
* Early use of `project` or `distinct` is implemented to minimize the memory footprint of the query results.

### 3. Triage & Remediation
Each detection file includes **"Analyst Notes"**. If a query triggers a true positive, the recommended first step is to correlate the source IP with `SigninLogs` and `AuditLogs` to identify lateral movement or persistence attempts.

---

## 👋 Collaboration & Community
Cybersecurity is a team sport. If you find a recurring false positive or have a suggestion to harden the detection logic, please open an **Issue** or submit a **Pull Request**.

**Connect:** Feel free to reach out on LinkedIn to discuss Detection Engineering strategies and Blue Team operations.

---
*“In God we trust, all others we monitor with KQL.”*
