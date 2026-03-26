# 🛡️ KQL Elite Hunting & Detection Engineering: The Vault

<p align="center">
  <img src="https://readme-typing-svg.demolab.com?font=Minecraft&size=22&pause=1000&color=36CD31&center=true&vCenter=true&width=600&lines=Welcome+to+The+Vault;High-Fidelity+Detection+Logic;Mastering+Microsoft+Security;Sharpness+V+KQL+Queries" alt="Typing SVG" />
</p>

Welcome to my personal **Threat Hunting** and **Advanced Detection** repository. This project is a specialized "Chest" for centralizing high-fidelity detection logic, from Cloud Identity to complex Endpoint behavioral patterns.

---

## 🎯 Repository Philosophy (The Golden Rules)
Unlike generic query collections, this vault is built on **Detection Engineering** principles:
1. **Alert Fatigue Reduction:** Optimized logic to minimize false positives (No "Ghost" alerts).
2. **Operational Context:** Breaking down the threat vector and adversary behavior.
3. **Strategic Mapping:** Direct alignment with **MITRE ATT&CK®** tactics and techniques.

---

## 📂 Hunting Library Structure (The World Map)

| Biome / Pillar | Technical Coverage | Status |
| :--- | :--- | :---: |
| 👤 **[01-Identity-EntraID](./01-Identity-EntraID)** | MFA Fatigue, Targeted Password Spraying, CA bypass, Service Principal anomalies. | 💎 `Active` |
| 💻 **[02-Endpoint-Defender](./02-Endpoint-Defender)** | Process injection, LOLBins (certutil/pwsh), Registry persistence, Ransomware precursors. | ⚔️ `In Progress` |
| ☁️ **[03-CloudApps-CASB](./03-CloudApps-CASB)** | Shadow IT, mass SaaS exfiltration, anomalous access from Tor/VPN nodes. | ⏳ `Active` |
| 🛡️ **[04-Defender-Cloud](./04-Defender-Cloud)** | Internal port scanning, Azure SQL anomalies, Public Storage exposure. | ⏳ `Coming Soon` |

---

## 🛠️ Implementation & Triage Guide (Survival Manual)

### 1. Deployment in Microsoft Sentinel 🏰
Queries are designed as **Hunting Queries** or **Analytics Rules**. 
> ⚠️ **Note:** Adjust thresholds (`dcount`, `summarize`) based on your organization's unique traffic baseline.

### 2. Performance Optimization (Efficiency V) ⛏️
* **Token-based Search:** Prioritizing `has` over `contains` to reduce CPU cycles.
* **Memory Management:** Early use of `project` and `distinct` to minimize result footprint.

### 3. Triage & Remediation 🧪
Check the **"Analyst Notes"** in each file. If a TP (True Positive) is found, correlate the source IP with `SigninLogs` and `AuditLogs` to track lateral movement.

---

## 👋 Collaboration & Community
Cybersecurity is a team sport. If you find a bug or have a suggestion to harden the logic, please open an **Issue** or submit a **Pull Request**.

**Connect:** Reach out on LinkedIn to discuss Detection Engineering strategies and Blue Team operations.

---
<p align="center">
  <i>“In God we trust, all others we monitor with KQL.”</i>
</p>

**Author:** 0W3RTY | **Difficulty:** Hardcore | **License:** MIT
