<h1 align="center">Mussa Saeed</h1>

<p align="center">
  <em>Cybersecurity · Security Operations · SOC · Detection Engineering</em>
</p>

<p align="center">
  <a href="https://github.com/Mussa-S">
    <img src="https://img.shields.io/badge/GitHub-Mussa--S-181717?style=flat-square&logo=github&logoColor=white" />
  </a>
</p>

---

> **Portfolio Note**
>
> This portfolio is focused on **Security Operations and SOC workflows**. The projects are designed to demonstrate practical investigation skills across authentication, phishing, malware, web attacks, network traffic, endpoint telemetry, SIEM analysis, detection engineering, and security automation.
>
> My current direction is toward **SOC Analyst / Security Analyst roles**, while developing deeper skills in Microsoft security technologies, offensive security, Python automation, and a private AI-powered SOC assistant.
>
> The goal is to show how I investigate alerts, validate evidence, distinguish confirmed activity from assumptions, document findings, and build tooling that improves security operations.

---

## 01 · Security Operations & SOC

### 🆕 Latest

| Workflow Project | Proof | Purpose | Stack | Status |
|---|---|---|---|---|
| **Private AI SOC Jarvis** | Architecture & build evidence in progress | Building a private AI-powered SOC assistant that can ingest Wazuh/SIEM alerts, investigate endpoint and network telemetry, enrich IOCs, map MITRE ATT&CK, maintain incident memory, explain findings, and support detection engineering with human approval for response actions. | Python · Wazuh · Local LLM · APIs · JSON · SQLite · MITRE ATT&CK · Docker | ![In Progress](https://img.shields.io/badge/In_Progress-e3a008?style=flat-square) |

### Completed

| Workflow Project | Proof | Purpose | Stack | Status |
|---|---|---|---|---|
| **Splunk Windows Authentication Investigation** | Investigation notes & evidence prepared | Analysed Windows authentication events, failed/successful logons, logon types, host pivots, and account activity to determine whether suspicious authentication represented compromise. | Splunk · SPL · Windows Event Logs · Event IDs 4624/4625/4740 | ![Complete](https://img.shields.io/badge/Complete-2ea44f?style=flat-square) |
| **Web Attack Investigation** | Investigation notes & evidence prepared | Reconstructed an attack chain from reconnaissance and login attacks through code injection, command execution, discovery, and a persistence attempt. | Web Logs · HTTP · Nikto · Attack Chain Analysis | ![Complete](https://img.shields.io/badge/Complete-2ea44f?style=flat-square) |
| **SOC104 — Malware Detected** | Investigation notes & evidence prepared | Investigated a suspected malware alert and used reputation, signatures, source validation, and telemetry limitations to identify a legitimate WinRAR installer false positive. | VirusTotal · Malware Triage · Endpoint Analysis | ![Complete](https://img.shields.io/badge/Complete-2ea44f?style=flat-square) |
| **SOC145 — Ransomware Investigation** | Investigation notes & evidence prepared | Investigated a critical ransomware alert, correlated suspicious recovery-inhibition utilities, mapped behaviours to MITRE ATT&CK, and assessed incident severity. | Malware Analysis · MITRE ATT&CK · Endpoint Telemetry · VirusTotal | ![Complete](https://img.shields.io/badge/Complete-2ea44f?style=flat-square) |
| **SOC141 — Phishing URL Investigation** | Investigation notes & evidence prepared | Correlated proxy/firewall telemetry, URL reputation, endpoint evidence, and timestamps to confirm phishing URL access without overclaiming credential theft or execution. | Phishing Analysis · Proxy Logs · Firewall Logs · VirusTotal | ![Complete](https://img.shields.io/badge/Complete-2ea44f?style=flat-square) |
| **SOC140 — Malicious Phishing Attachment** | Investigation notes & evidence prepared | Investigated a malicious attachment campaign, analysed the file hash and email controls, and determined the message was blocked before confirmed endpoint execution. | Email Security · VirusTotal · Malware Triage · IOC Analysis | ![Complete](https://img.shields.io/badge/Complete-2ea44f?style=flat-square) |
| **PayPal Brand Impersonation Investigation** | Email/header evidence prepared | Analysed sender identity, Return-Path, SPF context, infrastructure, and the true embedded URL to confirm a phishing campaign. | Email Headers · SPF · URL Analysis · Threat Intelligence | ![Complete](https://img.shields.io/badge/Complete-2ea44f?style=flat-square) |
| **Wireshark SOC Network Traffic Investigation** | PCAP analysis & screenshots prepared | Analysed HTTP/TCP traffic, streams, flags, sequence behaviour, payload direction, and conversation statistics to confirm substantial client-to-server transfer while separating evidence from assumptions. | Wireshark · PCAP · TCP/IP · HTTP · Network Analysis | ![Complete](https://img.shields.io/badge/Complete-2ea44f?style=flat-square) |
| **SC-200 Security Operations Labs** | Labs being documented | Building hands-on Microsoft Sentinel, Defender XDR, KQL, incident investigation, threat hunting, and detection-rule practice. | Microsoft Sentinel · Defender XDR · KQL · SC-200 | ![In Progress](https://img.shields.io/badge/In_Progress-e3a008?style=flat-square) |
| **Detection Engineering Lab** |  | Build and tune detections from safe lab telemetry, then validate alerts through SOC investigation workflows. | Wazuh · Sigma · SPL · KQL | ![Queued](https://img.shields.io/badge/Queued-888888?style=flat-square) |
| **SOC Home Lab** |  | Build monitored Windows/Linux endpoints that generate controlled telemetry for investigation, baselining, and AI-assisted SOC workflows. | Wazuh · Windows · Linux · Sysmon · Networking | ![Queued](https://img.shields.io/badge/Queued-888888?style=flat-square) |

> **Focus area:** Security Operations, SIEM analysis, endpoint and network investigation, alert triage, threat intelligence, incident response, detection engineering, and security automation.

---

## 02 · IT Support Projects

### Help Desk

| Project | Notes | Status |
|---|---|---|
| **Help Desk / Ticketing Lab** | Building an end-to-end support workflow covering ticket intake, prioritisation, troubleshooting, escalation, documentation, SLA handling, and common Windows/user support scenarios. | ![In Progress](https://img.shields.io/badge/In_Progress-e3a008?style=flat-square) |

---

## 03 · Security & Technical Projects

| Project | Focus | Status |
|---|---|---|
| **OSINT Investigation Project** | Public-source intelligence collection, source validation, pivoting, timeline building, evidence handling, and reporting within a safe/ethical investigation scenario. | ![In Progress](https://img.shields.io/badge/In_Progress-e3a008?style=flat-square) |
| **Python Security Automation / Coding Project** | Build practical Python tooling for APIs, JSON parsing, IOC extraction, alert processing, log enrichment, automation, and SOC workflows. | ![In Progress](https://img.shields.io/badge/In_Progress-e3a008?style=flat-square) |
| **Private AI SOC Jarvis** | AI-assisted alert investigation, Wazuh integration, local AI, incident memory, threat enrichment, voice interaction, and detection engineering. | ![In Progress](https://img.shields.io/badge/In_Progress-e3a008?style=flat-square) |
| **AI-Assisted AppSec Pipeline** | Future module combining Git/CI/CD, SAST, SCA, DAST, AI triage, remediation validation, and detection creation. | ![Queued](https://img.shields.io/badge/Queued-888888?style=flat-square) |
| **Enterprise IAM & Zero Trust Lab** | Secondary project covering Entra ID, MFA, Conditional Access, RBAC, identity lifecycle, SSO, and identity monitoring. | ![Queued](https://img.shields.io/badge/Queued-888888?style=flat-square) |

---

## 04 · Certifications

**In Progress**

![OSCP](https://img.shields.io/badge/OSCP-In_Progress-e3a008?style=flat-square)

![SC-200](https://img.shields.io/badge/SC--200_Microsoft_Security_Operations_Analyst-In_Progress-e3a008?style=flat-square&logo=microsoft&logoColor=white)

---

<p align="center">
  <strong>Current focus:</strong> SOC · Microsoft Security · Offensive Security · Python Automation · AI Security Engineering
</p>
