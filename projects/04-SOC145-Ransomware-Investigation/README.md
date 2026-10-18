# SOC145 — Ransomware Investigation

![Status](https://img.shields.io/badge/Status-Complete-2ea44f?style=flat-square) ![Severity](https://img.shields.io/badge/Severity-Critical-d73a49?style=flat-square) ![Ransomware](https://img.shields.io/badge/Focus-Ransomware_Investigation-1f6feb?style=flat-square)

## Overview

This project documents the investigation of a **critical ransomware alert** involving `ab.exe` on endpoint `MarkPRD` (`172.16.17.88`). The investigation focused on validating the file, reviewing local process context, identifying recovery-inhibition behavior, mapping activity to MITRE ATT&CK, and determining the appropriate incident response.

## Alert Context

| Field | Value |
|---|---|
| Rule | `SOC145 - Ransomware Detected` |
| Event ID | `92` |
| File | `ab.exe` |
| MD5 | `0b486fe0503524cfe4726a4022fa6a68` |
| Host | `MarkPRD` |
| Device Action | Allowed |
| Severity | Critical |

## Malware Validation

The exact sample was detected by **60/70 engines** and identified with Avaddon/Delshad ransomware-related labels.

![VirusTotal ransomware detection](screenshots/evidence-01.webp)

## Endpoint Context

The endpoint process list contained `ab.exe` alongside utilities commonly associated with recovery inhibition, including `wmic.exe`, `bcdedit.exe`, `wbadmin.exe`, and `vssadmin.exe`.


Because the local telemetry did not expose timestamps, process parents, or command lines for every process, I treated the presence of those utilities as **consistent with** ransomware behavior rather than claiming exact commands that were not observed.

## MITRE ATT&CK Mapping

- `T1486` — Data Encrypted for Impact
- `T1490` — Inhibit System Recovery
- `T1489` — Service Stop

## Findings

- Strong multi-engine confirmation that `ab.exe` was malicious ransomware.
- Alert action was **Allowed**, so containment could not be assumed.
- Recovery-inhibition tooling was present on the affected host.
- Available malware behavior was consistent with encryption and recovery interference.
- No reliable incident-time C2 telemetry was available in the local dataset.

## Final Disposition

**True Positive — Critical Ransomware Incident**

In a real environment this finding would require immediate endpoint isolation, escalation, scoping for additional affected hosts, preservation of evidence, and recovery planning.

## Skills Demonstrated

`Ransomware Triage` · `Endpoint Process Analysis` · `VirusTotal` · `MITRE ATT&CK` · `Impact Analysis` · `Incident Escalation` · `Evidence Discipline`
