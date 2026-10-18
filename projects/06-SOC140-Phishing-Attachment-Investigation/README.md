# SOC140 — Malicious Phishing Attachment Investigation

![Status](https://img.shields.io/badge/Status-Complete-2ea44f?style=flat-square) ![Blocked](https://img.shields.io/badge/Outcome-Blocked-2ea44f?style=flat-square) ![Email](https://img.shields.io/badge/Focus-Email_Security-1f6feb?style=flat-square)

## Overview

This project investigates a phishing email titled **“COVID19 Vaccine”** sent to `mark@letsdefend.io`. The message contained a password-protected attachment whose exact hash was strongly classified as malicious.

The objective was to determine whether the email was malicious, whether it reached the user, whether endpoint execution or scheduled-task creation could be confirmed, and how broad the campaign was.

## Alert Summary

| Field | Value |
|---|---|
| Rule | `SOC140 - Phishing Mail Detected - Suspicious Task Scheduler` |
| Event ID | `82` |
| Sender | `aaronluo@cmail.carleton.ca` |
| Recipient | `mark@letsdefend.io` |
| Subject | `COVID19 Vaccine` |
| Source IP | `189.162.189.159` |
| Device Action | Blocked |
| Attachment MD5 | `72c812cf21909a48eb9ccceb9e04b865d` |

![SOC140 alert](screenshots/evidence-01.webp)

## Attachment Validation

The exact attachment sample, identified as `Material.pdf`, was detected by **31/62** VirusTotal engines and labelled with phishing/trojan/downloader behavior.


## Investigation Findings

- The attachment was password protected (`infected`).
- Exact-hash reputation strongly supported a malicious file.
- The explicit alert action was **Blocked**.
- Campaign search returned one matching email to the target user.
- No incident-time endpoint execution was confirmed.
- No reliable scheduled-task creation evidence was available in the lab telemetry.
- Later ransomware artifacts on the endpoint were not treated as part of this email because timestamps could not support the correlation.

## Final Disposition

**True Positive — Malicious Phishing Email Blocked Before Delivery**

The email and attachment were malicious, but the available evidence did **not** support claiming endpoint execution or scheduled-task creation from this event.

## Skills Demonstrated

`Email Security` · `Attachment Analysis` · `Hash Reputation` · `VirusTotal` · `Campaign Scoping` · `Endpoint Correlation` · `False-Correlation Avoidance`
