# Splunk Windows Authentication Investigation

![Status](https://img.shields.io/badge/Status-Complete-2ea44f?style=flat-square) ![Splunk](https://img.shields.io/badge/Splunk-SPL-000000?style=flat-square&logo=splunk) ![SOC](https://img.shields.io/badge/Focus-Authentication_Investigation-1f6feb?style=flat-square)

## Overview

This project investigates Windows authentication activity in the **Splunk BOTS v3** dataset. The goal was to determine whether the observed failed logons represented credential guessing, brute-force activity, account compromise, or benign authentication noise.

Rather than treating every `4625` event as malicious, I followed a SOC-style workflow: understand the available telemetry, identify authentication failures, inspect account/host/logon context, pivot to related activity, correlate failed and successful logons, and reach a defensible disposition.

## Environment

| Item | Value |
|---|---|
| SIEM | Splunk Enterprise |
| Dataset | BOTS v3 |
| Index | `botsv3` |
| Sourcetype | `wineventlog:security` |
| Key Event IDs | `4624`, `4625`, `4740` |

## Investigation Flow

```text
Windows Security telemetry
        ↓
Authentication event inventory
        ↓
Failed logons (4625)
        ↓
User / host / logon type / failure reason
        ↓
Account and host pivots
        ↓
Failed vs successful authentication correlation
        ↓
Network-logon validation
        ↓
Scope / impact / disposition
```

## Key Evidence

### Failed logon context

The dataset contained only a small number of failed logons. Two were service-related failures on `SEPM`, while a third involved the disabled AzureAD guest account `MalloryKrauesen Guest` using network logon type 3.

![Failed logon details](screenshots/evidence-01.webp)

### Host pivot

Pivoting on the affected host showed mostly successful service logons and did not reveal a pattern of repeated network authentication or a successful network logon following the disabled-account failure.


## Findings

- `4624` successful logons were present in normal service activity.
- Only three `4625` failures were observed.
- No `4740` account lockout events were found.
- There was no repeated failure pattern consistent with brute force.
- The guest-account failure was associated with a disabled account and did not correlate with a successful network logon.
- No evidence of confirmed account compromise was identified in the available telemetry.

## Final Disposition

**Likely Benign / Low Severity**

The available evidence did not support brute-force activity or successful compromise. The investigation demonstrates why failed logons must be evaluated in context rather than escalated solely because Event ID `4625` exists.

## Skills Demonstrated

`Splunk` · `SPL` · `Windows Security Events` · `Authentication Analysis` · `Event Correlation` · `SOC Triage` · `Evidence-Based Disposition`
