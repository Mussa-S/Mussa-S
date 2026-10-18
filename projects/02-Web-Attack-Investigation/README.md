# Web Attack Investigation

![Status](https://img.shields.io/badge/Status-Complete-2ea44f?style=flat-square) ![Web](https://img.shields.io/badge/Focus-Web_Attack_Investigation-1f6feb?style=flat-square) ![HTTP](https://img.shields.io/badge/Protocol-HTTP-orange?style=flat-square)

## Overview

This project reconstructs a **multi-stage web attack** from the raw `access.log` supplied in the LetsDefend *Investigate Web Attack* challenge. Instead of answering challenge questions independently, I correlated the requests chronologically to understand the full attack path from reconnaissance through post-authentication activity.

## Environment

| Item | Value |
|---|---|
| Platform | LetsDefend |
| Data Source | Web server `access.log` |
| Attacker | `192.168.199.2` |
| Victim | `192.168.199.5` |
| Application | bWAPP |

## Reconstructed Attack Chain

```text
Nikto reconnaissance
        ↓
Directory enumeration
        ↓
Repeated login requests
        ↓
Successful authentication pattern
        ↓
Code injection / OS command execution
        ↓
Host discovery
        ↓
Attempted local-account creation
```

## Key Evidence

### Authentication attack and successful access

Repeated `POST /bWAPP/login.php` requests were followed by a response-pattern change and then successful access to `/bWAPP/portal.php`. A `200` response by itself was not treated as proof; the conclusion came from the sequence of events.

![Authentication and portal access](screenshots/evidence-01.webp)

### Post-authentication command execution

After authentication, the attacker reached a vulnerable PHP endpoint and submitted encoded calls to `system()` followed by discovery commands such as `whoami`, `net user`, and `net share`.


## Findings

- Reconnaissance used a `Nikto/2.1.6` user agent.
- Directory discovery preceded the authentication attack.
- The login attack progressed to authenticated portal access.
- Post-authentication activity showed code injection / OS command execution.
- Discovery commands were issued after access.
- A `net user ... /add` request represented an attempted persistence action; the web log proves submission of the payload, not successful account creation.

## Final Disposition

**True Positive — High Severity Web Compromise**

The correlated HTTP evidence supports a successful attack chain that progressed beyond reconnaissance and authentication into command execution and a persistence attempt.

## Skills Demonstrated

`HTTP Log Analysis` · `Attack-Chain Reconstruction` · `Nikto` · `Authentication Attacks` · `Code Injection` · `Command Execution` · `SOC Escalation`
