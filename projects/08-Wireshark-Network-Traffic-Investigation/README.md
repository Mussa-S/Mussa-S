# Wireshark SOC Network Traffic Investigation

![Status](https://img.shields.io/badge/Status-Complete-2ea44f?style=flat-square) ![Wireshark](https://img.shields.io/badge/Tool-Wireshark-1679A7?style=flat-square&logo=wireshark&logoColor=white) ![PCAP](https://img.shields.io/badge/Focus-PCAP_Analysis-1f6feb?style=flat-square)

## Overview

This project analyses a **SOC3 PCAP** in Wireshark using a SOC-style network-investigation workflow. The objective was not to label a single packet as “bad,” but to determine what happened, prove whether data moved, measure direction and volume, and decide what the capture can and cannot establish.

The capture contained **296 packets** with internal HTTP/TCP traffic between `192.168.124.6` and `192.168.124.7:8080`.

## Investigation Flow

```text
PCAP overview
    ↓
Protocols and hosts
    ↓
Reduce noise
    ↓
HTTP request/response behavior
    ↓
Follow TCP streams
    ↓
Validate payload-bearing segments
    ↓
Measure conversation volume/direction
    ↓
Assess impact and confidence
```

## Large HTTP POST

One stream contained:

```http
POST /tcp-lab/upload-post HTTP/1.1
Host: 192.168.124.7:8080
User-Agent: curl/7.81.0
Content-Length: 307200
Content-Type: application/x-www-form-urlencoded
```

Following the stream showed a substantial request body moving from client to server.

![Large HTTP POST stream](screenshots/evidence-01.webp)

## Conversation-Level Impact

Wireshark Conversations statistics showed stream 3 as the clear volume outlier: roughly **322 kB client → server** across the TCP conversation, while the other streams were approximately 1 kB.


## Findings

- A failed image request returned HTTP `404`; the response body was the error page, not the requested image.
- The large POST declared a 307,200-byte application body.
- Numerous payload-bearing client-to-server TCP segments carried the upload.
- Server acknowledgements, HTTP `200 OK`, and normal FIN/ACK teardown support successful transport/application processing.
- TCP flags and sequence behavior were interpreted in context rather than used as standalone malicious indicators.

## Final Assessment

**Substantial client-to-server data transfer confirmed.**

**Malicious activity was not established from this isolated PCAP alone.** A large upload is an important volume/direction outlier, but without application/business context it is not sufficient to label the transfer malicious.

## Skills Demonstrated

`Wireshark` · `PCAP Analysis` · `HTTP` · `TCP Streams` · `TCP Flags` · `Sequence/Acknowledgment Analysis` · `Conversation Statistics` · `Data-Transfer Validation`
