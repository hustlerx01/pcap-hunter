# Incident ticket: telnet-raw.pcap

**Priority:** P3  
**Conns:** 1 | **DNS queries:** 0 | **HTTP requests:** 0 | **ARP bindings:** 0

## Findings
| SID | Signature | Sev | MITRE | Count | Src -> Dst (first) | Evidence (first) |
|---|---|---|---|---|---|---|
| 1000030 | POLICY cleartext authentication on port 23 | medium | T1040 | 1 | 192.168.0.2 -> 192.168.0.1 | `credential prompt/exchange seen in plaintext (values redacted)` |

## Recommended actions
- **T1040:** Rotate exposed credentials; replace telnet/FTP/plain SMTP auth with SSH/SFTP/TLS.

## Top talkers
- 192.168.0.2 -> 192.168.0.1: 1 conns
