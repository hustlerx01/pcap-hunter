# Incident ticket: smtp.pcap

**Priority:** P3  
**Conns:** 3 | **DNS queries:** 1 | **HTTP requests:** 0 | **ARP bindings:** 0

## Findings
| SID | Signature | Sev | MITRE | Count | Src -> Dst (first) | Evidence (first) |
|---|---|---|---|---|---|---|
| 1000030 | POLICY cleartext authentication on port 25 | medium | T1040 | 1 | 10.10.1.4 -> 74.53.140.153 | `credential prompt/exchange seen in plaintext (values redacted)` |

## Recommended actions
- **T1040:** Rotate exposed credentials; replace telnet/FTP/plain SMTP auth with SSH/SFTP/TLS.

## Top talkers
- 10.10.1.4 -> 10.10.1.1: 1 conns
- 10.10.1.4 -> 74.53.140.153: 1 conns
- 10.10.1.20 -> 10.10.1.255: 1 conns

## DNS queries (first 5)
- `mail.patriots.in`
