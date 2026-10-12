# Incident ticket: http_dvwa_directorytraversal.pcapng

**Priority:** P2  
**Conns:** 1 | **DNS queries:** 0 | **HTTP requests:** 1 | **ARP bindings:** 0

## Findings
| SID | Signature | Sev | MITRE | Count | Src -> Dst (first) | Evidence (first) |
|---|---|---|---|---|---|---|
| 1000011 | WEB directory traversal attempt | high | T1190 | 1 | 10.2.2.101 -> 10.2.2.104 | `/dvwa/vulnerabilities/fi/?page=../../../../../../etc/passwd` |

## Recommended actions
- **T1190:** Check web server response codes/logs for success; patch/WAF the vulnerable parameter.

## Top talkers
- 10.2.2.101 -> 10.2.2.104: 1 conns
