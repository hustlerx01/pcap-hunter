# Incident ticket: http_dvwa_sqlinjection.pcapng

**Priority:** P2  
**Conns:** 3 | **DNS queries:** 0 | **HTTP requests:** 3 | **ARP bindings:** 0

## Findings
| SID | Signature | Sev | MITRE | Count | Src -> Dst (first) | Evidence (first) |
|---|---|---|---|---|---|---|
| 1000010 | WEB SQL injection attempt in URI | high | T1190 | 3 | 10.2.2.101 -> 10.2.2.104 | `/dvwa/vulnerabilities/sqli/?id=%' or '0'='0&Submit=Submit` |

## Recommended actions
- **T1190:** Check web server response codes/logs for success; patch/WAF the vulnerable parameter.

## Top talkers
- 10.2.2.101 -> 10.2.2.104: 3 conns
