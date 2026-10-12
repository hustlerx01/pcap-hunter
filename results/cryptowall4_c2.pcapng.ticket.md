# Incident ticket: cryptowall4_c2.pcapng

**Priority:** P3  
**Conns:** 3 | **DNS queries:** 0 | **HTTP requests:** 3 | **ARP bindings:** 0

## Findings
| SID | Signature | Sev | MITRE | Count | Src -> Dst (first) | Evidence (first) |
|---|---|---|---|---|---|---|
| 1000041 | MALWARE suspicious HTTP POST check-in | medium | T1071.001 | 3 | 192.168.122.145 -> 184.170.149.44 | `POST /76N1Lm.php?n=x4tk7t4jo6 UA=''` |

## Recommended actions
- **T1071.001:** Isolate the host, pull EDR telemetry, block the destination and hunt for it fleet-wide.

## Top talkers
- 192.168.122.145 -> 184.170.149.44: 3 conns
