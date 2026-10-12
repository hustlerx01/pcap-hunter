# Incident ticket: synscan.pcapng

**Priority:** P3  
**Conns:** 1994 | **DNS queries:** 0 | **HTTP requests:** 0 | **ARP bindings:** 0

## Findings
| SID | Signature | Sev | MITRE | Count | Src -> Dst (first) | Evidence (first) |
|---|---|---|---|---|---|---|
| 1000001 | SCAN TCP SYN port scan | medium | T1046 | 1 | 172.16.0.8 -> 64.13.134.52 | `997 distinct ports unanswered/rejected, e.g. [1, 3, 4, 6, 7, 9, 13, 17]` |

## Recommended actions
- **T1046:** Confirm scanner is not an authorised VA tool; block source at perimeter if external.

## Top talkers
- 172.16.0.8 -> 64.13.134.52: 1994 conns
