# Incident ticket: arppoison.pcapng

**Priority:** P3  
**Conns:** 29 | **DNS queries:** 27 | **HTTP requests:** 15 | **ARP bindings:** 4

## Findings
| SID | Signature | Sev | MITRE | Count | Src -> Dst (first) | Evidence (first) |
|---|---|---|---|---|---|---|
| 1000021 | ARP one MAC claims multiple IPs | medium | T1557.002 | 1 | 00:25:b3:bf:91:ee -> broadcast | `IPs: ['172.16.0.1', '172.16.0.105']` |

## Recommended actions
- **T1557.002:** Locate the rogue MAC on the switch (CAM table); enable Dynamic ARP Inspection.

## Top talkers
- 172.16.0.107 -> 12.153.20.41: 27 conns
- 172.16.0.107 -> 74.125.95.147: 2 conns

## DNS queries (first 5)
- `www.google.com`
- `video.google.com`
- `maps.google.com`
- `news.google.com`
- `mail.google.com`
