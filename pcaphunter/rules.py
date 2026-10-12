"""Suricata-inspired detections over Zeek-style records. Each returns alerts
{sid, signature, severity, mitre, src, dst, evidence}."""
import re, urllib.parse
from collections import defaultdict

SQLI = re.compile(r"(\bunion\b.+\bselect\b|'\s*or\s*'?\d|'\s*or\s+1=1|--\s|\bsleep\(|information_schema|' or ')", re.I)
TRAV = re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|win\.ini)", re.I)
CLEAR_CREDS = re.compile(rb"(USER \S+\r\nPASS \S+|AUTH LOGIN|login:|Password:)", re.I)


def a(sid, sig, sev, mitre, src, dst, ev):
    return {"sid": sid, "signature": sig, "severity": sev, "mitre": mitre, "src": src, "dst": dst, "evidence": ev}


def port_scan(r, min_ports=50):
    by = defaultdict(set)
    for c in r["conn"]:
        if c["proto"] == "tcp" and c["state"] in ("S0", "REJ"):
            by[(c["orig_h"], c["resp_h"])].add(c["resp_p"])
    return [a(1000001, "SCAN TCP SYN port scan", "medium", "T1046", s, d, f"{len(p)} distinct ports unanswered/rejected, e.g. {sorted(p)[:8]}")
            for (s, d), p in by.items() if len(p) >= min_ports]


def http_attacks(r):
    out = []
    for h in r["http"]:
        u = urllib.parse.unquote_plus(h["uri"])
        if SQLI.search(u):
            out.append(a(1000010, "WEB SQL injection attempt in URI", "high", "T1190", h["orig_h"], h["resp_h"], u[:160]))
        if TRAV.search(h["uri"]) or TRAV.search(u):
            out.append(a(1000011, "WEB directory traversal attempt", "high", "T1190", h["orig_h"], h["resp_h"], u[:160]))
    return out


def arp_spoof(r):
    seen = defaultdict(set)
    for x in r["arp"]:
        seen[x["ip"]].add(x["mac"])
    out = [a(1000020, "ARP IP claimed by multiple MACs (possible ARP poisoning)", "high", "T1557.002", ip, "broadcast", f"MACs: {sorted(m)}")
           for ip, m in seen.items() if len(m) > 1]
    macs = defaultdict(set)
    for x in r["arp"]:
        macs[x["mac"]].add(x["ip"])
    out += [a(1000021, "ARP one MAC claims multiple IPs", "medium", "T1557.002", m, "broadcast", f"IPs: {sorted(ips)}")
            for m, ips in macs.items() if len(ips) > 1]
    return out


def cleartext_auth(r):
    out = []
    for k, p in r["payloads"].items():
        if k[3] in (21, 23, 110, 143, 25, 587) or k[1] in (23,):
            if CLEAR_CREDS.search(p):
                out.append(a(1000030, f"POLICY cleartext authentication on port {k[3]}", "medium", "T1040", k[0], k[2], "credential prompt/exchange seen in plaintext (values redacted)"))
    return out


def beaconing(r, min_n=5, max_jitter=0.2):
    """Repeated connections to same dst:port at regular intervals (C2-like)."""
    by = defaultdict(list)
    for c in r["conn"]:
        by[(c["orig_h"], c["resp_h"], c["resp_p"])].append(c["ts"])
    out = []
    for (s, d, p), ts in by.items():
        if len(ts) < min_n:
            continue
        ts.sort(); gaps = [b - a_ for a_, b in zip(ts, ts[1:])]
        mean = sum(gaps) / len(gaps)
        if mean < 1:
            continue
        jitter = (sum((g - mean) ** 2 for g in gaps) / len(gaps)) ** 0.5 / mean
        if jitter <= max_jitter:
            out.append(a(1000040, "C2 periodic beaconing", "high", "T1071.001", s, d, f"{len(ts)} conns to :{p}, mean interval {mean:.1f}s, jitter {jitter:.2f}"))
    return out


def suspicious_post(r):
    """POSTs with no Host/UA or odd PHP endpoints, typical of commodity malware check-ins."""
    out = []
    for h in r["http"]:
        if h["method"] == "POST" and (not h["user_agent"] or re.search(r"\.php\?\w=", h["uri"]) or re.search(r"^/[a-z0-9]{1,12}\.php$", h["uri"])):
            out.append(a(1000041, "MALWARE suspicious HTTP POST check-in", "medium", "T1071.001", h["orig_h"], h["resp_h"], f"POST {h['host']}{h['uri'][:80]} UA='{h['user_agent'][:40]}'"))
    return out


RULES = [port_scan, http_attacks, arp_spoof, cleartext_auth, beaconing, suspicious_post]


def run(records):
    alerts = []
    for f in RULES:
        alerts += f(records)
    return alerts
