"""PCAP/PCAPNG -> Zeek-style records (conn, dns, http, arp) using dpkt."""
import socket
from collections import defaultdict
import dpkt


def _ip(b):
    try:
        return socket.inet_ntop(socket.AF_INET if len(b) == 4 else socket.AF_INET6, b)
    except Exception:
        return "?"


def reader(f):
    head = f.read(4); f.seek(0)
    return dpkt.pcapng.Reader(f) if head == b"\x0a\x0d\x0d\x0a" else dpkt.pcap.Reader(f)


def parse(path):
    conns = {}
    dns, http, arp, payloads = [], [], [], defaultdict(bytes)
    with open(path, "rb") as f:
        rd = reader(f)
        lt = rd.datalink()
        for ts, buf in rd:
            try:
                eth = dpkt.ethernet.Ethernet(buf) if lt == dpkt.pcap.DLT_EN10MB else None
                if eth is None:
                    continue
            except Exception:
                continue
            if isinstance(eth.data, dpkt.arp.ARP):
                a = eth.data
                # requests and replies both advertise the sender's IP->MAC binding
                if _ip(a.spa) != "0.0.0.0":
                    arp.append({"ts": ts, "op": a.op, "ip": _ip(a.spa), "mac": a.sha.hex(":")})
                continue
            ip = eth.data
            if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
                continue
            l4 = ip.data
            proto = "tcp" if isinstance(l4, dpkt.tcp.TCP) else "udp" if isinstance(l4, dpkt.udp.UDP) else None
            if proto is None:
                continue
            src, dst = _ip(ip.src), _ip(ip.dst)
            key = (src, l4.sport, dst, l4.dport, proto)
            rkey = (dst, l4.dport, src, l4.sport, proto)
            if rkey in conns:
                c = conns[rkey]; c["resp_bytes"] += len(l4.data); c["resp_pkts"] += 1
            else:
                c = conns.setdefault(key, {"ts": ts, "orig_h": src, "orig_p": l4.sport, "resp_h": dst, "resp_p": l4.dport,
                                           "proto": proto, "orig_bytes": 0, "resp_bytes": 0, "orig_pkts": 0, "resp_pkts": 0, "flags": set()})
                c["orig_bytes"] += len(l4.data); c["orig_pkts"] += 1
            c["last"] = ts
            if proto == "tcp":
                fl = l4.flags
                if fl & dpkt.tcp.TH_SYN and not fl & dpkt.tcp.TH_ACK: c["flags"].add("S")
                if fl & dpkt.tcp.TH_SYN and fl & dpkt.tcp.TH_ACK: c["flags"].add("SA")
                if fl & dpkt.tcp.TH_RST: c["flags"].add("R")
                if l4.data:
                    payloads[key if key in conns else rkey] += bytes(l4.data[:4096]) if len(payloads[key if key in conns else rkey]) < 65536 else b""
                if l4.dport in (80, 8080) and l4.data[:4] in (b"GET ", b"POST", b"HEAD", b"PUT "):
                    try:
                        r = dpkt.http.Request(l4.data)
                        http.append({"ts": ts, "orig_h": src, "resp_h": dst, "method": r.method, "host": r.headers.get("host", ""),
                                     "uri": r.uri, "user_agent": r.headers.get("user-agent", ""), "body_len": len(r.body)})
                    except Exception:
                        line = l4.data.split(b"\r\n", 1)[0].decode("latin1").split(" ")
                        if len(line) >= 2:
                            http.append({"ts": ts, "orig_h": src, "resp_h": dst, "method": line[0], "host": "", "uri": line[1], "user_agent": "", "body_len": 0})
            if proto == "udp" and 53 in (l4.sport, l4.dport):
                try:
                    d = dpkt.dns.DNS(l4.data)
                    if d.qr == dpkt.dns.DNS_Q:
                        for q in d.qd:
                            dns.append({"ts": ts, "orig_h": src, "resp_h": dst, "query": q.name, "qtype": q.type})
                except Exception:
                    pass
    conn = []
    for k, c in conns.items():
        c["duration"] = round(c.get("last", c["ts"]) - c["ts"], 3)
        c["state"] = "REJ" if "R" in c["flags"] and "SA" not in c["flags"] else ("S0" if c["flags"] == {"S"} else "SF")
        c["flags"] = sorted(c["flags"]); c.pop("last", None)
        conn.append(c)
    return {"conn": conn, "dns": dns, "http": http, "arp": arp, "payloads": payloads}
