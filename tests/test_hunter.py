"""Builds tiny synthetic PCAPs in-memory with dpkt so CI needs no downloads."""
import socket, dpkt
from pcaphunter.parse import parse
from pcaphunter import rules
from pcaphunter.cli import ticket

A, B = socket.inet_aton("192.0.2.10"), socket.inet_aton("192.0.2.20")
M1, M2 = bytes.fromhex("020000000001"), bytes.fromhex("020000000002")


def eth_tcp(src, dst, sport, dport, flags, data=b""):
    t = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=data)
    ip = dpkt.ip.IP(src=src, dst=dst, p=6, data=t); ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=M1, dst=M2, data=ip))


def write(tmp, frames):
    p = tmp / "t.pcap"
    with open(p, "wb") as f:
        w = dpkt.pcap.Writer(f)
        for ts, fr in frames:
            w.writepkt(fr, ts=ts)
    return p


def test_port_scan(tmp_path):
    fr = [(1 + i * 0.01, eth_tcp(A, B, 40000, port, dpkt.tcp.TH_SYN)) for i, port in enumerate(range(1, 101))]
    al = rules.run(parse(write(tmp_path, fr)))
    assert any(x["sid"] == 1000001 for x in al)


def test_no_scan_on_normal_traffic(tmp_path):
    fr = [(1, eth_tcp(A, B, 40000, 443, dpkt.tcp.TH_SYN)), (1.1, eth_tcp(B, A, 443, 40000, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK))]
    assert rules.run(parse(write(tmp_path, fr))) == []


def test_sqli_and_traversal(tmp_path):
    req1 = b"GET /dvwa/vulnerabilities/sqli/?id=1%27+or+%271%27%3D%271&Submit=Submit HTTP/1.1\r\nHost: x\r\nUser-Agent: t\r\n\r\n"
    req2 = b"GET /page.php?file=../../../../etc/passwd HTTP/1.1\r\nHost: x\r\nUser-Agent: t\r\n\r\n"
    fr = [(1, eth_tcp(A, B, 40001, 80, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, req1)), (2, eth_tcp(A, B, 40002, 80, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, req2))]
    sids = {x["sid"] for x in rules.run(parse(write(tmp_path, fr)))}
    assert {1000010, 1000011} <= sids


def test_arp_spoof(tmp_path):
    def arp(mac, ip):
        a = dpkt.arp.ARP(op=dpkt.arp.ARP_OP_REPLY, sha=mac, spa=ip, tha=M2, tpa=B)
        return bytes(dpkt.ethernet.Ethernet(src=mac, dst=M2, type=dpkt.ethernet.ETH_TYPE_ARP, data=a))
    fr = [(1, arp(M1, A)), (2, arp(bytes.fromhex("02deadbeef01"), A))]
    assert any(x["sid"] == 1000020 for x in rules.run(parse(write(tmp_path, fr))))


def test_beaconing(tmp_path):
    fr = [(100 + 60 * i, eth_tcp(A, B, 50000 + i, 8443, dpkt.tcp.TH_SYN)) for i in range(8)]
    assert any(x["sid"] == 1000040 for x in rules.run(parse(write(tmp_path, fr))))


def test_ticket_priority(tmp_path):
    fr = [(1 + i * 0.01, eth_tcp(A, B, 40000, port, dpkt.tcp.TH_SYN)) for i, port in enumerate(range(1, 101))]
    rec = parse(write(tmp_path, fr)); md, pri = ticket("x", rec, rules.run(rec))
    assert pri == "P3" and "T1046" in md
