"""pcap-hunter: PCAP -> Zeek-style logs -> Suricata-style alerts -> incident ticket (markdown)."""
import argparse, collections, json, sys
from pathlib import Path
from .parse import parse
from .rules import run

SEV = {"high": 3, "medium": 2, "low": 1}


def ticket(name, rec, alerts):
    top = max((SEV[x["severity"]] for x in alerts), default=0)
    pri = {3: "P2", 2: "P3", 1: "P4", 0: "P5 (no findings)"}[top]
    L = [f"# Incident ticket: {name}", "", f"**Priority:** {pri}  ", f"**Conns:** {len(rec['conn'])} | **DNS queries:** {len(rec['dns'])} | **HTTP requests:** {len(rec['http'])} | **ARP bindings:** {len(rec['arp'])}", ""]
    if not alerts:
        L += ["No detections fired. Analyst review recommended only if other context exists.", ""]
    grouped = collections.OrderedDict()
    for x in sorted(alerts, key=lambda x: -SEV[x["severity"]]):
        grouped.setdefault((x["sid"], x["signature"], x["severity"], x["mitre"]), []).append(x)
    if grouped:
        L += ["## Findings", "| SID | Signature | Sev | MITRE | Count | Src -> Dst (first) | Evidence (first) |", "|---|---|---|---|---|---|---|"]
        for (sid, sig, sev, m), xs in grouped.items():
            e = xs[0]["evidence"].replace("|", "\\|")
            L.append(f"| {sid} | {sig} | {sev} | {m} | {len(xs)} | {xs[0]['src']} -> {xs[0]['dst']} | `{e}` |")
        L += ["", "## Recommended actions"]
        acts = {"T1046": "Confirm scanner is not an authorised VA tool; block source at perimeter if external.",
                "T1190": "Check web server response codes/logs for success; patch/WAF the vulnerable parameter.",
                "T1557.002": "Locate the rogue MAC on the switch (CAM table); enable Dynamic ARP Inspection.",
                "T1040": "Rotate exposed credentials; replace telnet/FTP/plain SMTP auth with SSH/SFTP/TLS.",
                "T1071.001": "Isolate the host, pull EDR telemetry, block the destination and hunt for it fleet-wide."}
        for m in sorted({k[3] for k in grouped}):
            L.append(f"- **{m}:** {acts.get(m, 'Investigate.')}")
    top_talkers = collections.Counter((c["orig_h"], c["resp_h"]) for c in rec["conn"]).most_common(3)
    L += ["", "## Top talkers", *[f"- {s} -> {d}: {n} conns" for (s, d), n in top_talkers]]
    if rec["dns"]:
        L += ["", "## DNS queries (first 5)", *[f"- `{q['query']}`" for q in rec["dns"][:5]]]
    return "\n".join(L) + "\n", pri


def main(argv=None):
    ap = argparse.ArgumentParser(); ap.add_argument("pcaps", nargs="+"); ap.add_argument("-o", "--out", default="results")
    a = ap.parse_args(argv)
    out = Path(a.out); out.mkdir(exist_ok=True)
    summary = []
    for p in a.pcaps:
        rec = parse(p); al = run(rec); name = Path(p).name
        md, pri = ticket(name, rec, al)
        (out / f"{name}.ticket.md").write_text(md)
        with open(out / f"{name}.alerts.jsonl", "w") as f:
            for x in al: f.write(json.dumps(x) + "\n")
        sigs = sorted({x["signature"] for x in al})
        summary.append({"pcap": name, "priority": pri, "conns": len(rec["conn"]), "alerts": len(al), "signatures": sigs})
        print(f"{name:40s} {pri:16s} conns={len(rec['conn']):5d} alerts={len(al):3d} {sigs}")
    json.dump(summary, open(out / "summary.json", "w"), indent=2)


if __name__ == "__main__":
    main()
