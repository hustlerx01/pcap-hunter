# Interview talking points: pcap-hunter

1. **Workflow.** PCAP, then Zeek-style records, then signatures, then a ticket. I can explain conn states (S0 = SYN with no reply, REJ = RST) and why a scan looks like hundreds of S0/REJ to distinct ports.
2. **SQLi/traversal.** I URL-decode before matching (`%27` becomes `'`). Attackers encode payloads, and so does DVWA's form. False positives come from search boxes containing `--` or "union select" in docs.
3. **The ARP bug.** My first rule only looked at ARP replies and missed the poisoning sample. Both requests and replies carry a sender IP/MAC binding. A unit test now covers conflicting bindings. This shows I validate against real captures and not only my own fixtures.
4. **CryptoWall C2.** It wasn't caught by IOC. It was caught by behaviour: POST to a random `.php?n=` path with an empty User-Agent. Next steps: JA3/JA4 for TLS, and checking the destination IP against threat intel (that ties into my IOC aggregator project).
5. **Beaconing math.** Interval mean plus coefficient of variation (jitter ≤ 0.2). Real C2 adds jitter, so production tools use longer windows and frequency analysis (e.g. RITA).
6. **Tickets, not just alerts.** Priority mapping, recommended actions per technique, top talkers. That's what an L1 actually hands to L2.
7. **What I'd do with more time.** Run real Suricata with ET Open on the same PCAPs and diff the results against my rules to measure coverage gaps.
