#!/bin/sh
# Public sample PCAPs (not committed). Cite: Chris Sanders "packets" repo (Practical Packet Analysis) and the Wireshark wiki SampleCaptures.
set -e; cd "$(dirname "$0")"
P=https://raw.githubusercontent.com/chrissanders/packets/master
for f in synscan.pcapng arppoison.pcapng http_dvwa_sqlinjection.pcapng http_dvwa_directorytraversal.pcapng cryptowall4_c2.pcapng; do curl -sfLO $P/$f; done
W=https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures
for f in telnet-raw.pcap dns.cap smtp.pcap; do curl -sfLO $W/$f; done
sha256sum *.pcap* *.cap > SHA256SUMS.txt
