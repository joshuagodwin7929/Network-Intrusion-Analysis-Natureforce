#!/usr/bin/env bash
# Regenerate the measured values used in the report from the pcap.
# Usage: ./scripts/reproduce_metrics.sh [path/to/pcap]
set -u
cd "$(dirname "$0")/.."
P="${1:-pcaps/2026-10-01-traffic-analysis-exercise.pcap}"
[ -f "$P" ] || { echo "pcap not found: $P" >&2; exit 1; }
command -v tshark >/dev/null || { echo "tshark is required" >&2; exit 1; }

echo "== capture summary =="
capinfos "$P" | grep -E "Number of packets|Earliest|Latest|Capture duration"
sha256sum "$P"

echo; echo "== DHCP: host name, MAC and requested IP (Request, frame 3) =="
tshark -r "$P" -Y "dhcp.option.hostname" -T fields -e frame.number -e dhcp.option.hostname -e dhcp.hw.mac_addr -e dhcp.option.requested_ip_address
echo "-- Offer and ACK: your (client) IP --"
tshark -r "$P" -Y "dhcp.ip.your" -T fields -e frame.number -e frame.time_utc -e dhcp.ip.your

echo; echo "== Kerberos user (non-computer accounts) =="
tshark -r "$P" -Y 'kerberos.CNameString && !(kerberos.CNameString contains "$")' -T fields -e frame.number -e frame.time_utc -e kerberos.CNameString -e kerberos.realm | head -20

echo; echo "== Executable request and response =="
tshark -r "$P" -Y "frame.number == 23091" -T fields -e frame.time_utc -e http.request.full_uri -e http.user_agent
tshark -r "$P" -Y "frame.number == 24916" -T fields -e frame.time_utc -e http.response.code -e http.content_type -e http.content_length -e http.server

echo; echo "== TCP conversations for the three large sessions =="
tshark -r "$P" -q -z conv,tcp | grep -E "Relative|195\.63\.128\.106|57\.150\.53\.97|107\.175\.82\.242"

echo; echo "== Stream 130 exact bytes (sum of frame lengths) =="
tshark -r "$P" -Y "tcp.stream eq 130 && ip.src == 195.63.128.106" -T fields -e frame.len | awk '{s+=$1} END {print "server to victim:", s}'
tshark -r "$P" -Y "tcp.stream eq 130 && ip.src == 10.10.1.128" -T fields -e frame.len | awk '{s+=$1} END {print "victim to server:", s}'

echo; echo "== Stream 130 last packets =="
tshark -r "$P" -Y "tcp.stream eq 130" -T fields -e frame.number -e frame.time_utc -e tcp.flags.str | tail -5

echo; echo "== Stream 130 TLS Client Hello count (0 = none detected) =="
tshark -r "$P" -Y "tcp.stream eq 130 && tls.handshake.type == 1" | wc -l

echo; echo "== Stream 130 first payload bytes (frame 24969) =="
tshark -r "$P" -Y "frame.number == 24969" -T fields -e tcp.payload | cut -c1-32

echo; echo "== SYNs to 195.63.128.106 (expect one); packets for 195.64.128.106 (expect 0) =="
tshark -r "$P" -Y "ip.dst == 195.63.128.106 && tcp.flags.syn == 1 && tcp.flags.ack == 0" -T fields -e frame.number -e frame.time_utc
tshark -r "$P" -Y "ip.addr == 195.64.128.106" | wc -l

echo; echo "== DNS answers for 195.63.128.106 (expect none) =="
tshark -r "$P" -Y "dns.a == 195.63.128.106" | wc -l

echo; echo "== Stream 127 server name =="
tshark -r "$P" -Y "tcp.stream eq 127 && tls.handshake.type == 1" -T fields -e frame.number -e frame.time_utc -e tls.handshake.extensions_server_name

echo; echo "== Packets containing domains tied to 195.63.128.106 on VirusTotal (expect 0) =="
tshark -r "$P" -Y 'frame contains "lapiscorbel" || frame contains "vdsina" || frame contains "rollup"' | wc -l

echo; echo "== holtandberyl.com: DNS, requests, status and redirect target =="
tshark -r "$P" -Y 'dns.qry.name contains "holtandberyl"' -T fields -e frame.number -e frame.time_utc -e dns.a
tshark -r "$P" -Y 'http.host contains "holtandberyl"' -T fields -e frame.number -e frame.time_utc -e http.request.uri
tshark -r "$P" -Y "frame.number == 8238 || frame.number == 8347" -T fields -e frame.number -e http.response.code -e http.location
