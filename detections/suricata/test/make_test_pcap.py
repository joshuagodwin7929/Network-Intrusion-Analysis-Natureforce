# Builds a small synthetic pcap to test the Suricata rule.
# One session should alert; three negative cases should not.
# Usage: pip install scapy && python3 make_test_pcap.py   (writes test.pcap in the current folder)
from scapy.all import Ether, IP, TCP, Raw, wrpcap

pk = []

def session(cport, dst, dport, ua, uri="/wilow/runner_ilove.exe", t0=0):
    c = "10.10.1.128"
    mac_c, mac_s = "00:22:fb:ec:7e:e7", "00:01:96:ce:dd:92"
    e1, e2 = Ether(src=mac_c, dst=mac_s), Ether(src=mac_s, dst=mac_c)
    req = (f"GET {uri} HTTP/1.1\r\nHost: {dst}:{dport}\r\nUser-Agent: {ua}\r\nAccept: */*\r\n\r\n").encode()
    body = b"MZ" + b"\x00" * 200
    resp = (f"HTTP/1.1 200 OK\r\nContent-Type: binary/octet-stream\r\nContent-Length: {len(body)}\r\n\r\n").encode() + body
    cs, ss = 1000, 5000
    L = [
        e1/IP(src=c, dst=dst)/TCP(sport=cport, dport=dport, flags="S", seq=cs),
        e2/IP(src=dst, dst=c)/TCP(sport=dport, dport=cport, flags="SA", seq=ss, ack=cs+1),
        e1/IP(src=c, dst=dst)/TCP(sport=cport, dport=dport, flags="A", seq=cs+1, ack=ss+1),
        e1/IP(src=c, dst=dst)/TCP(sport=cport, dport=dport, flags="PA", seq=cs+1, ack=ss+1)/Raw(req),
        e2/IP(src=dst, dst=c)/TCP(sport=dport, dport=cport, flags="PA", seq=ss+1, ack=cs+1+len(req))/Raw(resp),
        e1/IP(src=c, dst=dst)/TCP(sport=cport, dport=dport, flags="A", seq=cs+1+len(req), ack=ss+1+len(resp)),
        e1/IP(src=c, dst=dst)/TCP(sport=cport, dport=dport, flags="FA", seq=cs+1+len(req), ack=ss+1+len(resp)),
        e2/IP(src=dst, dst=c)/TCP(sport=dport, dport=cport, flags="FA", seq=ss+1+len(resp), ack=cs+2+len(req)),
        e1/IP(src=c, dst=dst)/TCP(sport=cport, dport=dport, flags="A", seq=cs+2+len(req), ack=ss+2+len(resp)),
    ]
    for i, p in enumerate(L):
        p.time = 1000000 + t0 + i * 0.01
    pk.extend(L)

session(63723, "107.175.82.242", 9000, "curl/8.21.0", t0=0)                      # SHOULD alert
session(63801, "107.175.82.242", 80, "curl/8.21.0", t0=10)                       # standard port: no alert
session(63802, "107.175.82.242", 9000, "Mozilla/5.0", t0=20)                     # not curl: no alert
session(63803, "107.175.82.242", 9000, "curl/8.21.0", uri="/a/readme.txt", t0=30)  # not .exe: no alert
wrpcap("test.pcap", pk)
