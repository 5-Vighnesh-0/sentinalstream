"""Write tests/fixtures/sample.pcap: deterministic synthetic loopback traffic.

Contents (all 127.0.0.1, fixed timestamps, no network access):
- 20 benign TCP sessions to port 8080: handshake, a request/response, FIN close.
- A SYN port scan of ports 1-50: one SYN each, answered by RST/ACK.
- A SYN flood: 300 SYNs from one source port to port 80 within 0.3 s, no replies.

Usage: python tests/fixtures/make_sample_pcap.py
"""
from pathlib import Path

from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from scapy.utils import wrpcap

HOST = "127.0.0.1"
BASE_TS = 1_700_000_000.0
OUT = Path(__file__).with_name("sample.pcap")


def tcp(sport, dport, flags, seq=0, ack=0, payload=b""):
    pkt = IP(src=HOST, dst=HOST) / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack)
    return pkt / Raw(payload) if payload else pkt


def stamp(pkt, ts):
    pkt.time = ts
    return pkt


def benign_session(i, start):
    c, s = 40000 + i, 8080
    req, resp = b"GET / HTTP/1.1\r\n\r\n", b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * (200 + 10 * i)
    steps = [
        (tcp(c, s, "S", 1), 0.000),
        (tcp(s, c, "SA", 100, 2), 0.001),
        (tcp(c, s, "A", 2, 101), 0.002),
        (tcp(c, s, "PA", 2, 101, req), 0.010),
        (tcp(s, c, "A", 101, 2 + len(req)), 0.011),
        (tcp(s, c, "PA", 101, 2 + len(req), resp), 0.050),
        (tcp(c, s, "A", 2 + len(req), 101 + len(resp)), 0.051),
        (tcp(c, s, "FA", 2 + len(req), 101 + len(resp)), 1.000),
        (tcp(s, c, "FA", 101 + len(resp), 3 + len(req)), 1.001),
        (tcp(c, s, "A", 3 + len(req), 102 + len(resp)), 1.002),
    ]
    return [stamp(p, start + dt) for p, dt in steps]


def port_scan(start):
    pkts = []
    for n, port in enumerate(range(1, 51)):
        t = start + n * 0.01
        pkts.append(stamp(tcp(55555, port, "S", 1), t))
        pkts.append(stamp(tcp(port, 55555, "RA", 0, 2), t + 0.0001))
    return pkts


def syn_flood(start):
    return [stamp(tcp(60000, 80, "S", n), start + n * 0.001) for n in range(300)]


def build():
    pkts = []
    for i in range(20):
        pkts += benign_session(i, BASE_TS + i * 2.0)
    pkts += port_scan(BASE_TS + 50)
    pkts += syn_flood(BASE_TS + 60)
    pkts.sort(key=lambda p: p.time)
    return pkts


if __name__ == "__main__":
    pkts = build()
    wrpcap(str(OUT), pkts)
    print(f"wrote {len(pkts)} packets to {OUT}")
