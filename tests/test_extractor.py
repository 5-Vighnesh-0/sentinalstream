import gzip
from pathlib import Path

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrHopByHop
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from backend.features import flow_table
from backend.features.extractor import Flow, is_non_first_fragment, parse_packet
from backend.features.flow_table import flows_from_pcap

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "sample.pcap"
LO = "127.0.0.1"


def timed(pkt, ts):
    pkt.time = ts
    return pkt


def test_ethernet_padding_is_not_payload():
    frame = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags="A")
    padded = timed(Ether(bytes(frame).ljust(60, b"\0")), 1.0)
    assert parse_packet(padded).payload_len == 0


def test_ipv6_extension_header_keeps_tcp():
    pkt = timed(IPv6(bytes(IPv6(src="::1", dst="::1") / IPv6ExtHdrHopByHop() / TCP(sport=1234, dport=80, flags="S"))), 1.0)
    p = parse_packet(pkt)
    assert (p.protocol, p.src_port, p.dst_port) == ("TCP", 1234, 80)


def test_non_first_fragment_detected():
    assert is_non_first_fragment(IP(src=LO, dst=LO, proto=17, frag=10) / Raw(b"x" * 20))
    assert not is_non_first_fragment(IP(src=LO, dst=LO) / TCP())


def test_out_of_order_packets_extend_duration():
    late = parse_packet(timed(IP(src=LO, dst=LO) / TCP(sport=1, dport=2), 5.0))
    early = parse_packet(timed(IP(src=LO, dst=LO) / TCP(sport=1, dport=2), 3.0))
    flow = Flow.start(late)
    flow.add(late)
    flow.add(early)
    assert flow.features()["flow_duration_s"] == 2.0


def test_out_of_range_timestamp_rejected():
    with pytest.raises(ValueError, match="timestamp"):
        parse_packet(timed(IP(src=LO, dst=LO) / TCP(), 1e12))


def test_bad_packet_is_skipped_not_fatal(monkeypatch):
    real = flow_table.parse_packet
    seen = []

    def first_fails(pkt):
        seen.append(1)
        if len(seen) == 1:
            raise ValueError("boom")
        return real(pkt)

    monkeypatch.setattr(flow_table, "parse_packet", first_fails)
    flows, stats = flows_from_pcap(SAMPLE)
    assert (stats["packets"], stats["skipped_errors"], len(flows)) == (600, 1, 71)


def test_gzip_capture_rejected(tmp_path):
    gz = tmp_path / "sample.pcap"
    gz.write_bytes(gzip.compress(SAMPLE.read_bytes()))
    with pytest.raises(ValueError, match="pcap"):
        flows_from_pcap(gz)
