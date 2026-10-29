from pathlib import Path

from backend.features.extractor import PacketInfo
from backend.features.flow_table import FlowTable, flows_from_pcap

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "sample.pcap"


def pkt(ts, flags="A", sport=40000, dport=8080, src="10.0.0.1", dst="10.0.0.2"):
    return PacketInfo(ts, src, dst, sport, dport, "TCP", 0, flags)


def reply(ts, flags="A"):
    return pkt(ts, flags, sport=8080, dport=40000, src="10.0.0.2", dst="10.0.0.1")


def test_idle_flow_expires_after_5_s():
    table = FlowTable()
    table.add(pkt(0.0))
    assert table.expire(4.9) == []
    assert len(table.expire(5.1)) == 1


def test_long_flow_is_cut_at_active_timeout():
    table = FlowTable()
    for t in range(12):
        table.add(pkt(float(t)))
    done = table.expire(12.0)
    assert len(done) == 1 and done[0].fwd_packets == 12  # first flow ran 0..11 s, past the 10 s active timeout
    table.add(pkt(12.5))
    assert table.flush()[0].fwd_packets == 1  # the same 5-tuple starts a new flow


def test_rst_ends_flow_immediately():
    table = FlowTable()
    table.add(pkt(0.0, "S"))
    done = table.add(reply(0.001, "RA"))
    assert len(done) == 1 and (done[0].fwd_packets, done[0].bwd_packets) == (1, 1)


def test_both_fins_end_flow_after_grace_keeping_last_ack():
    table = FlowTable()
    table.add(pkt(0.0, "FA"))
    table.add(reply(0.1, "FA"))
    table.add(pkt(0.2, "A"))  # closing ACK must stay in the same flow
    assert table.expire(0.5) == []
    done = table.expire(1.3)
    assert len(done) == 1 and done[0].fwd_packets == 2


def test_cap_evicts_least_recently_active():
    table = FlowTable(max_flows=2)
    table.add(pkt(0.0, sport=1))
    table.add(pkt(1.0, sport=2))
    table.add(pkt(2.0, sport=1))  # sport=1 is now the most recent
    evicted = table.add(pkt(3.0, sport=3))
    assert [f.src_port for f in evicted] == [2]
    assert table.evicted == 1


def test_sample_pcap_flows_unchanged():
    flows, _ = flows_from_pcap(SAMPLE)
    by_key = {f.flow_key: f for f in flows}
    assert len(flows) == 71
    benign = by_key["TCP|127.0.0.1|40000|127.0.0.1|8080"].features()
    assert (benign["fwd_packets"], benign["bwd_packets"]) == (6, 4)
