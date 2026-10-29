import time
from pathlib import Path

from scapy.utils import rdpcap

from backend.pipeline import Pipeline

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "sample.pcap"


def test_pipeline_end_to_end_with_fake_capture():
    packets = rdpcap(str(SAMPLE))

    def fake_sniff(prn, **_):
        for pkt in packets:
            prn(pkt)

    # A frozen clock never expires the 2023 sample flows mid-feed; stop() flushes them, so the result is deterministic.
    pipeline = Pipeline("lo", sniff=fake_sniff, listen=lambda **_: None, clock=lambda: 0.0)
    pipeline.start()
    deadline = time.monotonic() + 10
    while pipeline.stats["packets"] < len(packets) and time.monotonic() < deadline:
        time.sleep(0.05)
    pipeline.stop()

    assert pipeline.stats["packets"] == 600
    assert pipeline.stats["flows_scored"] == 71
    assert sorted(a["source"] for a in pipeline.alerts) == ["isolation_forest", "rule"]


def test_full_flow_queue_counts_drops():
    pipeline = Pipeline("lo", flow_queue_size=1, sniff=lambda **_: None)
    pipeline._emit(["flow"])
    pipeline._emit(["flow", "flow"])
    assert pipeline.stats["dropped_flows"] == 2
