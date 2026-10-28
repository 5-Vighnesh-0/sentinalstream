from pathlib import Path

from backend.detection.scan_rule import ScanDetector
from backend.features.extractor import Flow, flows_from_pcap

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "sample.pcap"


def flow(dport, ts, src="10.0.0.9", proto="TCP"):
    return Flow(src, "10.0.0.1", 40000, dport, proto, ts, ts)


def alerts(detector, flows):
    return sum(detector.observe(f) for f in flows)


def test_fast_scan_raises_one_alert():
    assert alerts(ScanDetector(), [flow(p, p * 0.01) for p in range(1, 51)]) == 1


def test_below_threshold_is_quiet():
    assert alerts(ScanDetector(), [flow(p, p * 0.01) for p in range(1, 20)]) == 0


def test_slow_scan_outside_window_is_quiet():
    assert alerts(ScanDetector(), [flow(p, p * 1.0) for p in range(1, 26)]) == 0


def test_long_scan_alerts_once_per_window():
    assert alerts(ScanDetector(), [flow(p, p * 0.1) for p in range(1, 101)]) == 1  # 10 s of scanning
    assert alerts(ScanDetector(), [flow(p, p * 0.1) for p in range(1, 301)]) == 3  # 30 s of scanning


def test_repeat_connections_to_one_port_are_not_a_scan():
    assert alerts(ScanDetector(), [flow(8080, i * 0.01) for i in range(200)]) == 0


def test_icmp_ignored():
    assert alerts(ScanDetector(), [flow(p, p * 0.01, proto="ICMP") for p in range(1, 51)]) == 0


def test_source_state_is_bounded():
    detector = ScanDetector(max_sources=2)
    for i in range(5):
        detector.observe(flow(1, i, src=f"10.0.0.{i}"))
    assert len(detector._recent) == 2


def test_sample_pcap_scan_detected_once():
    flows, _ = flows_from_pcap(SAMPLE)
    detector = ScanDetector()
    hits = [f for f in sorted(flows, key=lambda f: f.first_ts) if detector.observe(f)]
    assert [f.src_port for f in hits] == [55555]
