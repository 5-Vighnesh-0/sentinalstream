from pathlib import Path

from backend.detection.scan_rule import ScanDetector
from backend.features.extractor import Flow
from backend.features.flow_table import flows_from_pcap

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


def test_long_scan_is_one_alert_per_burst():
    assert alerts(ScanDetector(), [flow(p, p * 0.1) for p in range(1, 301)]) == 1  # 30 s of continuous scanning


def test_scan_after_a_quiet_window_alerts_again():
    first = [flow(p, p * 0.01) for p in range(1, 51)]
    second = [flow(p, 30 + p * 0.01) for p in range(51, 101)]  # 28 s after the first burst ended
    assert alerts(ScanDetector(), first + second) == 2


def test_no_stale_refire_on_the_next_unrelated_flow():
    # Phase 7 gate: 10.5 s after a 2 s scan, the host's next DNS lookup re-fired the rule on the stale window.
    scan = [flow(p, p * 0.01) for p in range(1, 201)]
    dns = [Flow("10.0.0.9", "10.0.0.53", 43837, 53, "UDP", 10.5 + i, 10.5 + i) for i in range(5)]
    assert alerts(ScanDetector(), scan + dns) == 1


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
