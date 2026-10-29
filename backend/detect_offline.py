"""Score every flow in a PCAP and write alerts to CSV.

Detectors: Isolation Forest (per TCP/UDP flow, unnamed "anomaly") and the cross-flow port-scan rule ("PortScan").

Usage:
  python backend/detect_offline.py --pcap tests/fixtures/sample.pcap [--model models/isolation_forest.joblib] [--out alerts.csv]
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # allow `python backend/detect_offline.py`

from backend.detection.scan_rule import ScanDetector  # noqa: E402
from backend.features.extractor import flows_from_pcap  # noqa: E402
from backend.features.feature_set import FEATURES, load_model, severity  # noqa: E402
from backend.ml import train_baseline  # noqa: E402

COLUMNS = ["timestamp", "src_ip", "dst_ip", "attack_type", "score", "severity", "source", "flow_key"]


def alert_row(flow, attack_type: str, confidence: float, source: str) -> dict:
    return {
        "timestamp": flow.end_time,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "attack_type": attack_type,
        "score": round(float(confidence), 4),
        "severity": severity(confidence, named=source != "isolation_forest"),
        "source": source,
        "flow_key": flow.flow_key,
    }


def detect(pcap, model_path):
    """Return (alerts, total flows, parse stats)."""
    model, meta = load_model(model_path)
    flows, stats = flows_from_pcap(pcap)
    # CICIDS2017 has no ICMP/other flows to learn from, so only TCP/UDP flows are scored.
    scored = [f for f in flows if f.protocol in ("TCP", "UDP")]
    rows = []
    if scored:
        X = pd.DataFrame([f.features() for f in scored], columns=FEATURES)
        flagged, confidence = train_baseline.score(model, meta, X)
        # Isolation Forest can't name attacks; named types come from the scan rule and (Phase 5) the Random Forest.
        rows += [alert_row(f, "anomaly", c, "isolation_forest") for f, hit, c in zip(scored, flagged, confidence) if hit]
        scans = ScanDetector()
        rows += [alert_row(f, "PortScan", 1.0, "rule") for f in sorted(scored, key=lambda f: f.first_ts) if scans.observe(f)]
    alerts = pd.DataFrame(rows, columns=COLUMNS).sort_values("timestamp", kind="stable", ignore_index=True)
    return alerts, len(scored), stats


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--model", default=train_baseline.DEFAULT_OUT)
    parser.add_argument("--out", default="data/detections.csv")
    args = parser.parse_args(argv)

    if not Path(args.pcap).is_file():
        sys.exit(f"PCAP not found: {args.pcap}")
    if not Path(args.model).is_file():
        sys.exit(f"model not found: {args.model} (train it with backend/ml/train_baseline.py)")

    try:
        alerts, total, stats = detect(args.pcap, args.model)
    except ValueError as e:  # not a capture file, or model/sidecar mismatch
        sys.exit(str(e))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    alerts.to_csv(args.out, index=False)
    by_source = alerts["source"].value_counts()
    print(f"{total} flows scored, {len(alerts)} alerts "
          f"({by_source.get('isolation_forest', 0)} isolation_forest, {by_source.get('rule', 0)} rule) -> {args.out}")
    skipped = {k: v for k, v in stats.items() if k != "packets"}
    print(f"{stats['packets']} packets read" + (f"; {skipped}" if skipped else ""))


if __name__ == "__main__":
    main()
