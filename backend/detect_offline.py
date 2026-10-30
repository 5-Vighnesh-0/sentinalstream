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

from backend.detection.detectors import COLUMNS, SCORED_PROTOCOLS, Detectors  # noqa: E402
from backend.features.flow_table import flows_from_pcap  # noqa: E402


def detect(pcap, model_path):
    """Return (alerts, flows scored, parse stats)."""
    detectors = Detectors(model_path)
    flows, stats = flows_from_pcap(pcap)
    alerts = pd.DataFrame(detectors.score(flows), columns=COLUMNS).sort_values("timestamp", kind="stable", ignore_index=True)
    return alerts, sum(f.protocol in SCORED_PROTOCOLS for f in flows), stats


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--model", default=str(Path(__file__).resolve().parents[1] / "models" / "random_forest.joblib"),
                        help="Random Forest (or an Isolation Forest alone)")
    parser.add_argument("--out", default="data/detections.csv")
    args = parser.parse_args(argv)

    if not Path(args.pcap).is_file():
        sys.exit(f"PCAP not found: {args.pcap}")
    if not Path(args.model).is_file():
        sys.exit(f"model not found: {args.model} (train it with backend/ml/train_supervised.py)")

    try:
        alerts, total, stats = detect(args.pcap, args.model)
    except ValueError as e:  # not a capture file, or model/sidecar mismatch
        sys.exit(str(e))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    alerts.to_csv(args.out, index=False)
    by_source = alerts["source"].value_counts()
    print(f"{total} flows scored, {len(alerts)} alerts ({by_source.get('random_forest', 0)} random_forest, "
          f"{by_source.get('isolation_forest', 0)} isolation_forest, {by_source.get('rule', 0)} rule) -> {args.out}")
    skipped = {k: v for k, v in stats.items() if k != "packets"}
    print(f"{stats['packets']} packets read" + (f"; {skipped}" if skipped else ""))


if __name__ == "__main__":
    main()
