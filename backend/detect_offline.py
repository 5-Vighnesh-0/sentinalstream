"""Score every flow in a PCAP and write the flagged ones to CSV.

Usage:
  python backend/detect_offline.py --pcap tests/fixtures/sample.pcap [--model models/isolation_forest.joblib] [--out alerts.csv]
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # allow `python backend/detect_offline.py`

from backend.features.extractor import flows_from_pcap  # noqa: E402
from backend.features.feature_set import FEATURES, load_model, severity  # noqa: E402
from backend.ml import train_baseline  # noqa: E402

COLUMNS = ["timestamp", "src_ip", "dst_ip", "attack_type", "score", "severity"]


def detect(pcap, model_path) -> tuple[pd.DataFrame, int]:
    """Return (flagged rows, total flows)."""
    model, meta = load_model(model_path)
    flows, _ = flows_from_pcap(pcap)
    if not flows:
        return pd.DataFrame(columns=COLUMNS), 0
    X = pd.DataFrame([f.features() for f in flows], columns=FEATURES)
    flagged, confidence = train_baseline.score(model, meta, X)
    rows = [
        {
            "timestamp": f.end_time,
            "src_ip": f.src_ip,
            "dst_ip": f.dst_ip,
            # Isolation Forest cannot name attacks; labels come only from the supervised model (Phase 5).
            "attack_type": "anomaly",
            "score": round(float(c), 4),
            "severity": severity(c),
        }
        for f, hit, c in zip(flows, flagged, confidence)
        if hit
    ]
    return pd.DataFrame(rows, columns=COLUMNS), len(flows)


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

    result, total = detect(args.pcap, args.model)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(args.out, index=False)
    print(f"{total} flows scored, {len(result)} flagged -> {args.out}")


if __name__ == "__main__":
    main()
