"""Train the Isolation Forest baseline on benign CICIDS2017 flows.

Usage:
  python backend/ml/train_baseline.py --csv data/raw/cicids2017/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv
"""
import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # allow `python backend/ml/train_baseline.py`

from backend.features.feature_set import CICIDS_NEEDED, FEATURES, from_cicids, save_model

DEFAULT_OUT = "models/isolation_forest.joblib"
RANDOM_STATE = 42
N_QUANTILES = 1001
# Flag flows more anomalous than this fraction of benign training flows; contamination="auto"
# flagged far too many benign Monday rows to be a usable alarm (see PROGRESS.md, Phase 1).
FLAG_QUANTILE = 0.99
FLAG_INDEX = 990  # np.linspace(0, 1, N_QUANTILES)[990] == FLAG_QUANTILE


def build_model():
    # Features are heavy-tailed counts and rates; log1p keeps Isolation Forest splits from being dominated by outliers.
    return make_pipeline(
        FunctionTransformer(np.log1p),
        IsolationForest(n_estimators=200, random_state=RANDOM_STATE),
    )


def anomaly_scores(model, X: pd.DataFrame) -> np.ndarray:
    """Higher = more anomalous."""
    return -model.score_samples(X[FEATURES])


def train(X: pd.DataFrame) -> tuple[object, dict]:
    """Fit on benign feature rows; return (model, scoring metadata to save in the sidecar)."""
    model = build_model().fit(X[FEATURES])
    quantiles = np.quantile(anomaly_scores(model, X), np.linspace(0, 1, N_QUANTILES)).tolist()
    # Threshold is taken from the same grid confidence uses, so a flagged flow never reports < FLAG_QUANTILE.
    return model, {"flag_quantile": FLAG_QUANTILE, "threshold": quantiles[FLAG_INDEX], "benign_score_quantiles": quantiles}


def score(model, meta: dict, X: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Return (flagged, confidence). Confidence = percentile of the anomaly score among benign training flows."""
    s = anomaly_scores(model, X)
    quantiles = np.asarray(meta["benign_score_quantiles"])
    confidence = np.searchsorted(quantiles, s, side="right") / len(quantiles)
    return s > meta["threshold"], confidence


def load_benign(csv_paths: list[str], sample: int) -> tuple[pd.DataFrame, dict]:
    frames, stats = [], {"rows_read": 0, "rows_dropped_invalid": 0, "benign_rows": 0}
    for path in csv_paths:
        raw = pd.read_csv(path, usecols=lambda c: c.strip() in CICIDS_NEEDED, low_memory=False)
        X, labels, dropped = from_cicids(raw)
        stats["rows_read"] += len(raw)
        stats["rows_dropped_invalid"] += dropped
        frames.append(X[labels == "BENIGN"])
    benign = pd.concat(frames, ignore_index=True)
    stats["benign_rows"] = len(benign)
    if len(benign) > sample:
        benign = benign.sample(n=sample, random_state=RANDOM_STATE)
    return benign.reset_index(drop=True), stats


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", nargs="+", required=True, help="CICIDS2017 MachineLearningCVE CSV file(s)")
    parser.add_argument("--sample", type=int, default=50_000, help="max benign rows to train on")
    parser.add_argument("--out", default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    X, stats = load_benign(args.csv, args.sample)
    if X.empty:
        sys.exit("no BENIGN rows found in the given CSV(s)")
    model, scoring = train(X)
    save_model(model, args.out, trained_on=args.csv, n_train_rows=len(X), random_state=RANDOM_STATE, **stats, **scoring)
    print(f"read {stats['rows_read']} rows, dropped {stats['rows_dropped_invalid']} invalid, "
          f"{stats['benign_rows']} benign; trained on {len(X)}; saved {args.out}")


if __name__ == "__main__":
    main()
