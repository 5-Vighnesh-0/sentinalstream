"""Benchmark the PPS rule, Isolation Forest and Random Forest on the same held-out CICIDS2017 test split.

Loads the committed model files (sha256-checked), rebuilds the training/test split exactly as
backend/ml/train_supervised.py did, and writes docs/benchmark/results.md and results.csv.

Usage:
  python backend/evaluation/benchmark.py --csv-dir data/raw/cicids2017/MachineLearningCVE
"""
import argparse
import platform
import subprocess
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, classification_report

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # allow `python backend/evaluation/benchmark.py`

from backend.features.feature_set import FEATURES, load_model  # noqa: E402
from backend.ml import cicids, train_baseline, train_supervised  # noqa: E402

OUT_DIR = Path("docs/benchmark")
PPS_QUANTILE = 0.99
LATENCY_CALLS = 1000
HOLDOUT_FAMILY = "PortScan"


def recall_at_fpr(attack: np.ndarray, scores: np.ndarray, fpr: float = 0.01) -> float:
    """Recall when the threshold lets through `fpr` of benign flows (comparable across detectors)."""
    threshold = np.quantile(scores[~attack], 1 - fpr)
    return float((scores[attack] > threshold).mean())


def binary_metrics(attack: np.ndarray, flagged: np.ndarray, scores: np.ndarray) -> dict:
    tp = int((flagged & attack).sum())
    fp = int((flagged & ~attack).sum())
    fn = int((~flagged & attack).sum())
    tn = int((~flagged & ~attack).sum())
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "precision": precision,
        "recall": recall,
        "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0,
        "fpr_benign": fp / (fp + tn) if fp + tn else 0.0,
        "pr_auc": float(average_precision_score(attack, scores)),
        "recall_at_1pct_fpr": recall_at_fpr(attack, scores),
    }


def latency_ms(score_one, X: pd.DataFrame) -> tuple[float, float]:
    """Median and p95 wall-clock time of single-flow calls, the way live inference sees a lone flow."""
    rows = np.random.default_rng(cicids.RANDOM_STATE).choice(len(X), LATENCY_CALLS)
    times = []
    for i in rows:
        one = X.iloc[[i]]
        started = time.perf_counter()
        score_one(one)
        times.append((time.perf_counter() - started) * 1000)
    return float(np.median(times)), float(np.percentile(times, 95))


def md_table(df: pd.DataFrame) -> str:
    """Markdown table without the optional `tabulate` dependency; cells are formatted by the caller."""
    rows = [list(map(str, df.columns))] + df.astype(str).values.tolist()
    lines = ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join([lines[0], "|" + "---|" * len(rows[0]), *lines[1:]])


def cpu_name() -> str:
    for line in Path("/proc/cpuinfo").read_text().splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return platform.processor()


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv-dir", required=True)
    args = parser.parse_args(argv)

    rf, rf_meta = load_model(train_supervised.RF_OUT)
    iforest, if_meta = load_model(train_supervised.IF_OUT)
    df, report = cicids.load(args.csv_dir)
    train, test = cicids.split(df)
    if len(train) != rf_meta["n_train_rows"]:
        sys.exit(f"split mismatch: {len(train)} training rows here, model trained on {rf_meta['n_train_rows']}; retrain first")
    X, attack = test[FEATURES], (test["label"] != "BENIGN").to_numpy()

    pps_threshold = float(np.quantile(train.loc[train["label"] == "BENIGN", "packets_per_s"], PPS_QUANTILE))
    if_flagged, _ = train_baseline.score(iforest, if_meta, X)
    benign_col = list(rf.classes_).index("BENIGN")
    rf_pred = rf.predict(X)
    detectors = {
        "PPS rule": (X["packets_per_s"].to_numpy() > pps_threshold, X["packets_per_s"].to_numpy(),
                     lambda one: one["packets_per_s"].to_numpy() > pps_threshold),
        "Isolation Forest": (if_flagged, train_baseline.anomaly_scores(iforest, X),
                             lambda one: train_baseline.score(iforest, if_meta, one)),
        "Random Forest": (rf_pred != "BENIGN", 1 - rf.predict_proba(X)[:, benign_col], rf.predict_proba),
    }
    rows = []
    for name, (flagged, scores, score_one) in detectors.items():
        p50, p95 = latency_ms(score_one, X)
        rows.append({"detector": name, **binary_metrics(attack, flagged, scores), "latency_p50_ms": p50, "latency_p95_ms": p95})
    results = pd.DataFrame(rows)

    per_class = pd.DataFrame(classification_report(test["label"], rf_pred, output_dict=True, zero_division=0)).T
    per_class = per_class.loc[sorted(rf.classes_)]

    benign_test = test[test["label"] == "BENIGN"]
    if_benign_flagged, _ = train_baseline.score(iforest, if_meta, benign_test[FEATURES])
    per_day = benign_test.assign(flagged=if_benign_flagged).groupby("day")["flagged"].agg(["size", "mean"])

    holdout_rf = train_supervised.train_rf(train[train["label"] != HOLDOUT_FAMILY])
    family = test["label"] == HOLDOUT_FAMILY
    holdout = {
        "Random Forest trained with it": float((rf_pred[family] != "BENIGN").mean()),
        f"Random Forest trained without {HOLDOUT_FAMILY}": float((holdout_rf.predict(X[family]) != "BENIGN").mean()),
        "Isolation Forest": float(if_flagged[family].mean()),
        "PPS rule": float((X.loc[family, "packets_per_s"] > pps_threshold).mean()),
    }

    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()
    fmt = {"precision": "{:.4f}", "recall": "{:.4f}", "f1": "{:.4f}", "fpr_benign": "{:.4%}", "pr_auc": "{:.4f}",
           "recall_at_1pct_fpr": "{:.4f}", "latency_p50_ms": "{:.3f}", "latency_p95_ms": "{:.3f}"}
    table = results.copy()
    for col, f in fmt.items():
        table[col] = table[col].map(f.format)
    table.columns = ["Detector", "Precision", "Recall", "F1", "FPR (benign)", "PR-AUC", "Recall @1% FPR",
                     "Latency p50 (ms)", "Latency p95 (ms)"]
    md = [
        "# Benchmark results",
        "",
        f"Generated by `python backend/evaluation/benchmark.py --csv-dir {args.csv_dir}` at commit `{commit}`.",
        "",
        f"Test split: {int((~attack).sum()):,} benign + {int(attack.sum()):,} attack flows "
        f"(stratified 20% of {len(df):,} cleaned, de-duplicated CICIDS2017 rows). Hardware: {cpu_name()}, single process.",
        "",
        md_table(table),
        "",
        f"PPS rule threshold: {pps_threshold:,.1f} packets/s (p99 of training benign flows). "
        "Isolation Forest and PPS rule flag at their p99 benign threshold; Random Forest flags when the predicted class is not BENIGN. "
        "PR-AUC and recall at 1% FPR use each detector's continuous score.",
        "",
        "## Random Forest per class (test split)",
        "",
        md_table(per_class[["precision", "recall", "f1-score", "support"]].reset_index(names="class").assign(
            precision=lambda d: d["precision"].map("{:.4f}".format), recall=lambda d: d["recall"].map("{:.4f}".format),
            **{"f1-score": lambda d: d["f1-score"].map("{:.4f}".format), "support": lambda d: d["support"].astype(int)})),
        "",
        "## Isolation Forest false-positive rate on benign test flows, per CICIDS2017 file",
        "",
        md_table(per_day.reset_index().assign(mean=lambda d: d["mean"].map("{:.4%}".format)).rename(
            columns={"day": "file", "size": "benign test flows", "mean": "flagged"})),
        "",
        f"## Held-out family: recall on the {int(family.sum()):,} {HOLDOUT_FAMILY} test flows",
        "",
        md_table(pd.DataFrame({"detector": list(holdout), "recall": [f"{v:.4f}" for v in holdout.values()]})),
        "",
        "## Dataset",
        "",
        f"`{report}`",
        "",
        "## Models",
        "",
        f"- `{train_supervised.RF_OUT}` sha256 `{rf_meta['sha256']}`",
        f"- `{train_supervised.IF_OUT}` sha256 `{if_meta['sha256']}`",
        "",
    ]
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "results.md").write_text("\n".join(md))
    results.to_csv(OUT_DIR / "results.csv", index=False)
    print("\n".join(md))


if __name__ == "__main__":
    main()
