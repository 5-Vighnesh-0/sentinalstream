"""Train the Random Forest, and retrain the Isolation Forest, on the CICIDS2017 training split.

Both models only ever see training-split rows, so backend/evaluation/benchmark.py can score the
committed files on the held-out test split.

Usage:
  python backend/ml/train_supervised.py --csv-dir data/raw/cicids2017/MachineLearningCVE
"""
import argparse
import sys
import time
from pathlib import Path

from sklearn.ensemble import RandomForestClassifier

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # allow `python backend/ml/train_supervised.py`

from backend.features.feature_set import FEATURES, file_sha256, save_model
from backend.ml import cicids, train_baseline

RF_OUT = "models/random_forest.joblib"
IF_OUT = train_baseline.DEFAULT_OUT
IF_SAMPLE = 50_000
# Depth and leaf size are capped so the compressed model stays small enough to commit (D3).
RF_PARAMS = {"n_estimators": 50, "max_depth": 16, "min_samples_leaf": 5, "class_weight": "balanced",
             "random_state": cicids.RANDOM_STATE}


def train_rf(train, n_jobs: int = -1) -> RandomForestClassifier:
    rf = RandomForestClassifier(**RF_PARAMS, n_jobs=n_jobs).fit(train[FEATURES], train["label"])
    rf.n_jobs = 1  # live batches are small; thread start-up would cost more than it saves
    return rf


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv-dir", required=True)
    args = parser.parse_args(argv)

    df, report = cicids.load(args.csv_dir)
    train, test = cicids.split(df)
    print(f"dataset: {report}")
    print(f"split: {len(train)} train / {len(test)} test rows")

    started = time.monotonic()
    rf = train_rf(train)
    save_model(rf, RF_OUT, classes=list(rf.classes_), params=RF_PARAMS, n_train_rows=len(train),
               trained_on="CICIDS2017 MachineLearningCSV, all 8 files, training split", dataset=report)
    print(f'pin for TRUSTED_MODEL_SHA256: "{file_sha256(RF_OUT)}",  # {RF_OUT}')
    print(f"random forest: {time.monotonic() - started:.0f} s, {Path(RF_OUT).stat().st_size:,} bytes -> {RF_OUT}")

    benign = train[train["label"] == "BENIGN"]
    sample = benign.sample(n=min(IF_SAMPLE, len(benign)), random_state=cicids.RANDOM_STATE)
    iforest, scoring = train_baseline.train(sample)
    save_model(iforest, IF_OUT, n_train_rows=len(sample), random_state=cicids.RANDOM_STATE,
               trained_on="CICIDS2017 MachineLearningCSV, all 8 files, benign rows of the training split",
               dataset=report, **scoring)
    print(f'pin for TRUSTED_MODEL_SHA256: "{file_sha256(IF_OUT)}",  # {IF_OUT}')
    print(f"isolation forest: threshold {scoring['threshold']:.4f}, {Path(IF_OUT).stat().st_size:,} bytes -> {IF_OUT}")


if __name__ == "__main__":
    main()
