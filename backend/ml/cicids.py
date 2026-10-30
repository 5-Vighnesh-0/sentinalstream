"""CICIDS2017 loading shared by training and the benchmark: one cleaning, one split. See docs/EVALUATION.md."""
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

from backend.features.feature_set import CICIDS_NEEDED, FEATURES, from_cicids

LABEL_GROUPS = {
    "BENIGN": "BENIGN",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Bot": "Bot",
    "Infiltration": "Infiltration",
    "Heartbleed": "Heartbleed",
}
MIN_CLASS_ROWS = 100  # rarer classes give meaningless per-class metrics and risky "balanced" weights
TEST_SIZE = 0.2
RANDOM_STATE = 42


def group_label(label: str) -> str:
    # The web-attack labels contain a mis-encoded dash ("Web Attack � XSS"); match on the prefix.
    return "WebAttack" if label.startswith("Web Attack") else LABEL_GROUPS[label]


def clean(frames: list[tuple[str, pd.DataFrame]]) -> tuple[pd.DataFrame, dict]:
    """frames: (file name, raw CSV frame). Returns FEATURES + label + day, and a report of every row removed."""
    parts, report = [], {"rows_read": 0, "rows_dropped_invalid": 0}
    for name, raw_frame in frames:
        X, labels, dropped = from_cicids(raw_frame)
        report["rows_read"] += len(raw_frame)
        report["rows_dropped_invalid"] += dropped
        parts.append(X.assign(label=labels.map(group_label), day=name))
    df = pd.concat(parts, ignore_index=True)
    before = len(df)
    df = df.drop_duplicates(subset=[*FEATURES, "label"]).reset_index(drop=True)
    report["duplicates_removed"] = before - len(df)
    counts = df["label"].value_counts()
    rare = counts[counts < MIN_CLASS_ROWS]
    report["dropped_rare_classes"] = {k: int(v) for k, v in rare.items()}
    df = df[~df["label"].isin(rare.index)].reset_index(drop=True)
    report["class_rows"] = {k: int(v) for k, v in df["label"].value_counts().items()}
    return df, report


def load(csv_dir) -> tuple[pd.DataFrame, dict]:
    frames = [(p.name, pd.read_csv(p, usecols=lambda c: c.strip() in CICIDS_NEEDED, low_memory=False))
              for p in sorted(Path(csv_dir).glob("*.csv"))]
    if not frames:
        raise FileNotFoundError(f"no CICIDS2017 CSVs in {csv_dir}")
    return clean(frames)


def split(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Stratified 80/20, fixed seed: training and the benchmark always see the same test rows."""
    return train_test_split(df, test_size=TEST_SIZE, stratify=df["label"], random_state=RANDOM_STATE)
