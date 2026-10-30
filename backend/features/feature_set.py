"""Shared flow feature subset.

The single definition of the features every model sees, used by training,
offline detection, live inference and the benchmark. See docs/DATA_MODEL.md.
"""
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn

FEATURES = [
    "flow_duration_s",
    "fwd_packets",
    "bwd_packets",
    "total_bytes",
    "packets_per_s",
]
# No TCP flag features: CICIDS2017's "SYN/ACK/FIN/RST Flag Count" columns hold only 0/1 and are
# unreliable, so real per-flow counts from live packets would always look anomalous (see PROGRESS.md, Phase 1).

# CICIDS2017 (CICFlowMeter) column names, after stripping the leading spaces the CSVs ship with.
CICIDS_DURATION_US = "Flow Duration"
CICIDS_COLUMNS = {
    "fwd_packets": "Total Fwd Packets",
    "bwd_packets": "Total Backward Packets",
}
CICIDS_BYTES = ["Total Length of Fwd Packets", "Total Length of Bwd Packets"]
CICIDS_LABEL = "Label"
CICIDS_NEEDED = [CICIDS_DURATION_US, *CICIDS_COLUMNS.values(), *CICIDS_BYTES, CICIDS_LABEL]

SEVERITY_HIGH = 0.90
SEVERITY_MEDIUM = 0.70
ANOMALY_MEDIUM = 0.999  # Isolation-Forest-only alerts: above p99.9 of benign training scores

# Models are pickles, which run code when loaded: load_model refuses any file not listed here.
# After retraining, the trainers print the line to paste in.
TRUSTED_MODEL_SHA256 = frozenset({
    "bb2cd31c1e40f45ef07622b5a1771fa1b429920c6f7ebcaa4db3e6d9346c7025",  # models/random_forest.joblib
    "df1aaacc4d8a73b375571d3505e7b6185b1827c947dff26f625a59f7766c9d92",  # models/isolation_forest.joblib
})


def packets_per_s(n_packets, duration_s):
    """Zero-duration rule: a flow with no measurable duration gets rate 0 (CICFlowMeter writes Infinity/NaN)."""
    duration_s = np.asarray(duration_s, dtype=float)
    with np.errstate(divide="ignore", invalid="ignore"):
        return np.where(duration_s > 0, np.asarray(n_packets, dtype=float) / duration_s, 0.0)


def severity(confidence: float, named: bool = True) -> str:
    """Named detections (scan rule, Random Forest) can be high; an unnamed anomaly is a triage hint, never high."""
    if not named:
        return "medium" if confidence >= ANOMALY_MEDIUM else "low"
    if confidence >= SEVERITY_HIGH:
        return "high"
    if confidence >= SEVERITY_MEDIUM:
        return "medium"
    return "low"


def from_cicids(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series, int]:
    """Map a raw CICIDS2017 CSV frame to (features, labels, rows_dropped).

    packets_per_s is recomputed from counts and duration so the zero-duration rule
    matches live extraction instead of using the CSV's Infinity values.
    """
    df = df.rename(columns=str.strip)
    df = df.loc[:, ~df.columns.duplicated()]
    out = pd.DataFrame(index=df.index)
    out["flow_duration_s"] = pd.to_numeric(df[CICIDS_DURATION_US], errors="coerce") / 1_000_000
    for feature, column in CICIDS_COLUMNS.items():
        out[feature] = pd.to_numeric(df[column], errors="coerce")
    out["total_bytes"] = sum(pd.to_numeric(df[c], errors="coerce") for c in CICIDS_BYTES)
    out["packets_per_s"] = packets_per_s(out["fwd_packets"] + out["bwd_packets"], out["flow_duration_s"])
    out = out[FEATURES].replace([np.inf, -np.inf], np.nan)
    # CICIDS2017 has a few rows with negative durations/counts; they are measurement errors.
    keep = out.notna().all(axis=1) & (out >= 0).all(axis=1)
    labels = df[CICIDS_LABEL].astype(str).str.strip()
    return out[keep].reset_index(drop=True), labels[keep].reset_index(drop=True), int((~keep).sum())


def sidecar_path(model_path) -> Path:
    model_path = Path(model_path)
    return model_path.with_name(model_path.stem + ".features.json")


def file_sha256(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save_model(model, model_path, **metadata) -> None:
    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path, compress=3)
    meta = {
        "model": model_path.stem,
        "feature_order": FEATURES,
        "sklearn_version": sklearn.__version__,
        "created_at": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "sha256": file_sha256(model_path),
        **metadata,
    }
    sidecar_path(model_path).write_text(json.dumps(meta, indent=2))


def load_model(model_path, trusted=TRUSTED_MODEL_SHA256):
    """Load a model this repo trained: pinned hash, matching sidecar, matching feature order."""
    meta = json.loads(sidecar_path(model_path).read_text())
    if meta["feature_order"] != FEATURES:
        raise ValueError(f"{model_path}: feature order {meta['feature_order']} does not match {FEATURES}")
    sha = file_sha256(model_path)
    if meta.get("sha256") != sha:
        raise ValueError(f"{model_path}: file does not match the sha256 in its sidecar")
    if sha not in trusted:
        raise ValueError(f"{model_path}: not a trusted model (sha256 {sha}); "
                         "add it to TRUSTED_MODEL_SHA256 in backend/features/feature_set.py after retraining")
    return joblib.load(model_path), meta
