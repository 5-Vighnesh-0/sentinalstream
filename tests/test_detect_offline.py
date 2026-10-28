import json
import subprocess
import sys

import pandas as pd

from backend.detect_offline import COLUMNS
from backend.features.extractor import flows_from_pcap
from backend.features.feature_set import FEATURES, save_model
from backend.ml import train_baseline

SAMPLE = "tests/fixtures/sample.pcap"


def test_cli_flags_attack_flows_not_benign(tmp_path):
    # Train on the fixture's benign sessions only, so the scan/flood flows are unseen behaviour.
    benign = [f.features() for f in flows_from_pcap(SAMPLE)[0] if f.dst_port == 8080]
    model, scoring = train_baseline.train(pd.DataFrame(benign, columns=FEATURES))
    model_path = tmp_path / "iforest.joblib"
    save_model(model, model_path, **scoring)
    out = tmp_path / "out.csv"

    result = subprocess.run(
        [sys.executable, "backend/detect_offline.py", "--pcap", SAMPLE, "--model", str(model_path), "--out", str(out)],
        capture_output=True, text=True, check=True,
    )

    df = pd.read_csv(out)
    assert list(df.columns) == COLUMNS
    assert len(df) >= 1
    assert set(df["attack_type"]) == {"anomaly"}
    assert df["score"].between(0, 1).all()
    assert f"71 flows scored, {len(df)} flagged" in result.stdout


def test_train_baseline_cli_on_cicids_shaped_csv(tmp_path):
    rows = 300
    csv = tmp_path / "Monday.csv"
    pd.DataFrame({
        " Flow Duration": [1_000_000 + i for i in range(rows)],
        " Total Fwd Packets": [3] * rows,
        " Total Backward Packets": [2] * rows,
        "Total Length of Fwd Packets": [120] * rows,
        " Total Length of Bwd Packets": [800] * rows,
        " Fwd Header Length": [60] * rows,
        " Fwd Header Length.1": [60] * rows,  # CICIDS2017 duplicates this column
        " SYN Flag Count": [1] * rows,
        " Label": ["BENIGN"] * (rows - 10) + ["DoS Hulk"] * 10,
    }).to_csv(csv, index=False)
    out = tmp_path / "isolation_forest.joblib"

    train_baseline.main(["--csv", str(csv), "--sample", "100", "--out", str(out)])

    meta = json.loads((tmp_path / "isolation_forest.features.json").read_text())
    assert meta["feature_order"] == FEATURES
    assert meta["n_train_rows"] == 100
    assert meta["benign_rows"] == rows - 10
    assert len(meta["benign_score_quantiles"]) == train_baseline.N_QUANTILES
    assert meta["flag_quantile"] == train_baseline.FLAG_QUANTILE
