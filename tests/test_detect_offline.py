import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from backend.detect_offline import COLUMNS
from backend.features.feature_set import FEATURES
from backend.ml import train_baseline

REPO = Path(__file__).resolve().parents[1]
SAMPLE = REPO / "tests" / "fixtures" / "sample.pcap"
FLOOD = "TCP|127.0.0.1|60000|127.0.0.1|80"


def run_cli(pcap, out, *extra):
    return subprocess.run(
        [sys.executable, "backend/detect_offline.py", "--pcap", str(pcap), "--out", str(out), *extra],
        cwd=REPO, capture_output=True, text=True, check=False,
    )


def test_cli_with_committed_models(tmp_path):
    result = run_cli(SAMPLE, tmp_path / "out.csv")
    assert result.returncode == 0, result.stderr
    df = pd.read_csv(tmp_path / "out.csv")
    assert list(df.columns) == COLUMNS
    rf, rule = df[df["source"] == "random_forest"], df[df["source"] == "rule"]
    assert rf.loc[rf["flow_key"] == FLOOD, "attack_type"].tolist() == ["DoS"]
    assert rule["attack_type"].tolist() == ["PortScan"]
    assert not df["flow_key"].str.contains("|8080", regex=False).any()  # no benign session flagged
    assert "71 flows scored, 52 alerts (51 random_forest, 0 isolation_forest, 1 rule)" in result.stdout


def test_cli_with_isolation_forest_only(tmp_path):
    result = run_cli(SAMPLE, tmp_path / "out.csv", "--model", "models/isolation_forest.joblib")
    assert result.returncode == 0, result.stderr
    df = pd.read_csv(tmp_path / "out.csv")
    assert list(df.columns) == COLUMNS
    iforest, rule = df[df["source"] == "isolation_forest"], df[df["source"] == "rule"]
    assert iforest["flow_key"].tolist() == [FLOOD]
    assert iforest["score"].min() >= train_baseline.FLAG_QUANTILE
    assert set(iforest["severity"]) <= {"low", "medium"}  # unnamed anomalies are never high (D6)
    assert rule["attack_type"].tolist() == ["PortScan"]
    assert rule["flow_key"].str.contains("|55555|", regex=False).all()
    assert not df["flow_key"].str.contains("|8080", regex=False).any()  # no benign session flagged
    assert "71 flows scored, 2 alerts (0 random_forest, 1 isolation_forest, 1 rule)" in result.stdout


def test_cli_rejects_non_capture_file(tmp_path):
    bogus = tmp_path / "x.pcap"
    bogus.write_text("not a capture")
    result = run_cli(bogus, tmp_path / "o.csv")
    assert result.returncode != 0
    assert "not a pcap/pcapng file" in result.stderr


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


def test_flagged_flows_always_have_confidence_at_least_p99():
    rng = np.random.default_rng(0)
    benign = pd.DataFrame(rng.lognormal(size=(2000, len(FEATURES))), columns=FEATURES)
    model, scoring = train_baseline.train(benign)
    flagged, confidence = train_baseline.score(model, scoring, pd.concat([benign, benign * 50], ignore_index=True))
    assert flagged.any()
    assert confidence[flagged].min() >= train_baseline.FLAG_QUANTILE
    assert scoring["threshold"] == scoring["benign_score_quantiles"][train_baseline.FLAG_INDEX]
