import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from backend.features.feature_set import (
    FEATURES,
    TRUSTED_MODEL_SHA256,
    file_sha256,
    from_cicids,
    load_model,
    packets_per_s,
    save_model,
    severity,
)
from backend.features.flow_table import flows_from_pcap

REPO = Path(__file__).resolve().parents[1]
SAMPLE = Path(__file__).resolve().parent / "fixtures" / "sample.pcap"


@pytest.fixture(scope="module")
def flows():
    return {f.flow_key: f for f in flows_from_pcap(SAMPLE)[0]}


def test_sample_flow_count(flows):
    assert len(flows) == 20 + 50 + 1  # benign sessions + scanned ports + one flood flow


def test_benign_session_features(flows):
    feats = flows["TCP|127.0.0.1|40000|127.0.0.1|8080"].features()
    assert list(feats) == FEATURES
    assert (feats["fwd_packets"], feats["bwd_packets"]) == (6, 4)
    assert feats["total_bytes"] == 18 + 219  # request + response payloads
    assert feats["flow_duration_s"] == pytest.approx(1.002, abs=1e-5)


def test_scan_flow_direction(flows):
    feats = flows["TCP|127.0.0.1|55555|127.0.0.1|22"].features()
    assert (feats["fwd_packets"], feats["bwd_packets"]) == (1, 1)


def test_flood_flow(flows):
    feats = flows["TCP|127.0.0.1|60000|127.0.0.1|80"].features()
    assert (feats["fwd_packets"], feats["bwd_packets"]) == (300, 0)
    assert feats["packets_per_s"] == pytest.approx(300 / 0.299, rel=1e-3)


def test_zero_duration_rule():
    assert packets_per_s(5, 0.0) == 0.0
    assert packets_per_s(5, 2.0) == 2.5


def test_severity_named_detections():
    assert [severity(c) for c in (0.95, 0.9, 0.8, 0.7, 0.69)] == ["high", "high", "medium", "medium", "low"]


def test_severity_unnamed_anomalies_never_high():
    assert [severity(c, named=False) for c in (1.0, 0.999, 0.998, 0.99)] == ["medium", "medium", "low", "low"]


def test_from_cicids_cleans_and_maps():
    raw = pd.DataFrame({
        " Flow Duration": [2_000_000, 0, -5, 1_000_000],
        " Total Fwd Packets": [3, 1, 1, 2],
        " Total Backward Packets": [1, 0, 1, 2],
        "Total Length of Fwd Packets": [100, 0, 0, 10],
        " Total Length of Bwd Packets": [50, 0, 0, np.inf],
        " SYN Flag Count": [1, 1, 0, 0],  # present in real CSVs, ignored by the mapping
        " Label": ["BENIGN", "PortScan", "BENIGN", "BENIGN"],
    })
    X, labels, dropped = from_cicids(raw)
    assert list(X.columns) == FEATURES
    assert dropped == 2  # negative duration and infinite bytes
    assert labels.tolist() == ["BENIGN", "PortScan"]
    assert X.loc[0, "flow_duration_s"] == 2.0
    assert X.loc[0, "total_bytes"] == 150
    assert X.loc[0, "packets_per_s"] == 2.0
    assert X.loc[1, "packets_per_s"] == 0.0  # zero-duration rule, not Infinity


def test_load_model_rejects_wrong_feature_order(tmp_path):
    path = tmp_path / "m.joblib"
    save_model({"dummy": True}, path)
    trusted = {file_sha256(path)}
    _, meta = load_model(path, trusted=trusted)
    assert meta["feature_order"] == FEATURES

    sidecar = tmp_path / "m.features.json"
    sidecar.write_text(sidecar.read_text().replace('"fwd_packets"', '"renamed"'))
    with pytest.raises(ValueError, match="feature order"):
        load_model(path, trusted=trusted)


def test_load_model_rejects_tampered_file(tmp_path):
    path = tmp_path / "m.joblib"
    save_model({"dummy": True}, path)
    trusted = {file_sha256(path)}
    path.write_bytes(path.read_bytes() + b"\0")
    with pytest.raises(ValueError, match="sha256"):
        load_model(path, trusted=trusted)


def test_untrusted_model_refused_before_unpickling(tmp_path):
    path = tmp_path / "m.joblib"
    save_model({"dummy": True}, path)
    with pytest.raises(ValueError, match="not a trusted model"):
        load_model(path)


def test_committed_models_are_pinned():
    for name in ("random_forest", "isolation_forest"):
        sha = json.loads((REPO / "models" / f"{name}.features.json").read_text())["sha256"]
        assert sha in TRUSTED_MODEL_SHA256, f"{name}: retrained? paste its pin into TRUSTED_MODEL_SHA256"
