"""Detectors over finished flows, shared by offline detection, PCAP upload and live capture."""
from pathlib import Path

import numpy as np
import pandas as pd

from backend.detection.scan_rule import ScanDetector
from backend.features.feature_set import FEATURES, load_model, severity
from backend.ml import train_baseline

COLUMNS = ["timestamp", "src_ip", "dst_ip", "attack_type", "score", "severity", "source", "flow_key"]
SCORED_PROTOCOLS = ("TCP", "UDP")  # CICIDS2017 has no ICMP/other flows to learn from
IFOREST_PATH = Path(__file__).resolve().parents[2] / "models" / "isolation_forest.joblib"


def alert_row(flow, attack_type: str, confidence: float, source: str) -> dict:
    return {
        "timestamp": flow.end_time,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "attack_type": attack_type,
        "score": round(float(confidence), 4),
        "severity": severity(confidence, named=source != "isolation_forest"),
        "source": source,
        "flow_key": flow.flow_key,
        # Not in the offline CSV; used by the API's alert object and flows table.
        "src_port": flow.src_port,
        "dst_port": flow.dst_port,
        "protocol": flow.protocol,
        "features": flow.features(),
    }


class Detectors:
    """Per flow: Random Forest (names the attack), else Isolation Forest ("anomaly"). Across flows: the scan rule.

    model_path is the Random Forest (SENTINEL_MODEL_PATH); the committed Isolation Forest is always loaded too.
    Passing an Isolation Forest instead runs without the Random Forest. Scan-rule state persists across calls,
    so live batches see one scan as one.
    """

    def __init__(self, model_path):
        model, meta = load_model(model_path)
        self.rf = model if hasattr(model, "predict_proba") else None
        self.iforest, self.if_meta = (load_model(IFOREST_PATH) if self.rf is not None else (model, meta))
        self.scans = ScanDetector()

    def score(self, flows) -> list[dict]:
        """Score one batch of finished flows; return alert rows. Only TCP/UDP flows are scored."""
        scored = [f for f in flows if f.protocol in SCORED_PROTOCOLS]
        if not scored:
            return []
        X = pd.DataFrame([f.features() for f in scored], columns=FEATURES)
        if_flagged, if_confidence = train_baseline.score(self.iforest, self.if_meta, X)
        if self.rf is not None:
            proba = self.rf.predict_proba(X)
            label = self.rf.classes_[proba.argmax(axis=1)]
            rf_confidence = proba.max(axis=1)
        else:
            label, rf_confidence = np.full(len(scored), "BENIGN"), np.zeros(len(scored))
        rows = []
        for f, name, rf_c, if_hit, if_c in zip(scored, label, rf_confidence, if_flagged, if_confidence):
            if name != "BENIGN":
                rows.append(alert_row(f, str(name), rf_c, "random_forest"))
            elif if_hit:  # Isolation Forest can't name attacks: only when the classifier saw nothing
                rows.append(alert_row(f, "anomaly", if_c, "isolation_forest"))
        rows += [alert_row(f, "PortScan", 1.0, "rule") for f in sorted(scored, key=lambda f: f.first_ts) if self.scans.observe(f)]
        return rows
