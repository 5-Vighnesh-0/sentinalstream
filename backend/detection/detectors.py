"""Detectors over finished flows, shared by offline detection, PCAP upload and live capture."""
import pandas as pd

from backend.detection.scan_rule import ScanDetector
from backend.features.feature_set import FEATURES, load_model, severity
from backend.ml import train_baseline

COLUMNS = ["timestamp", "src_ip", "dst_ip", "attack_type", "score", "severity", "source", "flow_key"]
SCORED_PROTOCOLS = ("TCP", "UDP")  # CICIDS2017 has no ICMP/other flows to learn from


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
    """Isolation Forest + port-scan rule. Scan-rule state persists across calls, so live batches see a scan as one."""

    def __init__(self, model_path):
        self.model, self.meta = load_model(model_path)
        self.scans = ScanDetector()

    def score(self, flows) -> list[dict]:
        """Score one batch of finished flows; return alert rows. Only TCP/UDP flows are scored."""
        scored = [f for f in flows if f.protocol in SCORED_PROTOCOLS]
        if not scored:
            return []
        X = pd.DataFrame([f.features() for f in scored], columns=FEATURES)
        flagged, confidence = train_baseline.score(self.model, self.meta, X)
        # Isolation Forest can't name attacks; named types come from the scan rule and (Phase 5) the Random Forest.
        rows = [alert_row(f, "anomaly", c, "isolation_forest") for f, hit, c in zip(scored, flagged, confidence) if hit]
        rows += [alert_row(f, "PortScan", 1.0, "rule") for f in sorted(scored, key=lambda f: f.first_ts) if self.scans.observe(f)]
        return rows
