# Limitations

Draft written in Phase 0. Each phase adds what it learns; Phase 7 finishes it. Nothing here is a measured result.

## Feature approximation

Training data are CICFlowMeter flow CSVs; the live pipeline computes features from raw packets in Python. The shared subset ([DATA_MODEL.md](DATA_MODEL.md#shared-feature-subset)) is designed to match, but only approximates CICFlowMeter:

- Flow boundaries differ. CICFlowMeter uses its own timeouts and FIN handling; SentinelStream exports flows on 5 s idle / 10 s active timeouts, so one long CICFlowMeter flow may become several SentinelStream flows with different durations and rates.
- Byte counts are transport payload lengths; header handling may not match CICFlowMeter exactly.
- No TCP flag features. CICIDS2017's `SYN/ACK/FIN/RST Flag Count` columns hold only 0/1 and are unreliable, so they were dropped in Phase 1. The models therefore cannot use "many SYNs, no ACKs" directly; SYN floods are caught only through packet rate and direction counts.
- Zero-duration flows need a defined `packets_per_s`; our rule may differ from how CICFlowMeter produced `Infinity` values.

Consequence: benchmark numbers describe the models on CICIDS2017 CSV features, not on live traffic.

## What it cannot detect

- Anything visible only in payloads (SQL injection content, malware signatures, exploit strings). Only flow statistics are used.
- Encrypted-traffic attacks that look statistically normal.
- Attack types absent from CICIDS2017 can only appear as `anomaly`, and only if Isolation Forest flags them. For example, CICIDS2017 has no UDP flood class, so the simulator's `udp_flood` mode can at best produce `anomaly`.
- Slow, low-volume attacks spread over longer than the active timeout.
- Port scans, with Isolation Forest alone. Each probed port is its own tiny flow (1 packet each way), which looks like ordinary benign short flows; in Phase 1 none of the 50 scan flows in the sample were flagged. Scans are a pattern across flows, which per-flow features don't capture.
- Attacks on other hosts the sensor cannot see (switched networks without a span port).

## Dataset limits

- CICIDS2017 was recorded in 2017 in a lab network; traffic mix and attack tools are dated.
- Classes are heavily imbalanced (some classes have tens of rows); per-class metrics for rare classes are unreliable.
- A random train/test split leaks session-level similarity, so scores are optimistic.

## Isolation Forest thresholding

- It flags flows above the 99th percentile of benign training scores, so about 1% of benign CICIDS2017 Monday flows are flagged by design. The default `contamination="auto"` flagged a large share of its own benign training rows in a Phase 1 investigation and was rejected (see PROGRESS.md).
- Confidence is the benign-score percentile, so every Isolation Forest alert has confidence ≥ 0.99 and severity `high`. Severity is only meaningful for supervised alerts until Phase 5 revisits this.
- Trained on one day (Monday) of one lab network. "Normal" on another network will differ.

## Trust boundary and security

- No authentication. The backend binds `127.0.0.1:8000`; do not expose it on a network.
- Uploaded PCAPs are parsed by Scapy, which is not hardened against hostile input. Size cap, extension check and generated filenames limit, but do not remove, that risk.
- Models are loaded with `joblib`, which can execute code; only load models trained by this repo.

## Capture and Docker

- Live capture needs root or `CAP_NET_RAW`/`CAP_NET_ADMIN`.
- A container's loopback is not the host's loopback. Live capture in Docker needs `network_mode: host` plus `NET_RAW`/`NET_ADMIN`, and the simulator must run in the same network namespace as the backend.
- Host networking behaves as documented only on Linux. On Docker Desktop (macOS/Windows), `lo` inside the VM is not the host's loopback, so the demo is supported on Linux only.
- Python + Scapy capture is suited to low traffic rates (a laptop, a lab); under heavy load the queue drops the oldest packets and the dropped counter rises.

## Scale and storage

- One SQLite file, one writer thread. No retention policy: the DB grows with alerts until deleted manually.
- One upload is processed at a time.

## What production would change (to be expanded in Phase 7)

- Zeek or a C-based flow exporter instead of Python packet capture.
- PostgreSQL (or a time-series store) instead of SQLite.
- A separate sensor host feeding a central collector, with authentication and TLS on the API.
- Features and training data from the deployment network, with periodic retraining and threshold tuning.
