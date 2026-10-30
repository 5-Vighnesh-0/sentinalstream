# Limitations

Draft written in Phase 0. Each phase adds what it learns; Phase 7 finishes it. Nothing here is a measured result.

## Feature approximation

Training data are CICFlowMeter flow CSVs; the live pipeline computes features from raw packets in Python. The shared subset ([DATA_MODEL.md](DATA_MODEL.md#shared-feature-subset)) is designed to match, but only approximates CICFlowMeter:

- Flow boundaries differ. CICFlowMeter uses a 120 s flow timeout and ends a flow at the first FIN; SentinelStream uses 5 s idle / 10 s active timeouts and both FINs or any RST, so long flows become chunks the models never saw in training.
- CICIDS2017 has documented labelling and flow-construction errors (Engelen, Rimmer, Joosen, "Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study", IEEE S&P Workshops 2021).
- IP fragments: a first fragment counts only its own slice; later fragments are skipped and counted, not reassembled.
- Timestamps are floats (sub-microsecond precision is lost); pcap and CICFlowMeter are microsecond-resolution anyway.
- Only TCP/UDP flows are scored. ICMP and other protocols are parsed but never alert (CICIDS2017 has nothing to learn them from).
- Byte counts are transport payload lengths; header handling may not match CICFlowMeter exactly.
- No TCP flag features. CICIDS2017's `SYN/ACK/FIN/RST Flag Count` columns hold only 0/1 and are unreliable, so they were dropped in Phase 1. The models therefore cannot use "many SYNs, no ACKs" directly; SYN floods are caught only through packet rate and direction counts.
- Zero-duration flows need a defined `packets_per_s`; our rule may differ from how CICFlowMeter produced `Infinity` values.

Consequence: benchmark numbers describe the models on CICIDS2017 CSV features, not on live traffic.

## What it cannot detect

- Anything visible only in payloads (SQL injection content, malware signatures, exploit strings). Only flow statistics are used.
- Encrypted-traffic attacks that look statistically normal.
- Attack types absent from CICIDS2017 can only appear as `anomaly`, and only if Isolation Forest flags them. For example, CICIDS2017 has no UDP flood class, so the simulator's `udp_flood` mode can at best produce `anomaly`.
- Slow, low-volume attacks spread over longer than the active timeout.
- Slow port scans: the scan rule needs ≥ 20 targets from one source within 10 s. Its thresholds are untuned, and it can't be benchmarked on CICIDS2017 MachineLearningCSV (no IPs or timestamps), only tested on fixtures.
- Floods spread over random source ports: each packet is its own 1-packet flow, which Isolation Forest doesn't flag. CICIDS2017 has no SYN-flood or UDP-flood class, so floods can only ever appear as `anomaly`.
- Attacks on other hosts the sensor cannot see (switched networks without a span port).
- UDP floods on one 5-tuple: the Phase 2 gate's 20,000-packet UDP burst raised no alert.

## Dataset limits

- CICIDS2017 was recorded in 2017 in a lab network; traffic mix and attack tools are dated.
- Classes are heavily imbalanced (some classes have tens of rows); per-class metrics for rare classes are unreliable.
- A random train/test split leaks session-level similarity, so scores are optimistic.

## Isolation Forest thresholding

- It flags flows above the 99th percentile of benign training scores, so about 1% of benign CICIDS2017 Monday flows are flagged by design. The default `contamination="auto"` flagged a large share of its own benign training rows in a Phase 1 investigation and was rejected (see PROGRESS.md).
- Confidence is the benign-score percentile, so every Isolation Forest alert has confidence ≥ 0.99. Severity for these unnamed alerts is `low`, or `medium` above p99.9 — never `high` (D6). A clear SYN flood can therefore show as `low`; only named detections reach `high`.
- Trained on one day (Monday) of one lab network. "Normal" on another network will differ. Measured in Phase 2: a KDE audio-visualizer widget streaming 60 fps over a loopback WebSocket had every 10 s slice flagged (360 alerts/hour); the other ~870 flows in 30 minutes raised none.
- On loopback every program shares 127.0.0.1, so the scan rule sees them as one source; a burst of DNS replies after resume (queries lost to kernel drops) raised one false `PortScan`.

## Trust boundary and security

- No authentication. The backend binds `127.0.0.1:8000`; do not expose it on a network.
- Uploaded PCAPs are parsed by Scapy, which is not hardened against hostile input. Size cap, extension check and generated filenames limit, but do not remove, that risk.
- Models are loaded with `joblib`, which can execute code; only load models trained by this repo.

## Capture and Docker

- Live capture needs root or `CAP_NET_RAW`/`CAP_NET_ADMIN`.
- A container's loopback is not the host's loopback. Live capture in Docker needs `network_mode: host` plus `NET_RAW`/`NET_ADMIN`, and the simulator must run in the same network namespace as the backend.
- Host networking behaves as documented only on Linux. On Docker Desktop (macOS/Windows), `lo` inside the VM is not the host's loopback, so the demo is supported on Linux only.
- Python + Scapy capture is suited to low traffic rates (a laptop, a lab). In Phase 2 a 20,000-packet loopback burst lost ~39,000 packets (UDP plus ICMP replies) in the kernel before Python read them. Losses are counted (`dropped_packets` for our queue, `kernel_dropped_packets` for the socket), not prevented.
- On `lo` the kernel delivers every packet twice to packet sockets; capture keeps only the incoming copy (BPF `inbound`), as libpcap does.

## Scale and storage

- One SQLite file, one writer thread. Retention keeps at most 100,000 alerts (oldest deleted first); repeats are merged (D4).
- All queues are bounded; drops are counted and shown in the `stats` message.
- Alerts are broadcast before the batched insert, so up to 2 s of already-shown alerts can be missing from SQLite after a crash.
- Uploaded PCAP alerts keep the capture's original timestamps.
- One upload is processed at a time, two can wait; more get 429.
- Privacy: on a real interface, alerts store IP addresses, which are personal data in many jurisdictions. Keep `data/` local; CI never uploads it.

## What production would change (to be expanded in Phase 7)

- Zeek or a C-based flow exporter instead of Python packet capture.
- PostgreSQL (or a time-series store) instead of SQLite.
- A separate sensor host feeding a central collector, with authentication and TLS on the API.
- Features and training data from the deployment network, with periodic retraining and threshold tuning.
