# Architecture

SentinelStream is a single-host pipeline: packets in, flows out, scores on flows, alerts to SQLite and to the browser. Everything runs in one Python process (backend) plus a static React app (frontend).

## Text diagram

```
                    UNTRUSTED                         │                TRUSTED (this host)
                                                      │
  network packets ──► [Capture thread] (Scapy sniff)  │
  (SENTINEL_IFACE)        │ callback: put_nowait      │
                          ▼                           │
                 packet queue  queue.Queue(maxsize=50000), drop-oldest on full
                          │                           │
                          ▼                           │
                 [Flow-table thread] 1 s tick ─ idle/active timeout ─► flow queue
                                                      │                    │
  PCAP upload ──► POST /upload-pcap ── size+ext check │                    │
  (browser)       saved as <uuid>.pcap in temp dir ──► [PCAP worker]      │
                                       PcapReader → same extractor ───────┤
                                                      │                    ▼
                                                      │          [Inference thread]
                                                      │          feature_set → detectors
                                                      │          (Random Forest + Isolation Forest)
                                                      │                    │ Alert
                                                      │        ┌───────────┴────────────┐
                                                      │        ▼                        ▼
                                                      │  writer queue           loop.call_soon_threadsafe(
                                                      │        │                  asyncio_queue.put_nowait, alert)
                                                      │        ▼                        │
                                                      │  [Writer thread]                ▼
                                                      │  1 SQLite connection     [FastAPI event loop]
                                                      │  batch: 50 alerts or 2 s  broadcaster task
                                                      │        │                        │
                                                      │        ▼                        ▼
                                                      │  data/sentinelstream.db   WS /ws/alerts ──► browser
                                                      │        ▲                        (React dashboard :3000)
  browser ──► GET /alerts, GET /health ───────────────┼────────┘ (read-only queries)
                                                      │
  OFFLINE (no server): CICIDS2017 CSVs ─► train_baseline.py / train_supervised.py ─► models/*.joblib + *.features.json
                                       └► benchmark.py ─► results table (README.md, docs/EVALUATION.md)
```

## Components

| Component | Path (created in phase) | Responsibility |
|---|---|---|
| Shared feature module | `backend/features/feature_set.py` (1) | Single source of truth: feature names, order, CICIDS2017 column mapping, zero-duration rule. Used by training, offline detection, live inference and the benchmark. |
| Flow extractor | `backend/features/extractor.py` (1) | `PcapReader` → group packets by 5-tuple → feature rows. |
| Baseline trainer | `backend/ml/train_baseline.py` (1) | Isolation Forest on benign flows; saves model + feature order. |
| Offline detector | `backend/detect_offline.py` (1) | CLI: PCAP in, CSV of flagged flows out. |
| Capture | `backend/capture/sniffer.py` (2) | `CaptureThread` (daemon): Scapy sniff, non-blocking enqueue, drop-oldest, dropped-packet counter. |
| Flow table | `backend/features/flow_table.py` (2) | Active flows keyed by 5-tuple; 1 s tick exports flows on idle/active timeout or FIN/RST. |
| Pipeline | `backend/pipeline.py` (2) | Wires capture → flow table → inference worker → alert sinks. `--iface` flag. |
| DB writer | `backend/db/writer.py` (3) | Writer thread with one long-lived SQLite connection; batched inserts. |
| API | `backend/api/main.py` (3) | FastAPI app: REST endpoints, WebSocket broadcaster, upload handling, startup/shutdown of pipeline threads. |
| Dashboard | `frontend/` (4) | React 18 + Vite + Tailwind + Recharts. Port 3000. |
| Supervised trainer | `backend/ml/train_supervised.py` (5) | Cleans CICIDS2017 CSVs, trains Random Forest (`class_weight="balanced"`). |
| Benchmark | `backend/evaluation/benchmark.py` (5) | Compares PPS rule, Isolation Forest, Random Forest on the same held-out split. |
| Simulator | `simulator/simulate_attack.py` (6) | portscan / udp_flood / syn_flood against 127.0.0.0/8 only, rate- and count-capped. |
| Packaging | `Dockerfile`s, `docker-compose.yml`, `docker-compose.demo.yml`, `.github/workflows/ci.yml` (6–7) | Containers and CI. |

The `ml/` top-level directory is reserved for notebooks/exploration notes; all importable ML code lives under `backend/ml/` so the backend container has it.

## Threads

| Thread | Blocks on | Never does |
|---|---|---|
| Capture (daemon) | Scapy sniff | ML, I/O, locking waits. Callback only calls `put_nowait`; on `queue.Full` it calls `get_nowait()` once, then `put_nowait()`, increments the dropped counter and logs a warning (rate-limited). |
| Flow table | packet queue `get(timeout=1)` | ML. Exports finished flows to the flow queue. |
| Inference | flow queue | SQLite or socket I/O. Pushes each alert to the writer queue and to the event loop via `loop.call_soon_threadsafe(asyncio_queue.put_nowait, alert)`. |
| Writer | writer queue | Opening a connection per insert. Commits every 50 alerts or 2 s, whichever comes first. |
| PCAP worker | upload job queue | Blocking the event loop. Runs one upload at a time. |
| FastAPI event loop | asyncio | ML or blocking DB writes. Reads use a separate read-only connection. |

## The three data flows

1. **Live detection.** Interface → capture thread → packet queue → flow table → flow queue → inference → (a) writer → SQLite, (b) asyncio queue → WebSocket → dashboard. The event loop also sends a `stats` message every second (packets/s, active flows, dropped packets, interface).
2. **PCAP upload.** Browser → `POST /upload-pcap` → size and extension check → saved under a temp directory as `<uuid4>.pcap|.pcapng` → `upload_batches` row (`pending`) → PCAP worker runs the same extractor and detectors → alerts tagged with `batch_id` → SQLite + WebSocket → batch marked `done` or `failed` → temp file deleted.
3. **Offline training and evaluation.** CICIDS2017 CSVs → cleaning → shared feature subset → stratified split → train Isolation Forest / Random Forest → `models/<name>.joblib` + `models/<name>.features.json` → `benchmark.py` → Markdown table + CSV pasted into README.md and docs/EVALUATION.md. No server involved.

## Detection logic

- **Random Forest** (supervised, Phase 5): flags a flow when the predicted class is not `BENIGN`. `attack_type` = predicted class, `confidence` = predicted class probability.
- **Isolation Forest** (unsupervised, Phase 1): flags a flow when `predict() == -1`. It cannot name an attack, so `attack_type = "anomaly"`. `confidence` = percentile of the flow's anomaly score among the benign training scores.
- **Combination:** if the Random Forest flags, its label wins. If only Isolation Forest flags, the alert is `"anomaly"`. If neither flags, no alert. Before Phase 5 only Isolation Forest is available.
- **PPS rule** (benchmark baseline only): flags when `packets_per_s` exceeds the 99th percentile of benign training flows.
- **Severity** from confidence: `high` ≥ 0.90, `medium` ≥ 0.70, otherwise `low`. These are initial, untuned values defined once in backend code.

Which detector is the live default is decided from the Phase 5 benchmark and stated in README.md.

## Trust boundary

Untrusted inputs, all validated at the edge:

| Input | Risk | Control |
|---|---|---|
| Network packets | Malformed or adversarial packets; floods | Scapy parsing inside try/except; bounded queue with drop-oldest; no payload stored. |
| Uploaded PCAP files | Oversized files, path traversal, parser crashes | 50 MB cap enforced while streaming; extension must be `.pcap` or `.pcapng`; saved under a generated filename in a temp dir (client filename is never used as a path, only stored as display text); parse errors mark the batch `failed`. |
| HTTP/WS clients | No auth exists | Backend binds `127.0.0.1:8000`; CORS allows only `http://localhost:3000`; query parameters validated by FastAPI/Pydantic; SQL uses bound parameters only. |
| Dataset CSVs / model files | `joblib` files execute code when loaded | Only load models this repo trained into `models/`; never load models from uploads or the network. |

Trusted: the host OS, the Python process, files under the repo root.

## Configuration

| Env var | Default | Used by |
|---|---|---|
| `SENTINEL_IFACE` | `lo` | Capture thread (overridden by `--iface`) |
| `SENTINEL_MODEL_PATH` | `models/random_forest.joblib` | Inference (supervised model). Until Phase 5 creates it, the pipeline runs Isolation Forest only (`models/isolation_forest.joblib`). |
| `SENTINEL_DB_PATH` | `data/sentinelstream.db` | Writer and API reads |

Ports: frontend 3000 (set explicitly in `vite.config` and the Nginx config), backend 8000.

## Deployment (Phase 6–7)

- Backend container: `python:3.12-slim`, `network_mode: host`, `cap_add: [NET_RAW, NET_ADMIN]`, binds `127.0.0.1:8000`, named volume for `data/`.
- Frontend container: Node 24 LTS build stage, Nginx serve stage, port 3000.
- A container's loopback is not the host's loopback. Live capture on `lo` only sees host traffic with host networking, and the simulator must share the backend's network namespace (also `network_mode: host` in `docker-compose.demo.yml`). Linux hosts only; see [LIMITATIONS.md](LIMITATIONS.md).
