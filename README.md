# SentinelStream

Real-time network intrusion detection on a single laptop CPU. SentinelStream captures live traffic (or reads a PCAP), groups packets into flows, scores each flow with machine-learning detectors, and streams alerts to a React dashboard over WebSocket.

> **Status: Phase 3 — API and persistence.** See [docs/PHASES.md](docs/PHASES.md) for the plan and [PROGRESS.md](PROGRESS.md) for what's done.

## What it does

- **Live capture** from an interface (default `lo`) with Scapy, non-blocking, with a bounded queue that drops the oldest packets under load.
- **Flow features**: duration, forward/backward packet counts, total bytes, packets/s — one shared definition used for training and live inference.
- **Detection**: a port-scan rule and (Phase 5) a Random Forest trained on CICIDS2017 that name attack types, plus an Isolation Forest that flags unnamed anomalies.
- **Dashboard**: live alert feed with severity and attack-type filters, packets/s chart, attack distribution, PCAP upload.
- **Offline and free**: no cloud, no paid APIs, no GPU, no telemetry.

Built for a junior SOC analyst or IT admin at a small organisation who wants one browser tab of live alerts.

## Architecture

_Diagram placeholder — rendered diagram added in Phase 7._ The text diagram, components, data flows and trust boundary are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

```
packets ─► capture thread ─► flow table ─► inference thread ─┬─► SQLite (batched writer)
PCAP upload ─► PCAP worker ───────────────────┘              └─► WebSocket ─► React dashboard
```

## Quick start

_Placeholder — filled in Phase 7._ Target:

```bash
docker compose up --build
```

Then open http://localhost:3000. The 5-minute demo with the attack simulator will be in `docs/DEMO.md` (Phase 6).

## Results

_Placeholder — no numbers yet._ Phase 5 adds a benchmark of a packets-per-second rule, Isolation Forest and Random Forest on a held-out CICIDS2017 split (precision, recall, F1, false-positive rate on benign flows, per-flow latency), produced by one command. Method: [docs/EVALUATION.md](docs/EVALUATION.md).

## Documentation

| Doc | Contents |
|---|---|
| [docs/PRD.md](docs/PRD.md) | Problem, users, requirements |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Components, threads, data flows, trust boundary |
| [docs/DATA_MODEL.md](docs/DATA_MODEL.md) | SQLite schema, feature subset, model artifacts |
| [docs/API_SPEC.md](docs/API_SPEC.md) | REST and WebSocket API |
| [docs/PHASES.md](docs/PHASES.md) | Build plan and acceptance gates |
| [docs/EVALUATION.md](docs/EVALUATION.md) | Datasets, metrics, benchmark method |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | What it can't do, and why |
| [AGENTS.md](AGENTS.md) | Rules for anyone (human or AI) working on the repo |

## Stack

Python 3.11+, Scapy, pandas, NumPy, scikit-learn, FastAPI, Uvicorn, SQLite · React 18, Vite, Tailwind CSS, Recharts · pytest, Vitest · Docker Compose, GitHub Actions.

## Citation

Trained on CICIDS2017: Sharafaldin, Lashkari, Ghorbani, "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization", ICISSP 2018.

## License

MIT (LICENSE file added in Phase 7).
