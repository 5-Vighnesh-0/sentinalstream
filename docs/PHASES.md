# Phases

Build one phase at a time. A phase starts only after the previous one is accepted by the human typing the exact phrase shown. Gates are copied into each `plans/phase-N-PLAN.md`.

## Rules (every phase)

1. Read AGENTS.md, PROGRESS.md and this file first.
2. Write `plans/phase-N-PLAN.md` (tasks, files, gate). Implement only that plan.
3. Add or update tests. The phase fails if tests fail or the gate can't be reproduced from a clean checkout.
4. Run the acceptance checks; paste real command output into PROGRESS.md with tasks done and blockers.
5. Print `✅ [what was completed]` after each completed step.
6. Stop, present deliverables and evidence, wait for `phase N accepted`.
7. If a check fails twice with the same error, stop and report it.

Ask before: downloading any file over 100 MB (name, source, size), adding a dependency not on the approved list in AGENTS.md, deleting any file, changing the SQLite schema after Phase 3, running capture with `sudo`.

---

## Phase 0 — Docs and scaffolding (no logic code)

**Deliverables:** README.md (overview, architecture placeholder, quick-start placeholder, Results placeholder), docs/PRD.md, docs/ARCHITECTURE.md, docs/DATA_MODEL.md, docs/API_SPEC.md, docs/PHASES.md, docs/EVALUATION.md, docs/LIMITATIONS.md, AGENTS.md, PROGRESS.md, empty directories backend/, frontend/, ml/, simulator/, data/, tests/, models/, plans/.

**Gate:** All files exist and are consistent with each other, no logic code exists. Present the file tree plus a one-paragraph summary.

**Accept phrase:** `documentation approved`

## Phase 1 — Offline detection

**Deliverables:**
- `backend/features/feature_set.py` — shared feature subset and CICIDS2017 mapping ([DATA_MODEL.md](DATA_MODEL.md#shared-feature-subset)).
- `backend/features/extractor.py` — `PcapReader`, group by 5-tuple.
- `backend/ml/train_baseline.py` — Isolation Forest trained on benign flows, saved with its feature order.
- `backend/detect_offline.py` — outputs CSV: `timestamp, src_ip, dst_ip, attack_type, score, severity`.
- Tests under `tests/` for feature extraction and the CLI, using a small synthetic PCAP fixture.
- docs/PHASE1_RESULTS.md.

Data: small sample only. Benign training rows come from a sample of the CICIDS2017 Monday CSV (MachineLearningCSV.zip, ~225 MB — ask before downloading, with exact size). Ask before downloading any full CICIDS2017 PCAP.

**Gate:** `python backend/detect_offline.py --pcap <sample>` yields a CSV with at least one flagged flow, and the numbers in PHASE1_RESULTS.md match the CSV. No FastAPI or React code yet.

**Accept phrase:** `phase 1 accepted`

## Phase 2 — Live capture

**Deliverables:**
- `backend/capture/sniffer.py` — `CaptureThread` (daemon), `queue.Queue(maxsize=50000)`, drop-oldest with warning and counter.
- `backend/features/flow_table.py` — active flows, 1-second tick, idle/active timeout.
- `backend/pipeline.py` — wires capture, flow table, inference worker, alerts to an in-memory list; `--iface` flag.
- Tests for flow expiry and queue overflow (no root needed).
- docs/PHASE2_RESULTS.md.

Capturing on `lo` needs root or `CAP_NET_RAW`: ask before using `sudo`.

**Gate:** On `lo`, a looped `ping 127.0.0.1` produces scored flows in near real time. A deliberately overfilled queue logs a warning and the capture thread stays alive.

**Accept phrase:** `phase 2 accepted`

## Phase 3 — API and persistence

**Deliverables:**
- SQLite schema per [DATA_MODEL.md](DATA_MODEL.md) (schema freezes after this phase).
- `backend/db/writer.py` — one long-lived connection, batched inserts (50 alerts or 2 s).
- `backend/api/main.py` — `GET /health`, `GET /alerts`, `POST /upload-pcap`, `WS /ws/alerts` per [API_SPEC.md](API_SPEC.md); asyncio bridge via `loop.call_soon_threadsafe(asyncio_queue.put_nowait, alert)`.
- `tests/test_api.py` — health and alerts query at minimum.

**Gate:** `uvicorn backend.api.main:app` starts, `GET /health` returns `{"status":"ok"}`, a WebSocket client receives an alert from loopback traffic, and SQLite holds the same alert.

**Accept phrase:** `phase 3 accepted`

## Phase 4 — Dashboard

**Deliverables:** Vite + Tailwind scaffold in `frontend/` (port 3000 in `vite.config`); `AlertFeed` (latest 200 only, severity colours, filters), `TrafficChart` (packets/s, last 60 s), `AttackDistribution`, `PCAPUpload`, Demo Mode banner, `useWebSocket` hook with exponential-backoff reconnect. Vitest tests for the hook and `AlertFeed`.

**Gate:** With the backend and a simulated attack running, new alerts appear within 2 seconds, the traffic chart updates every second, and the UI stays responsive after 1,000 alerts.

**Accept phrase:** `phase 4 accepted`

## Phase 5 — Supervised model and benchmark

**Deliverables:**
- `backend/ml/train_supervised.py` — clean CICIDS2017 CSVs (nulls, infinities, duplicate columns), Random Forest with `class_weight="balanced"` (XGBoost only if already installed or approved), saved with feature order.
- `backend/evaluation/benchmark.py` — compares PPS rule, Isolation Forest, Random Forest per [EVALUATION.md](EVALUATION.md); outputs a Markdown table and CSV.
- Table pasted into README.md and docs/EVALUATION.md; statement of the live default detector and why.

Full MachineLearningCSV.zip (~225 MB) is needed: ask before downloading if not already present.

**Gate:** A table with real numbers for all three detectors on the same held-out data, reproducible by one command.

**Accept phrase:** `phase 5 accepted`

## Phase 6 — Simulator and demo

**Deliverables:** `simulator/simulate_attack.py` with modes `portscan`, `udp_flood`, `syn_flood`; hard cap on packet rate and count (default 200 packets, 10 ms interval); refuses any target outside 127.0.0.0/8; `--dry-run`. `docker-compose.demo.yml`. docs/DEMO.md (5-minute walkthrough). Tests for the target check and caps.

**Gate:** Following docs/DEMO.md on a fresh machine shows an alert in the dashboard within 5 minutes with no code edits.

**Accept phrase:** `phase 6 accepted`

## Phase 7 — Packaging

**Deliverables:** Backend Dockerfile (python slim), frontend Dockerfile (Node build, Nginx serve), `docker-compose.yml` (shared SQLite volume, env vars, host networking for capture), `.github/workflows/ci.yml` (Ruff, pytest, frontend build, both Docker builds), CONTRIBUTING.md, LICENSE (MIT), finished docs/LIMITATIONS.md (what it cannot detect, trust boundary, feature approximation, production changes such as Zeek, PostgreSQL, a separate sensor).

**Gate:** `docker compose up --build` works on a clean machine, CI passes on main, and LIMITATIONS.md is specific and honest.

**Accept phrase:** `phase 7 accepted`
