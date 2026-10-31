# AGENTS.md — read this first

Rules for anyone working on SentinelStream, human or AI agent.

## Start of every session

1. Read this file, [PROGRESS.md](PROGRESS.md) and [docs/PHASES.md](docs/PHASES.md). Don't rely on memory of earlier sessions.
2. Find the current phase in PROGRESS.md. Work on that phase only.

## Hard rules

1. **Follow phases in order. Never skip a gate.** Phase N+1 starts only after the human types `phase N accepted` (Phase 0: `documentation approved`).
2. **Phase 0 is documentation only.** No `.py`, `.ts` or `.tsx` files until `documentation approved`.
3. **Only do what the current phase asks.** No extra features, abstractions, auth, dark mode, files or dependencies beyond the phase plan.
4. **No unmeasured numbers.** Accuracy, latency and false-positive rates appear only if a script in this repo produced them. Every number in README.md must be reproducible from `backend/evaluation/benchmark.py`.
5. **Ask before:** downloading any file over 100 MB (state filename, source, size); adding a dependency not on the approved list below; deleting any file; changing the SQLite schema after Phase 3; running packet capture with `sudo`.
6. **Stay inside the repo root.** Don't touch system config or network settings.
7. If a check fails twice with the same error, stop and report it instead of looping.

## Phase loop

1. Write `plans/phase-N-PLAN.md`: tasks, files to create or change, acceptance gate copied from docs/PHASES.md.
2. Implement only that plan.
3. Add or update tests. A phase fails if tests fail or the gate can't be reproduced from a clean checkout.
4. Run the acceptance checks yourself. Paste real command output into PROGRESS.md with tasks completed and blockers.
5. After each completed step, print one line: `✅ [what was completed]`.
6. Stop, present deliverables and evidence, wait for acceptance.

## Fixed design decisions (don't re-debate; if one proves impossible, stop and ask)

- One shared feature module, `backend/features/feature_set.py`. Feature order is saved next to every model as `models/<name>.features.json`. TCP flag counts were removed from the subset in Phase 1 (human-approved; see PROGRESS.md).
- Isolation Forest only outputs `anomaly` + score. Attack names come from the supervised classifier and, since the Phase 1 hardening pass (human-approved D2), from the cross-flow port-scan rule (`source="rule"`).
- Trained models are committed to git, compressed, and refused at load if their sha256 doesn't match the sidecar (D3).
- Weak-spot decisions D1–D6 and which phase owns each fix: [docs/superpowers/specs/2026-10-28-weak-spot-hardening-design.md](docs/superpowers/specs/2026-10-28-weak-spot-hardening-design.md).
- Benchmark: CICIDS2017 CSVs, shared feature subset, stratified split, PPS rule vs Isolation Forest vs Random Forest.
- Docker capture needs `network_mode: host` + `NET_RAW` (Phase 7 verified NET_ADMIN is not needed); the simulator shares the backend's network namespace.
- Queue overflow: `get_nowait()` once, then `put_nowait()`, log a warning with a dropped counter. Never block the sniff callback.
- No ML in the sniff callback. Bridge with `loop.call_soon_threadsafe(asyncio_queue.put_nowait, alert)`. One long-lived SQLite connection in the writer thread; batch 50 alerts or 2 s.
- PCAP upload: size cap (50 MB), extension check, generated filename in a temp dir. Never use the client filename as a path.

## Conventions

| Item | Value |
|---|---|
| Ports | frontend 3000 (explicit in `vite.config`), backend 8000 |
| Env vars | `SENTINEL_IFACE` (default `lo`), `SENTINEL_MODEL_PATH` (default `models/random_forest.joblib`), `SENTINEL_DB_PATH` (default `data/sentinelstream.db`) |
| Importable Python | under `backend/` (run as `python -m` or with repo root on `PYTHONPATH`) |
| Tests | `tests/` (pytest), `frontend/src/**/*.test.tsx` (Vitest) |
| Data / models | `data/`, `models/` — git-ignored, reproducible from scripts |
| Contracts | [docs/DATA_MODEL.md](docs/DATA_MODEL.md) and [docs/API_SPEC.md](docs/API_SPEC.md) are the source of truth; change docs and code together |

## Approved dependencies

From the project brief: Python 3.11+, scapy, pandas, numpy, scikit-learn (joblib comes with it), fastapi, uvicorn, sqlite3 (stdlib), pytest, react 18, vite, tailwindcss, recharts, vitest. XGBoost only if already installed or approved.

Approved by the human in Phase 0: python-multipart, httpx, uvicorn[standard], ruff, @testing-library/react, jsdom.

Approved by the human in Phase 4: @tailwindcss/vite, @vitejs/plugin-react, @testing-library/dom (no typescript: .tsx is transpiled, not type-checked).

Approved by the human for the dashboard redesign (post-v1): self-hosted font packages (@fontsource / @fontsource-variable), lucide-react.

Anything else: ask first.

## Logging progress

Append to PROGRESS.md for each phase: tasks completed, real command output for every gate check, blockers, open questions. Never edit earlier evidence.
