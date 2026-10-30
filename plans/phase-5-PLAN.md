# Phase 5 Plan — Supervised model and benchmark

## Data profile (all 8 MachineLearningCSV files, measured before planning)

- 2,830,743 rows read; 115 invalid (NaN / infinite / negative in the subset) dropped.
- Exact duplicates on the 5 features + label: 1,116,945 removed (39%). PortScan collapses from 158,930 to 1,612 rows: on these 5 features almost every probe is the same 1–2 packet flow.
- 4,382 rows share their 5 features with a row of a different label (irreducible error on this subset).
- Classes under 100 rows after dedup: Infiltration (36), Heartbleed (11) → dropped. Web Attack Brute Force/XSS/SQLi → `WebAttack` (2,097).

## Tasks

1. `backend/ml/cicids.py` — one loader for training and benchmark: read the 8 CSVs (`from_cicids`), group labels (DATA_MODEL.md), drop exact duplicates, drop classes < 100 rows, keep the source file per row; deterministic stratified 80/20 split (`random_state=42`). Returns a report of every count.
2. `backend/ml/train_supervised.py` — Random Forest (`class_weight="balanced"`, 100 trees, depth capped so the compressed file is small enough to commit, `n_jobs=1` at prediction) on the training split; Isolation Forest retrained on a 50,000-row sample of the training split's benign rows (so the committed IF never saw test rows). Saves both with sidecars.
3. `backend/evaluation/benchmark.py` — one command: rebuild the split, load the **committed** model files (prints sha256), PPS-rule threshold = p99 of training benign `packets_per_s`; on the test split report per detector: precision, recall, F1, FPR on benign, PR-AUC, recall at 1% FPR, single-flow latency p50/p95; Random Forest per-class table with support; Isolation Forest benign FPR per CICIDS2017 day; extra run: Random Forest retrained without PortScan, recall on PortScan test rows (vs Isolation Forest). Writes `docs/benchmark/results.md` and `results.csv`.
4. `backend/detection/detectors.py` — live detectors: Random Forest (named) → scan rule → Isolation Forest (`anomaly`); model paths from `SENTINEL_MODEL_PATH` (RF) and the committed IF.
5. Tests: loader (label grouping, dedup, rare-class drop, split determinism), metric helpers (recall at FPR), detectors combination with a stub RF.
6. README.md and docs/EVALUATION.md: paste the table, state the live default and why.

## Files

| Action | Path |
|---|---|
| create | backend/ml/cicids.py, backend/ml/train_supervised.py, backend/evaluation/__init__.py, backend/evaluation/benchmark.py |
| create | models/random_forest.joblib + .features.json; update models/isolation_forest.* |
| create | docs/benchmark/results.md, docs/benchmark/results.csv |
| modify | backend/detection/detectors.py, backend/pipeline.py, backend/api/main.py (model wiring), README.md, docs/EVALUATION.md, docs/LIMITATIONS.md |
| create | tests/test_cicids.py, tests/test_benchmark.py; update tests/test_detectors via existing tests |

## Acceptance gate (from docs/PHASES.md)

> A table with real numbers for all three detectors on the same held-out data, reproducible by one command.
>
> Hardening: classes with < 100 rows merged or dropped, support reported per class; PR-AUC and recall at 1% FPR for every detector; one run holding out one attack family; benign false-positive rate per CICIDS2017 day for Isolation Forest; benchmark loads the committed model files and prints their sha256; Random Forest capped so the compressed file is small enough to commit.

## Checks

```bash
.venv/bin/python backend/ml/train_supervised.py --csv-dir data/raw/cicids2017/MachineLearningCVE
.venv/bin/python backend/evaluation/benchmark.py --csv-dir data/raw/cicids2017/MachineLearningCVE
.venv/bin/pytest -q
```
