# Phase 1 Plan — Offline detection

## Tasks

1. Python environment: `.venv` (git-ignored) and `requirements.txt` with the approved packages needed this phase (scapy, pandas, numpy, scikit-learn, pytest).
2. `backend/features/feature_set.py` — feature names and order, CICIDS2017 column mapping, zero-duration rule, severity thresholds, model save/load with `<name>.features.json` sidecar and feature-order check.
3. `backend/features/extractor.py` — `PcapReader` → bidirectional flows keyed by 5-tuple → feature rows.
4. `backend/ml/train_baseline.py` — load CICIDS2017 CSV(s), clean, keep `BENIGN` rows, sample (default 50,000 rows, `random_state=42`), fit Isolation Forest, save `models/isolation_forest.joblib` + `.features.json` (includes benign training scores for percentile confidence).
5. `backend/detect_offline.py` — `--pcap`, `--model`, `--out`; writes CSV `timestamp, src_ip, dst_ip, attack_type, score, severity` for flagged flows.
6. Synthetic sample PCAP: `tests/fixtures/make_sample_pcap.py` writes `tests/fixtures/sample.pcap` (benign TCP sessions + a SYN port scan on 127.0.0.1). Deterministic, no network access.
7. Tests: feature extraction on the fixture, feature-order check, CICIDS column mapping, CLI end-to-end with a tiny model.
8. Run the gate; write docs/PHASE1_RESULTS.md from the actual CSV; log evidence in PROGRESS.md.

## Files

| Action | Path |
|---|---|
| create | requirements.txt |
| create | backend/__init__.py, backend/features/__init__.py, backend/ml/__init__.py |
| create | backend/features/feature_set.py, backend/features/extractor.py |
| create | backend/ml/train_baseline.py, backend/detect_offline.py |
| create | tests/fixtures/make_sample_pcap.py, tests/fixtures/sample.pcap |
| create | tests/test_features.py, tests/test_detect_offline.py |
| create | docs/PHASE1_RESULTS.md |
| update | PROGRESS.md |

## Data

CICIDS2017 MachineLearningCSV.zip, from the official UNB page (https://www.unb.ca/cic/datasets/ids-2017.html). The download is behind a registration form, so the human downloads it to `data/raw/cicids2017/MachineLearningCSV.zip`. Training uses a sample of benign rows from `Monday-WorkingHours.pcap_ISCX.csv`. No PCAPs from CICIDS2017 are downloaded.

## Acceptance gate (from docs/PHASES.md)

> `python backend/detect_offline.py --pcap <sample>` yields a CSV with at least one flagged flow, and the numbers in PHASE1_RESULTS.md match the CSV. No FastAPI or React code yet.

## Checks

```bash
.venv/bin/python -m pytest -q
.venv/bin/python backend/ml/train_baseline.py --csv data/raw/cicids2017/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv
.venv/bin/python backend/detect_offline.py --pcap tests/fixtures/sample.pcap --out data/phase1_detections.csv
grep -rlE "fastapi|react" backend/ tests/ || echo "no FastAPI/React code"
```
