# Evaluation

No results yet. Every number in this file and in README.md must come from `backend/evaluation/benchmark.py` (Phase 5). Until then the table below is a template.

## Datasets

| Dataset | Role | Source | Status |
|---|---|---|---|
| CICIDS2017 MachineLearningCSV (CICFlowMeter flow CSVs, 8 files) | Primary: training and benchmark | Canadian Institute for Cybersecurity, University of New Brunswick (official download page) | Not downloaded. ~225 MB zip; ask before downloading. |
| NSL-KDD | Optional secondary check | UNB CIC | Not planned unless time allows. |
| Synthetic PCAP fixtures | Unit tests and Phase 1 gate | Generated in this repo with Scapy | Phase 1 |

## Preparation

1. Strip whitespace from column names.
2. Drop duplicate columns (CICIDS2017 has `Fwd Header Length` twice).
3. Replace `±inf` with NaN, then drop rows with NaN in the shared feature columns. Report how many rows were dropped.
4. Map columns to the [shared feature subset](DATA_MODEL.md#shared-feature-subset); map labels to [attack types](DATA_MODEL.md#attack-types).
5. Drop exact duplicate rows within the shared subset + label. Report the count.

## Split

- Stratified 80/20 train/test split on the grouped label, `random_state=42`.
- All three detectors are scored on the same test rows.
- Isolation Forest and the PPS rule threshold are fit on **benign rows of the training split only**.
- Random Forest is fit on all training rows.

## Detectors

| Detector | Type | Flags a flow when |
|---|---|---|
| PPS rule | Threshold | `packets_per_s` > 99th percentile of benign training flows |
| Isolation Forest | Unsupervised | `predict() == -1` |
| Random Forest | Supervised, `class_weight="balanced"` | predicted class ≠ `BENIGN` |

## Metrics

Binary task (attack vs benign) so all three detectors are comparable. Positive class = attack.

| Metric | Definition |
|---|---|
| Precision | TP / (TP + FP) |
| Recall | TP / (TP + FN) |
| F1 | 2 · P · R / (P + R) |
| False-positive rate on benign flows | FP / (FP + TN) |
| Per-flow inference latency | Median and p95 wall-clock time of 1,000 single-flow `predict` calls on random test rows, in ms. CPU model recorded with the results. |

Random Forest also gets a per-class precision/recall/F1 table (multi-class), since it is the only detector that names attacks.

## Results table (template)

Command: `python backend/evaluation/benchmark.py` (Phase 5). Outputs a Markdown table and a CSV.

| Detector | Precision | Recall | F1 | FPR (benign) | Latency p50 (ms) | Latency p95 (ms) |
|---|---|---|---|---|---|---|
| PPS rule | — | — | — | — | — | — |
| Isolation Forest | — | — | — | — | — | — |
| Random Forest | — | — | — | — | — | — |

Test rows: — benign, — attack. Hardware: —. Commit: —.

## Live default

To be decided in Phase 5 from the table above, and stated here and in README.md with the reason.

## Caveats to report with results

- Scores are on CICFlowMeter features, not on features computed live from packets; live behaviour can differ (see [LIMITATIONS.md](LIMITATIONS.md)).
- A random split of CICIDS2017 flows puts flows from the same attack session in both train and test, which inflates scores compared with a time-based split.
