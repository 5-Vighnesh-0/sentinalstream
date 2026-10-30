# Progress

Current phase: **Phase 2 — awaiting `phase 2 accepted`**

Phase 1 accepted ("phase 1 accepted") on 2026-10-29 and pushed.

Phase 0 accepted ("documentation approved") on 2026-10-28.

## Environment (recorded 2026-10-28)

| Tool | Version |
|---|---|
| OS | Linux 7.0.0-38-generic |
| Python | 3.14.4 (project requires 3.11+; Docker image will use 3.12-slim) |
| Node | v26.11.1 |
| Docker | 29.1.3 |
| git | 2.53.0 |

## Available skills and plugins

Checked at the start of Phase 0. Skill used per area:

| Area | Matching skills found | Use |
|---|---|---|
| Documentation | `engineering:documentation`, `agent-skills:documentation-and-adrs` | `engineering:documentation` used for Phase 0 |
| FastAPI | `fastapi`, `fastapi-templates` | Phase 3 |
| React / Vite | `vite`, `frontend-design`, `agent-skills:frontend-ui-engineering` | Phase 4 |
| Charts | `dataviz` | Phase 4 (TrafficChart, AttackDistribution) |
| Docker | `multi-stage-dockerfile` | Phase 7 |
| Testing | `python-testing-patterns`, `vitest`, `webapp-testing`, `superpowers:test-driven-development` | Phases 1–7 |
| CI | `agent-skills:ci-cd-and-automation` | Phase 7 |
| Security | `security-and-hardening` | Phase 3 (upload route), Phase 6 (simulator target check) |

Plugins: the GitHub MCP connector (`plugin:engineering:github`) is installed but not authorised in this session; `gh` CLI is logged in and can be used instead. No packet-capture or ML-specific skill exists, so Scapy and scikit-learn work is done manually.

## Decisions made with the human (Phase 0)

| Question | Answer |
|---|---|
| Git | Use the existing GitHub repo `sentinelstream`. Local repo initialised on `main`; remote not added yet (see open questions). |
| Phase 1 benign training data | CICIDS2017 MachineLearningCSV.zip (~225 MB) — ask before downloading in Phase 1, with exact size. Sample PCAP is synthetic (Scapy). |
| Extra dependencies | Approved: python-multipart, httpx, uvicorn[standard], ruff, @testing-library/react, jsdom. |
| Alerts ↔ flows link | Add nullable `alerts.flow_id` → `flows.id`. |

## Open questions

1. ~~GitHub remote URL~~ Resolved: `origin` = https://github.com/5-Vighnesh-0/sentinalstream. Phase 0 pushed as 405ab1d on top of the repo's initial commit.

---

## Phase 0 — Docs and scaffolding

Plan: [plans/phase-0-PLAN.md](plans/phase-0-PLAN.md)

### Tasks completed

- [x] Skills/plugins recorded (above)
- [x] `git init -b main`, `.gitignore`, empty dirs with `.gitkeep`
- [x] README.md
- [x] docs/PRD.md, docs/ARCHITECTURE.md, docs/DATA_MODEL.md, docs/API_SPEC.md
- [x] docs/PHASES.md, docs/EVALUATION.md, docs/LIMITATIONS.md
- [x] AGENTS.md, PROGRESS.md
- [x] Consistency check and no-logic-code check (evidence below)

### Blockers

None.

### Evidence

```text
$ find . -path ./.git -prune -o -type f \( -name "*.py" -o -name "*.ts" -o -name "*.tsx" \) -print
(no output = no logic code)

$ find . -path ./.git -prune -o -print | sort
.
./AGENTS.md
./backend
./backend/.gitkeep
./data
./data/.gitkeep
./docs
./docs/API_SPEC.md
./docs/ARCHITECTURE.md
./docs/DATA_MODEL.md
./docs/EVALUATION.md
./docs/LIMITATIONS.md
./docs/PHASES.md
./docs/PRD.md
./frontend
./frontend/.gitkeep
./.gitignore
./ml
./ml/.gitkeep
./models
./models/.gitkeep
./plans
./plans/.gitkeep
./plans/phase-0-PLAN.md
./PROGRESS.md
./README.md
./simulator
./simulator/.gitkeep
./tests
./tests/.gitkeep

$ grep -c for shared contract terms per doc (feature_set.py / flow_id / 50 MB / 3000 / 8000)
README.md              feature_set=0 flow_id=0 50MB=0 port3000=1 port8000=0
AGENTS.md              feature_set=1 flow_id=0 50MB=1 port3000=1 port8000=1
docs/API_SPEC.md       feature_set=0 flow_id=1 50MB=1 port3000=1 port8000=1
docs/ARCHITECTURE.md   feature_set=1 flow_id=0 50MB=1 port3000=5 port8000=3
docs/DATA_MODEL.md     feature_set=3 flow_id=1 50MB=0 port3000=0 port8000=0
docs/EVALUATION.md     feature_set=0 flow_id=0 50MB=0 port3000=0 port8000=0
docs/LIMITATIONS.md    feature_set=0 flow_id=0 50MB=0 port3000=0 port8000=1
docs/PHASES.md         feature_set=1 flow_id=0 50MB=0 port3000=1 port8000=0
docs/PRD.md            feature_set=0 flow_id=0 50MB=0 port3000=1 port8000=1

$ grep -rhoE "SENTINEL_[A-Z_]+" --include=*.md . | sort | uniq -c
      3 SENTINEL_DB_PATH
      4 SENTINEL_IFACE
      2 SENTINEL_MODEL_PATH

$ grep -rn "critical" docs AGENTS.md README.md   # severity enum is low|medium|high only
docs/API_SPEC.md:66:**422** invalid parameter (e.g. `severity=critical`, `limit=0`).
```

The only `critical` hit is the API_SPEC example of an *invalid* severity value, as intended.

---

## Phase 1 — Offline detection

Plan: [plans/phase-1-PLAN.md](plans/phase-1-PLAN.md) · Results: [docs/PHASE1_RESULTS.md](docs/PHASE1_RESULTS.md)

### Tasks completed

- [x] `.venv` + `requirements.txt` (scapy 2.8.0, pandas 3.1.0, numpy 2.5.4, scikit-learn 1.9.1, pytest 9.2.0), `pytest.ini`
- [x] `backend/features/feature_set.py`, `backend/features/extractor.py`
- [x] `backend/ml/train_baseline.py`, `backend/detect_offline.py`
- [x] `tests/fixtures/make_sample_pcap.py` → `tests/fixtures/sample.pcap` (600 packets, 71 flows)
- [x] `tests/test_features.py`, `tests/test_detect_offline.py` — 10 passed
- [x] CICIDS2017 zip provided by the human (official form-gated download): 235,102,953 bytes, sha256 `c3f26274b36c837ccf28ffd2dbf4582941c30b3ee70a635c6e5b2f87c4727928`. Only the Monday CSV extracted.
- [x] Isolation Forest trained on 50,000 benign Monday rows
- [x] Gate run, reproduced from a clean clone, docs/PHASE1_RESULTS.md written
- [x] Docs updated for the design changes below (DATA_MODEL, ARCHITECTURE, EVALUATION, LIMITATIONS, AGENTS, README)

### Design changes (human-approved 2026-10-28)

1. **TCP flag counts dropped from the shared subset (9 → 5 features).** In CICIDS2017 the `SYN/ACK/FIN/RST Flag Count` columns hold only 0/1 and are unreliable, so real per-flow counts from packets made every normal TCP session look anomalous. Human chose "drop the 4 flag features" over "0/1 presence" and "keep counts".
2. **Isolation Forest flag rule:** anomaly score > 99th percentile of benign training scores (stored as `threshold` in the sidecar) instead of `predict() == -1` with `contamination="auto"`.

### Investigation (one-off, scratch script — not a claimed result)

First gate run with the original 9 features and `contamination="auto"`: `71 flows scored, 71 flagged`. Monday flag-column check (benign rows after cleaning):

```text
syn_count {0: 495915, 1: 33988}
ack_count {0: 367498, 1: 162405}
fin_count {0: 517743, 1: 12160}
rst_count {0: 529831, 1: 72}
multi-packet flows 120717
syn_count {0: 118412, 1: 2305}
```

Variant comparison (scratch script in the session scratchpad, using the repo's `from_cicids` / `flows_from_pcap`; 50,000 Monday benign rows, `random_state=42`):

```text
contamination="auto":
A counts (current)   flagged benign 20/20  scan 50/50  flood 1/1  | flagged on its own Monday training rows: 23.5%
B binary flags       flagged benign 20/20  scan 50/50  flood 1/1  | flagged on its own Monday training rows: 23.5%
C no flags           flagged benign 20/20  scan 0/50  flood 1/1  | flagged on its own Monday training rows: 31.1%
threshold at benign-score percentile:
A counts (current)   p99: benign 20/20  scan 0/50  flood 1/1  | Monday train flagged 0.90%
B binary flags       p99: benign 20/20  scan 0/50  flood 1/1  | Monday train flagged 0.90%
C no flags           p99: benign 0/20  scan 0/50  flood 1/1  | Monday train flagged 1.00%
(p99.9 flagged nothing in any variant, including the flood)
```

### Evidence — gate run

```text
$ .venv/bin/pytest -q
..........                                                               [100%]
10 passed in 7.78s

$ .venv/bin/python backend/ml/train_baseline.py --csv data/raw/cicids2017/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv
read 529918 rows, dropped 15 invalid, 529903 benign; trained on 50000; saved models/isolation_forest.joblib

$ .venv/bin/python backend/detect_offline.py --pcap tests/fixtures/sample.pcap --out data/phase1_detections.csv
71 flows scored, 1 flagged -> data/phase1_detections.csv

$ cat data/phase1_detections.csv
timestamp,src_ip,dst_ip,attack_type,score,severity
2023-11-14T22:14:20.299Z,127.0.0.1,127.0.0.1,anomaly,0.991,high

$ python -c "...threshold from sidecar..."
{'feature_order': ['flow_duration_s', 'fwd_packets', 'bwd_packets', 'total_bytes', 'packets_per_s'], 'n_train_rows': 50000, 'rows_read': 529918, 'rows_dropped_invalid': 15, 'benign_rows': 529903, 'flag_quantile': 0.99, 'threshold': 0.6738411569235067, 'sklearn_version': '1.9.1'}

$ grep -rliE "fastapi|react" backend/ tests/ || echo "no FastAPI/React code"
no FastAPI/React code
```

### Evidence — clean checkout

```text
$ git clone (clean checkout of HEAD) && python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt
$ unzip Monday CSV
$ .venv/bin/pytest -q
10 passed in 3.63s
$ .venv/bin/python backend/ml/train_baseline.py --csv data/raw/cicids2017/MachineLearningCVE/Monday-WorkingHours.pcap_ISCX.csv
read 529918 rows, dropped 15 invalid, 529903 benign; trained on 50000; saved models/isolation_forest.joblib
$ .venv/bin/python backend/detect_offline.py --pcap tests/fixtures/sample.pcap --out data/phase1_detections.csv
71 flows scored, 1 flagged -> data/phase1_detections.csv
$ diff <clean>/data/phase1_detections.csv <workdir>/data/phase1_detections.csv && echo identical
identical
```

### Gate verdict

`python backend/detect_offline.py --pcap tests/fixtures/sample.pcap` yields a CSV with 1 flagged flow (the SYN flood); PHASE1_RESULTS.md matches the CSV; no FastAPI or React code. Reproducible from a clean clone given the CICIDS zip.

### Blockers

None.

### Known gaps (documented in LIMITATIONS.md)

- Port scan flows are not flagged by Isolation Forest (0/50).
- Every Isolation Forest alert has confidence ≥ 0.99, so severity is always `high`.
- The sample's benign traffic is synthetic and near-identical; it is not evidence of a low false-positive rate.

---

## Phase 1 — hardening pass

Design: [weak-spot design](docs/superpowers/specs/2026-10-28-weak-spot-hardening-design.md) · Plan: [hardening plan](docs/superpowers/plans/2026-10-28-weak-spot-hardening.md)

Method: superpowers brainstorming, informed by three read-only reviews (agent-skills code-reviewer, security-auditor, doubt-driven-development). Their claims that I re-ran: Ethernet padding counted as payload, loopback ping one-way, gzip auto-decompression in Scapy, `::ffff:127.0.0.1` treated as loopback — all confirmed. One claim not confirmed: a 0x96 byte in the Thursday WebAttacks CSV (none found; recheck in Phase 5).

### Decisions (human, 2026-10-28/29)

- D1 hardening pass now; later-phase fixes go into PHASES.md gates.
- D2 cross-flow port-scan rule + Phase 5 Random Forest; the rule may name `PortScan`.
- D3 models committed to git, compressed, sha256-checked.
- D4 alert aggregation (`count`, `last_seen`) before the Phase 3 schema freeze.
- D5 one timestamp-driven flow table for offline, upload and live (Phase 2).
- D6 Isolation-Forest-only alerts are `low`/`medium`, never `high`.
- Ponytail ultra trims approved (recorded in the design doc).

### Tasks completed

- [x] Task 1 — packet parsing: Ethernet padding, IPv6 transport detection, non-first fragments skipped, out-of-order timestamps, per-packet error handling, timestamp range check, pcap/pcapng magic check (gzip rejected) — `6378576`
- [x] Task 2 — severity tiers (D6), compressed models with sha256 check — `f0827ad`
- [x] Task 3 — Isolation Forest threshold taken from the confidence grid — `f2326db`
- [x] Task 4 — `backend/detection/scan_rule.py` with bounded per-source state — `9fc4323`
- [x] Task 5 — CLI: TCP/UDP-only scoring, IF + scan rule, `source`/`flow_key`; model retrained and committed — `820eb7a`
- [x] Task 6 — docs: AGENTS, DATA_MODEL, API_SPEC, ARCHITECTURE, LIMITATIONS, EVALUATION, PRD, README, PHASES gates — `d1ba0b7`
- [x] Task 7 — gate re-run, clean clone without CICIDS, PHASE1_RESULTS rewritten

### Evidence — gate run

```text
$ .venv/bin/pytest -q
29 passed in 10.43s

$ .venv/bin/python backend/detect_offline.py --pcap tests/fixtures/sample.pcap --out data/phase1_detections.csv
71 flows scored, 2 alerts (1 isolation_forest, 1 rule) -> data/phase1_detections.csv
600 packets read

$ cat data/phase1_detections.csv
timestamp,src_ip,dst_ip,attack_type,score,severity,source,flow_key
2023-11-14T22:14:10.190Z,127.0.0.1,127.0.0.1,PortScan,1.0,high,rule,TCP|127.0.0.1|55555|127.0.0.1|20
2023-11-14T22:14:20.299Z,127.0.0.1,127.0.0.1,anomaly,0.991,low,isolation_forest,TCP|127.0.0.1|60000|127.0.0.1|80

$ python -c "...sidecar..."
{'feature_order': ['flow_duration_s', 'fwd_packets', 'bwd_packets', 'total_bytes', 'packets_per_s'], 'n_train_rows': 50000, 'rows_read': 529918, 'rows_dropped_invalid': 15, 'benign_rows': 529903, 'flag_quantile': 0.99, 'threshold': 0.6738411569235067, 'sha256': '72912080f27ae7bb67f2ab726099e60b12d7065c9d000a0abec5c88d5d46ed30', 'sklearn_version': '1.9.1'}

$ ls -l models/
-rw-rw-r-- 1 vighnesh vighnesh  24880 Oct 29 14:02 isolation_forest.features.json
-rw-rw-r-- 1 vighnesh vighnesh 705848 Oct 29 14:02 isolation_forest.joblib

$ grep -rliE "fastapi|react" backend/ tests/ || echo "no FastAPI/React code"
no FastAPI/React code
```

### Evidence — clean clone without the dataset

```text
$ git clone (HEAD, no data/ — no CICIDS) && python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt
$ ls data/
$ .venv/bin/pytest -q
29 passed in 5.66s
$ .venv/bin/python backend/detect_offline.py --pcap tests/fixtures/sample.pcap --out data/phase1_detections.csv
71 flows scored, 2 alerts (1 isolation_forest, 1 rule) -> data/phase1_detections.csv
600 packets read
$ diff <clean>/data/phase1_detections.csv <workdir>/data/phase1_detections.csv && echo identical
identical
```

(`ls data/` prints nothing: only `.gitkeep`, which `ls` hides.)

### Gate verdict

`python backend/detect_offline.py --pcap tests/fixtures/sample.pcap` yields 2 alerts: the port scan (rule) and the SYN flood (Isolation Forest); no benign session flagged; PHASE1_RESULTS.md matches the CSV; no FastAPI or React code; reproducible from a clean clone with no dataset.

### Blockers

None.

### Still open (owned by later phases, see PHASES.md)

- Real false-positive rate: Phase 2 (alerts/hour on loopback) and Phase 5 (per CICIDS2017 day).
- Random-source-port floods are not detected per flow (documented).
- Scan rule thresholds untuned and not benchmarkable on MachineLearningCSV (documented).

---

## Phase 2 — Live capture

Plan: [plans/phase-2-PLAN.md](plans/phase-2-PLAN.md) · Results: [docs/PHASE2_RESULTS.md](docs/PHASE2_RESULTS.md)

### Tasks completed

- [x] `backend/features/flow_table.py` — timestamp-driven flow table (5 s idle, 10 s active, both FINs + 1 s grace, any RST, 100,000-flow cap); `flows_from_pcap` moved here so offline, upload and live share it (D5) — `e897bdc`
- [x] `backend/detection/detectors.py` — Isolation Forest + scan rule shared by offline and live; `detect_offline.py` uses it
- [x] `backend/capture/sniffer.py` — `CaptureThread` (daemon, `store=False`, BPF `not port 8000 and not port 3000`, drop-oldest with warning) — `843462e`
- [x] `backend/pipeline.py` — capture → bounded packet queue → flow table (1 s tick) → bounded flow queue → batched inference → in-memory alerts; `--iface`, `--duration`, `--queue-size` — `843462e`
- [x] Kernel drops counted via `PACKET_STATISTICS` — `b9a3abc` (human chose "count drops only", no bigger buffer)
- [x] Loopback duplicate packets removed (bug found by the live gate) — `eda1ca1`, then in the kernel filter — `4356d62`
- [x] Tests: flow expiry/cap, offline equivalence, queue overflow + warning + thread alive, kernel-drop accumulation, loopback dedup filter, pipeline end to end with a fake capture — 42 passed
- [x] Live gate on `lo` with `sudo` (human-approved each run), docs/PHASE2_RESULTS.md, LIMITATIONS.md, API_SPEC.md (`kernel_dropped_packets`)

### Evidence — gate 1 (curl loop, commit eda1ca1)

```text
2026-10-29 14:57:21,334 INFO capturing on lo with models/isolation_forest.joblib
2026-10-29 14:58:21,383 INFO summary {"elapsed_s": 60.1, "packets": 19043, "flows_scored": 120, "flows_unscored": 0, "dropped_packets": 0, "kernel_dropped_packets": 0, "active_flows": 0, "evicted_flows": 0, "max_delay_s": 2.02, "alerts": {"isolation_forest": 6}, "alerts_per_hour": {"isolation_forest": 359.7}}
```

### Evidence — gate 2 (overfilled queue, commit 4356d62, kernel BPF dedup)

```text
2026-10-29 20:36:38,148 INFO capturing on lo with models/isolation_forest.joblib
2026-10-29 20:36:41,176 WARNING packet queue full: dropped 1 packets so far
2026-10-29 20:37:08,203 INFO summary {"elapsed_s": 30.1, "packets": 5698, "flows_scored": 8, "flows_unscored": 1, "dropped_packets": 308, "kernel_dropped_packets": 39473, "active_flows": 0, "evicted_flows": 0, "max_delay_s": 6.59, "alerts": {"isolation_forest": 3}, "alerts_per_hour": {"isolation_forest": 359.3}}
```

(The gate 2 run on `eda1ca1` reported 0 queue drops, 79,404 kernel drops and no warning: the duplicate copies overflowed the kernel buffer before reaching our queue. That result prompted the BPF fix.)

### Evidence — 30-minute baseline (commit eda1ca1)

```text
2026-10-29 14:58:58,194 INFO capturing on lo with models/isolation_forest.joblib
2026-10-29 20:18:41,186 INFO summary {"elapsed_s": 1800.0, "packets": 479305, "flows_scored": 1053, "flows_unscored": 10, "dropped_packets": 0, "kernel_dropped_packets": 1593, "active_flows": 0, "evicted_flows": 0, "max_delay_s": 17385.24, "alerts": {"isolation_forest": 180, "rule": 1}, "alerts_per_hour": {"isolation_forest": 360.0, "rule": 2.0}}
```

Suspend/resume during the run (from `journalctl`): suspend 15:14:40, resume 20:04:24 local. Alert causes: 180 × `TCP|127.0.0.1|34812|127.0.0.1|43749` (KDE audio-visualizer widget, `ss -tnp` + `/proc/<pid>/cmdline`); 1 × `PortScan` from `UDP|127.0.0.53|53|…` 9 s after resume.

### Evidence — runs with the loopback-duplicate bug (kept as evidence, not results)

```text
phase2_baseline.log: 2026-10-29 14:48:00,916 INFO summary {"elapsed_s": 1800.1, "packets": 170131, "flows_scored": 547, "flows_unscored": 4, "dropped_packets": 0, "active_flows": 0, "evicted_flows": 0, "max_delay_s": 6.0, "alerts": {"isolation_forest": 96}, "alerts_per_hour": {"isolation_forest": 192.0}}
phase2_gate1.log: 2026-10-29 14:17:22,870 INFO summary {"elapsed_s": 60.5, "packets": 2367, "flows_scored": 131, "flows_unscored": 0, "dropped_packets": 0, "active_flows": 0, "evicted_flows": 0, "max_delay_s": 5.88, "alerts": {}, "alerts_per_hour": {}}
phase2_gate2.log: 2026-10-29 14:17:57,017 INFO summary {"elapsed_s": 30.3, "packets": 822, "flows_scored": 7, "flows_unscored": 1, "dropped_packets": 17, "active_flows": 0, "evicted_flows": 0, "max_delay_s": 5.62, "alerts": {}, "alerts_per_hour": {}}
phase2_gate2b.log: 2026-10-29 14:54:15,709 INFO summary {"elapsed_s": 30.1, "packets": 11141, "flows_scored": 10, "flows_unscored": 1, "dropped_packets": 191, "kernel_dropped_packets": 79582, "active_flows": 0, "evicted_flows": 0, "max_delay_s": 5.69, "alerts": {"isolation_forest": 3}, "alerts_per_hour": {"isolation_forest": 359.2}}
```

### Evidence — clean clone (no root)

```text
$ git clone (HEAD 4356d62, no data/) && python3 -m venv .venv && .venv/bin/pip install -q -r requirements.txt
$ .venv/bin/pytest -q
42 passed in 7.63s
$ .venv/bin/python backend/detect_offline.py --pcap tests/fixtures/sample.pcap --out data/check.csv
71 flows scored, 2 alerts (1 isolation_forest, 1 rule) -> data/check.csv
600 packets read; {'evicted_flows': 0}
$ diff data/check.csv <workdir>/data/phase1_detections.csv && echo identical
identical
$ .venv/bin/python backend/pipeline.py --iface lo --duration 3   # no root
PermissionError: [Errno 1] Operation not permitted
capture thread stopped (capturing needs root or CAP_NET_RAW)
```

### Gate verdict

On `lo`, a curl loop produced scored flows in near real time (max 2.02 s); an overfilled queue logged a warning and capture stayed alive; 30 minutes of normal use were recorded and alerts/hour per detector are in PHASE2_RESULTS.md (Isolation Forest 360/h, all from one benign app; scan rule 2/h, one post-resume artifact).

### Blockers

None.

### Open (owned by later phases)

- The audio-visualizer false positives: D4 aggregation (Phase 3) collapses them; whether a longer active timeout reduces the train/live mismatch can be measured in Phase 5.
- Gate 1 and the baseline ran on `eda1ca1` (Python-side dedup); gate 2 on `4356d62` (kernel-side dedup). Both remove the same duplicates; only the kernel-drop count differs.
