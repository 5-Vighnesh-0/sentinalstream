# Product Requirements — SentinelStream

## Problem

A small organisation rarely has a SIEM or a dedicated security team. The person watching the network, often a junior SOC analyst or an IT admin, needs one place that shows suspicious traffic as it happens, without paid services, cloud accounts or a GPU.

## Users

| User | Need |
|---|---|
| Junior SOC analyst / IT admin (primary) | One browser tab with live alerts, filterable by severity and attack type; a way to check a captured PCAP after the fact. |
| Recruiter / technical interviewer (secondary) | Clear README, honest limitations, reproducible benchmark, passing tests and CI. |

## Goals

1. Detect suspicious flows from live traffic or a PCAP file and show them in a browser dashboard in near real time.
2. Combine a cross-flow port-scan rule and a supervised classifier (named attack types) with an unsupervised anomaly detector (unknown patterns); Phase 5 measures whether the combination helps.
3. Publish benchmark numbers that anyone can reproduce with one command.
4. Run fully offline on one laptop CPU once dependencies and data are downloaded. $0 budget.

## Non-goals

- Authentication, multi-user accounts, role-based access.
- Production-grade sensor deployment, high-throughput capture (>1 Gbps), packet payload inspection.
- Alert response or blocking (this is detection only, not IPS).
- Cloud hosting, paid APIs, telemetry, GPU training.
- Dark mode, theming, mobile layout beyond basic responsiveness.

## User stories

| ID | Story |
|---|---|
| US-1 | As an analyst, I open the dashboard and see new alerts appear without refreshing. |
| US-2 | As an analyst, I filter alerts by severity and by attack type. |
| US-3 | As an analyst, I see current packets per second and the mix of attack types. |
| US-4 | As an analyst, I upload a PCAP file and see the alerts it produced, separately from live alerts. |
| US-5 | As an evaluator, I follow docs/DEMO.md and see an alert from a simulated attack within 5 minutes. |
| US-6 | As an evaluator, I run one command and reproduce the benchmark table in the README. |

## Functional requirements

| ID | Requirement | Phase |
|---|---|---|
| FR-1 | Read a PCAP, group packets into bidirectional flows by 5-tuple, compute the shared feature subset ([DATA_MODEL.md](DATA_MODEL.md#shared-feature-subset)). | 1 |
| FR-2 | Score flows offline and write a CSV of flagged flows. | 1 |
| FR-3 | Capture live packets from an interface (`SENTINEL_IFACE`, default `lo`) without blocking the capture callback; drop the oldest packet on queue overflow and log it. | 2 |
| FR-4 | Expire flows on idle/active timeout and score them in a separate inference thread. | 2 |
| FR-5 | Persist alerts, the flows behind them and upload batches to SQLite with batched inserts. | 3 |
| FR-6 | Expose `GET /health`, `GET /alerts`, `POST /upload-pcap`, `WS /ws/alerts` ([API_SPEC.md](API_SPEC.md)). | 3 |
| FR-7 | Dashboard: alert feed (latest 200, severity colours, filters), traffic chart (packets/s, last 60 s), attack distribution, PCAP upload, Demo Mode banner, auto-reconnecting WebSocket. | 4 |
| FR-8 | Train a Random Forest on CICIDS2017 and benchmark it against Isolation Forest and a packets-per-second rule. | 5 |
| FR-9 | Rate-capped attack simulator restricted to loopback targets, with `--dry-run`. | 6 |
| FR-10 | `docker compose up --build` starts backend and frontend; CI runs lint, tests, frontend build and both Docker builds. | 7 |

## Non-functional requirements

These are targets checked by phase gates, not measured results.

| ID | Target | Checked in |
|---|---|---|
| NFR-1 | A new alert reaches the dashboard within 2 s of the flow being scored. | Phase 4 gate |
| NFR-2 | Traffic chart updates every 1 s. | Phase 4 gate |
| NFR-3 | UI stays responsive after receiving 1,000 alerts (feed renders at most 200). | Phase 4 gate |
| NFR-4 | Capture thread never blocks and survives queue overflow. | Phase 2 gate |
| NFR-5 | Works offline, CPU only. Frontend on port 3000, backend on port 8000. | All phases |
| NFR-6 | Every number in README.md is reproducible from `backend/evaluation/benchmark.py`. | Phase 5 gate |

## Success criteria

The project is done when every gate in [PHASES.md](PHASES.md) has passed and been accepted, i.e. the target state holds: `docker compose up --build` starts the stack, docs/DEMO.md produces a visible alert within 5 minutes, CI passes, and the README holds a real, reproducible benchmark table.
