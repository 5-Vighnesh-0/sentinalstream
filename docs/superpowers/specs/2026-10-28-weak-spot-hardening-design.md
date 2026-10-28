# Weak-spot hardening — design

Date: 2026-10-28 · Status: **draft for human review** · Method: superpowers brainstorming, informed by three read-only reviews (agent-skills code-reviewer, security-auditor, doubt-driven-development).

## Goal

For the project as a whole and for each case (component or use case), name every known weak point and pair it with a complement: a fix plus how it is verified, or an honest limitation. Nothing found is left silent.

"No gaps of any sort" is not achievable for an intrusion detector. The bar here is: **every known weak point is either fixed with a test/gate, or documented in LIMITATIONS.md with its consequence.**

## Decisions

| # | Decision | Status |
|---|---|---|
| D1 | Hardening pass now: Phase 1 code fixes land before Phase 2; later-phase fixes are written into docs and that phase's gate. | **Approved** |
| D2 | Port scans: cross-flow scan rule + Phase 5 Random Forest. The rule may label `PortScan`; alerts carry `source` (`rule` / `random_forest` / `isolation_forest`). Relaxes "attack names only from the classifier". | **Approved** |
| D3 | Models ship in git, compressed (`joblib` compress=3), sha256 in the sidecar, verified before load. Missing model → `/health` and the banner say so. | Recommended, awaiting approval (alternative: GitHub Release assets + fetch script) |
| D4 | Alert aggregation: a new detection with the same (src_ip, dst_ip, attack_type) as an alert whose `last_seen` is < 30 s old updates that alert instead of creating one with `count`, `first_seen`, `last_seen`. Schema change lands before the Phase 3 freeze. | Recommended, awaiting approval |
| D5 | One flow table driven by packet timestamps, shared by offline CLI, PCAP upload and live capture (live tick only advances "now"). | Recommended, awaiting approval |
| D6 | Severity: Isolation-Forest-only alerts are `low` (above p99 of benign) or `medium` (above p99.9), never `high` — an unnamed anomaly is a triage hint. `high` is reserved for named detections (rule or Random Forest) with confidence ≥ 0.90. | Recommended, awaiting approval |

## Overall project

| Weak point | Complement | Lands | Verified by |
|---|---|---|---|
| Fresh clone has no model (dataset behind a registration form, `models/` ignored) → CI, Docker, recruiters get no detector | D3 | Phase 1 (IF), Phase 5 (RF) | CI runs detection on fixtures from a clean checkout |
| Docker build silently bakes in local `data/` | `.dockerignore` excluding `data/`, `.venv/`, `node_modules/` | Phase 7 | CI Docker build from clean checkout |
| Training features ≠ live features (CICFlowMeter 120 s flows, first-FIN end; ours 5 s idle / 10 s active) | D5 + LIMITATIONS entry; never claim parity | Phase 2 + docs | Doc review |
| Claims without evidence (PRD goal 2, README "combines supervised + unsupervised") | Reword until Phase 5 numbers exist | Now (docs) | grep of README/PRD |
| CICIDS2017 citation required by its terms | Citation in README.md and EVALUATION.md | Now (docs) | Doc review |

## Case 1 — Flow feature extraction (`extractor.py`, reused live)

| Weak point | Complement | Lands | Verified by |
|---|---|---|---|
| Loopback ping counts as one-way (src==dst, ICMP ports 0) — every ping looks like a flood on `lo` *(verified)* | ICMP: echo id as port, type (8/0, 128/129) decides direction | Phase 1 | Unit test: request+reply → fwd 1, bwd 1 |
| Ethernet trailer padding counted as payload (+6 B per small frame) *(verified)* | Payload = IP length − IP header − transport header | Phase 1 | Unit test on a 60-byte padded ACK → 0 |
| IPv6 extension headers → protocol `OTHER`; ICMPv6 payload includes header | Protocol from the matched transport layer; ICMPv6 branch | Phase 1 | Unit tests (HBH+TCP, ICMPv6) |
| IP fragments split into junk flows | Skip non-first fragments and count them (`fragments_skipped`) — no reassembly (YAGNI) | Phase 1 | Unit test |
| Out-of-order packets shorten duration | `first_ts = min(...)` | Phase 1 | Unit test |
| Float timestamps lose sub-µs precision at epoch 1.7e9 | Keep Scapy's `EDecimal` time, convert to float only for the duration | Phase 1 | Unit test with 1e-7 s delta |
| One malformed packet / huge timestamp aborts the whole PCAP | Per-packet try/except, count `packets_skipped` | Phase 1 | Unit test with a corrupt packet |
| Unbounded flow dict (random-source-port flood) | `slots=True`; `MAX_FLOWS` cap with oldest-first eviction + counter | Phase 1 | Unit test at cap |
| No tests for UDP/ICMP/IPv6/non-IP paths | Hand-built packet cases | Phase 1 | pytest |

## Case 2 — Isolation Forest (unsupervised anomaly)

| Weak point | Complement | Lands | Verified by |
|---|---|---|---|
| Severity always `high` | D6; store fine tail quantiles (p99…p99.99) | Phase 1 | Unit test of severity mapping |
| Rounding mismatch: flagged flow can get confidence 0.989 | Threshold taken from the stored quantile array, no separate rounding | Phase 1 | Unit test: every flagged flow has confidence ≥ 0.99 |
| Misses scans and random-port floods (each is a 1–2 packet flow) | D2 scan rule; random-port floods documented as a limitation | Phase 1 rule / docs | Fixture test |
| Trained on one day of one lab network | LIMITATIONS; Phase 2 measures alerts/hour on real loopback use | Phase 2 | PHASE2_RESULTS |
| No real false-positive number | Phase 1: report FPR on held-out benign rows from all 5 days; Phase 2: alerts/hour on 30 min of normal loopback use | Phase 1 / 2 | Script output in PROGRESS |

## Case 3 — Port-scan rule (new, D2)

| Weak point | Complement | Lands | Verified by |
|---|---|---|---|
| Not benchmarkable on CICIDS MachineLearningCSV (no IPs/timestamps) | Stated in EVALUATION.md; tested on fixtures only | Phase 1 | Doc |
| Threshold choice (N distinct dst ports per src in W seconds) is a guess | Start N=20, W=10 s; record in LIMITATIONS; Phase 2 alerts/hour shows FP cost | Phase 1 / 2 | Fixture: 50-port scan → 1 alert; 20 benign sessions → 0 |
| Slow scans (< N ports per W) evade it | LIMITATIONS | Docs | — |
| Memory per source under spoofed sources | Bounded per-source state (cap + eviction) | Phase 1 | Unit test |

## Case 4 — Random Forest + benchmark (Phase 5)

| Weak point | Complement | Lands | Verified by |
|---|---|---|---|
| Rare classes (Heartbleed, Infiltration, SQLi) get huge balanced weights → false named alerts | Merge/drop classes with < 100 rows; report support per class | Phase 5 | Per-class table with support |
| Unfair comparison (IF/rule fixed at ~1% FPR, RF argmax) | Add PR-AUC and recall at 1% FPR for all detectors | Phase 5 | Benchmark table |
| Random split leaks sessions; RF has seen every attack family | Extra run holding out one attack family | Phase 5 | Benchmark table |
| Benchmarked model ≠ deployed model | Benchmark loads the exact committed files | Phase 5 | sha256 printed in benchmark output |
| No SYN/UDP flood class in CICIDS (its DoS is HTTP-layer) | LIMITATIONS; simulator floods rely on IF (see Case 8) | Docs | — |

## Case 5 — Live capture pipeline (Phase 2)

| Weak point | Complement | Lands | Verified by |
|---|---|---|---|
| Ping gate is meaningless (no ICMP in CICIDS) | Gate on a `curl` loop against `python -m http.server` on 127.0.0.1 | Phase 2 gate | PHASE2_RESULTS |
| Dashboard's own traffic gets scored (feedback loop) | BPF filter `not port 8000 and not port 3000` | Phase 2 | Test of filter string; gate |
| Scapy `sniff()` stores every packet | `store=False` | Phase 2 | Code review + memory note in results |
| Flow queue / writer queue / asyncio queue unbounded | All bounded, drop counters exposed in `stats` | Phase 2/3 | Overflow test |
| Alert storm from one scan/flood | D4 | Phase 3 | Test: 1,000 scan probes → 1 aggregated alert |
| Per-flow predict calls bottleneck bursts | Batch-predict per tick | Phase 2 | Test |

## Case 6 — API, WebSocket, persistence (Phase 3)

| Weak point | Complement | Lands | Verified by |
|---|---|---|---|
| Any website can read alerts over WS (CORS doesn't cover WS) or via DNS rebinding | `TrustedHostMiddleware(["localhost","127.0.0.1"])`; WS closes 1008 unless Origin ∈ {`http://localhost:3000`, `http://127.0.0.1:3000`} | Phase 3 | test_api: bad Host → 400, bad Origin → 1008 |
| CSRF upload (multipart is a "simple" request) | Require `X-Sentinel-Upload: 1` header + Origin allowlist → else 403 | Phase 3 | test_api |
| Gzip bypasses 50 MB cap (Scapy auto-decompresses) *(verified)* | Magic-byte check (pcap/pcapng only) before parsing | Phase 1 (extractor helper) + Phase 3 route | Unit test with gzip file |
| Hostile PCAP can exhaust memory/CPU or crash the API process | Parse uploads in a subprocess with `RLIMIT_AS`, `RLIMIT_CPU`, timeout, packet/flow caps | Phase 3 | Test: oversized/garbage file → batch `failed`, API alive |
| Upload backlog unbounded; temp files leak; batches stuck `pending` after crash | Queue 1 running + 2 waiting else 429; dedicated temp dir wiped at startup; stale batches → `failed` at boot | Phase 3 | test_api |
| DB grows forever | Retention: max rows (default 100,000) oldest-first delete | Phase 3 | Test |
| Model file not tied to sidecar | sha256 check + path must be under `models/` | Phase 1 (`load_model`) | Unit test with tampered file |
| Filenames with newlines/ANSI forge logs | Sanitise to `[A-Za-z0-9._ -]`, log with `%r` | Phase 3 | Test |
| Crash loses ≤ 2 s of already-broadcast alerts | LIMITATIONS | Docs | — |

## Case 7 — Dashboard (Phase 4)

| Weak point | Complement | Lands | Verified by |
|---|---|---|---|
| Unescaped data rendering | Never `dangerouslySetInnerHTML`; React escapes by default | Phase 4 | grep in CI |
| Uploaded PCAP alerts carry 2017/2023 timestamps and sort below live ones | Upload alerts shown under their batch filter, timestamps labelled "capture time" | Phase 4 | Vitest |
| No-model state invisible | Banner shows "no model loaded" from `/health` | Phase 4 | Vitest |

## Case 8 — Simulator and demo (Phase 6)

| Weak point | Complement | Lands | Verified by |
|---|---|---|---|
| Loopback-only check bypassable (hostnames, `::1`, `::ffff:127.0.0.1` is_loopback=True *(verified)*) | Accept only an `IPv4Address` literal in 127.0.0.0/8; no DNS; no IPv6; re-check `pkt[IP].dst` before each send; L3 send on `lo` only | Phase 6 | Unit tests per bypass |
| Floods invisible to detectors if source ports vary | Floods use one fixed 5-tuple | Phase 6 | Fixture test |
| 5-minute gate untestable in CI (needs root) | Record each mode to a pcap once, commit as fixture; CI asserts ≥ 1 alert per mode | Phase 6 | CI |
| Scapy sending to 127.0.0.1 may need `L3RawSocket` | Verify on the pinned Scapy; use plain sockets for portscan/udp_flood | Phase 6 | Manual gate run |

## Case 9 — Docker and deployment (Phase 7)

| Weak point | Complement | Lands | Verified by |
|---|---|---|---|
| Over-privileged container (root + NET_ADMIN + host net + untrusted parsing) | `cap_drop: [ALL]`, `cap_add: [NET_RAW]`, `no-new-privileges`, `read_only: true`, `models/` mounted read-only. Capture runs as root inside the container (non-root `USER` makes `cap_add` ineffective) | Phase 7 | `docker inspect` in gate evidence |
| Accidental LAN exposure | Uvicorn `--host 127.0.0.1`; frontend `127.0.0.1:3000:3000`; never wildcard CORS | Phase 7 | Gate evidence (`ss -ltnp`) |
| Host networking works as documented only on Linux | LIMITATIONS (already there) | Docs | — |

## Case 10 — CI and supply chain (Phase 7)

| Weak point | Complement | Lands | Verified by |
|---|---|---|---|
| Mutable action tags / base images | Pin by SHA / digest | Phase 7 | Workflow review |
| Unpinned transitive deps | Compiled lockfile with hashes, `pip install --require-hashes`; `npm ci --ignore-scripts` | Phase 7 | CI |
| Over-broad token | `permissions: contents: read` | Phase 7 | Workflow review |
| CI can't download CICIDS | CI uses committed models (D3) and fixtures only | Phase 7 | CI green from clean checkout |

## Case 11 — Docs accuracy

| Weak point | Complement | Lands |
|---|---|---|
| ARCHITECTURE omits `log1p` | Add | Now |
| "FIN/RST from both sides" wrong for RST (one-sided) | "both FINs, or any RST" | Now |
| Detection CSV has no ports / flow_key | Add `flow_key` column | Phase 1 |
| Tests depend on working directory | Paths from `Path(__file__)` | Phase 1 |

## Scope of the hardening pass (what changes now)

Phase 1 code: Case 1 all rows, Case 2 rows 1–2 and the held-out FPR report, Case 3 (scan rule, offline), `load_model` sha256 check, magic-byte check helper, `flow_key` in CSV, test path fixes, D3/D6 if approved.
Docs: decisions D1–D6, every later-phase row above added to its phase's deliverables/gate in PHASES.md, LIMITATIONS additions, citation, ARCHITECTURE/DATA_MODEL/API_SPEC updates (schema: `source`, D4 fields).
Not now: anything that needs FastAPI, React, Docker or the simulator to exist.

## Out of scope

Fragment reassembly, payload inspection, authentication, TLS, cross-flow features inside the ML model, NSL-KDD.
