# Phase 2 Plan — Live capture

## Tasks

1. `backend/features/flow_table.py` — `FlowTable` driven by packet timestamps (D5): `add(packet) -> finished flows`, `expire(now) -> finished flows`, `flush()`. Export on 5 s idle, 10 s active, any RST, or both FINs plus a 1 s grace (so the closing ACK stays in the flow). Flow cap 100,000 with least-recently-active eviction and a counter.
2. `backend/features/extractor.py` — `flows_from_pcap` uses `FlowTable` with a 1 s tick on packet time, so offline, upload and live produce the same flows. Remove the "no timeout" shortcut.
3. `backend/detection/detectors.py` — `Detectors(model_path).score(flows) -> list[alert dict]`: Isolation Forest + scan rule, TCP/UDP only, batch predict. `detect_offline.py` uses it (no duplicate scoring code).
4. `backend/capture/sniffer.py` — `CaptureThread` (daemon): Scapy `sniff(store=False, filter="not port 8000 and not port 3000")`; callback only `put_nowait`; on `queue.Full`: `get_nowait()` once, `put_nowait()`, increment `dropped`, log a warning (first drop, then every 1,000th).
5. `backend/pipeline.py` — capture → `queue.Queue(maxsize=50000)` → flow-table thread (1 s tick on wall clock) → bounded flow queue (drop counter) → inference thread (batch per tick) → in-memory alert list. CLI: `--iface` (default `SENTINEL_IFACE` or `lo`), `--model`, `--duration`, `--queue-size`; prints alerts as JSON lines and a stats line every 10 s.
6. Tests (no root): flow expiry rules, cap eviction, offline equivalence on the sample PCAP, queue overflow keeps newest + warns + thread stays alive (fake sniff), pipeline end-to-end with a fake sniff feeding the sample PCAP.
7. Live gate on `lo` (needs `sudo`, asked first): curl loop → scored flows; overfilled queue (`--queue-size 50`) → warning, capture alive; 30 min of normal loopback use → alerts/hour per detector.
8. docs/PHASE2_RESULTS.md, PROGRESS.md.

## Files

| Action | Path |
|---|---|
| create | backend/features/flow_table.py, backend/detection/detectors.py, backend/capture/__init__.py, backend/capture/sniffer.py, backend/pipeline.py |
| modify | backend/features/extractor.py, backend/detect_offline.py |
| create | tests/test_flow_table.py, tests/test_sniffer.py, tests/test_pipeline.py |
| create | docs/PHASE2_RESULTS.md |
| update | PROGRESS.md |

## Acceptance gate (from docs/PHASES.md)

> On `lo`, a `curl` loop against `python -m http.server` on 127.0.0.1 produces scored flows in near real time (ping is not used: CICIDS2017 has no ICMP flows). A deliberately overfilled queue logs a warning and the capture thread stays alive. 30 minutes of normal loopback use are recorded and alerts per hour per detector are reported in PHASE2_RESULTS.md.

## Checks

```bash
.venv/bin/pytest -q
.venv/bin/python backend/detect_offline.py --pcap tests/fixtures/sample.pcap --out data/phase2_offline_check.csv   # same 2 alerts as Phase 1
# live (human runs, sudo):
python3 -m http.server 8081 --bind 127.0.0.1 &
while true; do curl -s -o /dev/null http://127.0.0.1:8081/; sleep 0.5; done &
sudo .venv/bin/python backend/pipeline.py --iface lo --duration 60
sudo .venv/bin/python backend/pipeline.py --iface lo --duration 60 --queue-size 50
sudo .venv/bin/python backend/pipeline.py --iface lo --duration 1800 > data/phase2_baseline.jsonl
```
