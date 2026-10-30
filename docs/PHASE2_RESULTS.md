# Phase 2 Results — Live capture

All numbers come from `backend/pipeline.py` runs on `lo` (Linux, `sudo`), logs in `data/phase2_*.log` (git-ignored; key lines are copied into PROGRESS.md). Detectors: the committed Isolation Forest plus the port-scan rule. The Random Forest arrives in Phase 5.

## Gate checks

| Check | Run | Result |
|---|---|---|
| Curl loop → scored flows in near real time | 60 s, `curl` every 0.5 s against `python -m http.server` on 127.0.0.1:8081 (commit `eda1ca1`) | 120 flows scored, max delay from a flow's last packet to scoring **2.02 s**; 0 queue / 0 kernel drops; no alert on any curl flow |
| Overfilled queue → warning, capture alive | 30 s, `--queue-size 50`, 20,000-packet UDP burst to 127.0.0.1:9 (commit `4356d62`) | `WARNING packet queue full: dropped 1 packets so far`; stats kept arriving for the full 30 s; 308 queue drops + **39,473 kernel drops**, both counted |
| 30 min of normal loopback use → alerts/hour per detector | 1,800 s of awake time (commit `eda1ca1`; laptop suspended 15:14:40–20:04:24 in the middle, the pipeline's monotonic clock excludes it) | see below |

## False-positive baseline (30 awake minutes, normal desktop use)

| | Value |
|---|---|
| Packets | 479,305 |
| TCP/UDP flows scored | 1,053 (10 ICMP/other flows recorded, not scored) |
| Isolation Forest alerts | **180 → 360 per hour** |
| Scan-rule alerts | **1 → 2 per hour** |
| Drops | 0 queue, 1,593 kernel (burst right after resume) |

Every alert has an identified cause:

- **All 180 Isolation Forest alerts** come from one connection: a KDE desktop widget (`luisbocanegra.audio.visualizer`) streams `cava` audio frames at 60 fps over a WebSocket on 127.0.0.1:34812 ↔ 43749. The flow table cuts this long-lived stream every 10 s (active timeout) and **every slice is flagged** — a continuous 60 fps local stream looks nothing like CICIDS2017's office traffic. The other ~870 flows raised **no** Isolation Forest alert.
- **The 1 scan-rule alert** fired 9 s after resume: the DNS stub resolver (127.0.0.53:53) answered many local programs at once while the kernel dropped 1,593 packets; with queries lost and replies captured, the resolver looked like one source contacting ≥ 20 ports. On loopback every program also shares the address 127.0.0.1, so the rule sees all of them as a single source.

Phase 3's alert aggregation (D4) turns the widget's slices into one alert with a growing count; the per-flow flag itself remains.

## Bugs found and fixed by the live gate

1. **Loopback duplicates.** Scapy's `L2ListenSocket` keeps `PACKET_OUTGOING` copies, and on `lo` the kernel hands packet sockets every packet twice, so live flows had double the packets and packets/s of the same traffic read from a PCAP. First fixed in Python (`eda1ca1`), then in the kernel BPF filter with `inbound` on `lo` (`4356d62`), so duplicates never fill the socket buffer. Same 20,000-packet burst: kernel drops **79,404 → 39,473**.
2. **Invisible kernel drops.** Our counter only saw queue drops (17 reported while ~19,000 packets were lost). The capture thread now reads `PACKET_STATISTICS` from its socket and reports `kernel_dropped_packets` separately (`b9a3abc`).

All gate runs before `eda1ca1` (with duplicates) are kept in PROGRESS.md as evidence of bug 1, not as results.

## What this shows

- Capture → flow table → inference works live on `lo` with flows scored ~2 s after they end (FIN-closed) and ≤ ~6 s for idle-expired flows (5 s idle timeout + 1 s tick).
- Under a burst Python capture cannot keep up; losses are now counted honestly instead of hidden, and the capture thread survives.
- The UDP burst itself raised **no** alert: CICIDS2017 has no UDP-flood class, and one fixed 5-tuple UDP flow of this shape is not unusual enough for the Isolation Forest (documented in LIMITATIONS.md).
- The false-positive rate on real desktop traffic is dominated by one unusual benign app. "Normal" on this laptop is not normal in CICIDS2017.

## Reproduce

Needs Linux, `sudo`, and the repo's `.venv`:

```bash
python3 -m http.server 8081 --bind 127.0.0.1 &
while true; do curl -s -o /dev/null http://127.0.0.1:8081/; sleep 0.5; done &
sudo .venv/bin/python backend/pipeline.py --iface lo --duration 60 > data/phase2_gate1_alerts.jsonl 2> data/phase2_gate1.log
sudo .venv/bin/python backend/pipeline.py --iface lo --duration 30 --queue-size 50 > data/phase2_gate2_alerts.jsonl 2> data/phase2_gate2.log &
sleep 5; .venv/bin/python -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); [s.sendto(b'x', ('127.0.0.1', 9)) for _ in range(20000)]"
sudo .venv/bin/python backend/pipeline.py --iface lo --duration 1800 > data/phase2_baseline_alerts.jsonl 2> data/phase2_baseline.log
```

The baseline depends on what runs on the machine, so its numbers will differ elsewhere; the method is what's reproducible.
