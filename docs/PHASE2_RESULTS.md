# Phase 2 Results — Live capture

> **Correction (2026-10-29, after Phase 2 was accepted).** The first version of this file reported numbers measured while every loopback packet was read two or three times: Scapy's `sniff`, given both our socket and `iface`, silently opened a second, unfiltered socket. Found during the Phase 3 gate, fixed in `9ca23c5`, and all three checks re-run below. The original runs stay in PROGRESS.md as evidence of the bug.

All numbers come from `backend/pipeline.py` runs on `lo` (Linux, `sudo`) at commit `9ca23c5`, logs in `data/phase2_*.log` (git-ignored; key lines are in PROGRESS.md). Detectors: the committed Isolation Forest plus the port-scan rule. The Random Forest arrives in Phase 5.

## Gate checks

| Check | Run | Result |
|---|---|---|
| Curl loop → scored flows in near real time | 60 s, `curl` every 0.5 s against `python -m http.server` on 127.0.0.1:8081 | 124 flows scored, max delay from a flow's last packet to scoring **5.34 s** (5 s idle timeout + 1 s tick); 0 queue / 0 kernel drops; no alert on any curl flow |
| Overfilled queue → warning, capture alive | 30 s, `--queue-size 50`, 20,000-packet UDP burst to 127.0.0.1:9 | Capture stayed alive for the full 30 s. 3,399 packets read, **39,213 dropped in the kernel and counted**. The queue itself did not fill: the capture thread (Scapy dissection) is the bottleneck, so excess is dropped before it reaches the queue. The queue-full warning path is proven by `tests/test_sniffer.py` (1,000+ drops, thread alive) and by the earlier live run on `4356d62` (warning logged, capture alive). |
| 30 min of normal loopback use → alerts/hour per detector | 1,800 s, laptop awake throughout | see below |

## False-positive baseline (30 minutes, normal desktop use)

| | Value |
|---|---|
| Packets | 157,893 |
| TCP/UDP flows scored | 428 (5 ICMP/other flows recorded, not scored) |
| Isolation Forest alerts | **179 → 358 per hour** |
| Scan-rule alerts | **0** |
| Drops | 0 queue, 0 kernel |

**All 179 Isolation Forest alerts come from one connection**: a KDE desktop widget (`luisbocanegra.audio.visualizer`) streams `cava` audio frames at 60 fps over a WebSocket on 127.0.0.1:34812 ↔ 43749. The flow table cuts this long-lived stream every 10 s (active timeout) and **every slice is flagged**: a continuous 60 fps local stream looks nothing like CICIDS2017's office traffic. The other ~250 flows raised **no** alert.

Phase 3's alert aggregation (D4) turns the widget's slices into one alert with a growing count; the per-flow flag itself remains.

## Bugs found and fixed by the live gates

1. **Every packet read 2–3 times on `lo`.** The kernel hands packet sockets every loopback packet twice (outgoing and incoming copy). Our socket now keeps only the incoming copy with BPF `inbound` (`4356d62`), and `sniff` is no longer given `iface`, which had made Scapy open its own unfiltered socket alongside ours (`9ca23c5`). Verified live: a 30-port loopback scan now gives exactly 30 flows (`fwd=1 bwd=1` each, scanner → port); before the fix it gave 90, a third of them reversed.
2. **Invisible kernel drops.** Our counter only saw queue drops. The capture thread now reads `PACKET_STATISTICS` from its socket and reports `kernel_dropped_packets` (`b9a3abc`).

## What this shows

- Capture → flow table → inference works live on `lo`: flows are scored within ~1 s of a RST and ≤ ~6 s for idle-expired flows.
- Under a burst Python capture cannot keep up; losses are counted honestly and the capture thread survives.
- The UDP burst raised **no** alert: CICIDS2017 has no UDP-flood class, and one fixed 5-tuple UDP flow of this shape is not unusual enough for the Isolation Forest (documented in LIMITATIONS.md).
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
