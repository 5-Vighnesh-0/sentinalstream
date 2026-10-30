# Demo: see an alert in 5 minutes

You run the backend (live capture on loopback), the dashboard, and a port scan against your own machine. Everything stays on 127.0.0.1; nothing leaves the computer. No dataset download is needed: the trained models are in the repo.

## You need

- Linux (live capture on `lo` behaves as described only on Linux)
- Python 3.11+ and Node.js 20.19+ (or 22.12+)
- `sudo` (capturing packets needs root)
- Ports 8000 and 3000 free

## 1. Install (about 2 minutes)

From the repo root:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

```bash
npm --prefix frontend ci
```

## 2. Start the backend (terminal 1)

```bash
sudo .venv/bin/uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
```

Wait for `Application startup complete.` It captures on `lo` and serves the API on 127.0.0.1:8000 only.

## 3. Start the dashboard (terminal 2)

```bash
npm --prefix frontend run dev
```

Open <http://localhost:3000>. The header says **Connected · capturing on lo** and a banner says you are in demo mode.

## 4. Run a port scan (terminal 3)

```bash
.venv/bin/python simulator/simulate_attack.py portscan
```

It connects to ports 1–200 on 127.0.0.1, one every 10 ms (about 2 seconds), with no root needed.

## What you should see

Within about 2 seconds a **High · PortScan · Port-scan rule** alert appears at the top of the feed, from `127.0.0.1:<port>` to `127.0.0.1:20` (the 20th port probed is where the rule fires). The **Attack types** chart counts it.

You may also see **Low · WebAttack · Classifier** alerts for the same scan, merged into one row with a repeat count: the Random Forest mislabels single probe flows as WebAttack (see [LIMITATIONS.md](LIMITATIONS.md)). The port-scan rule is the detection to trust here.

## Optional

- **Floods:** `.venv/bin/python simulator/simulate_attack.py udp_flood` (no root) usually raises a **Low · anomaly** alert. `sudo .venv/bin/python simulator/simulate_attack.py syn_flood` raises **Low · WebAttack** alerts: on loopback the kernel answers each SYN with a reset, which splits the flood into tiny flows the classifier mislabels. Both are documented limitations, not bugs in the demo.
- **Analyse a capture file:** in the dashboard's "Analyse a capture file" panel, upload `tests/fixtures/sample.pcap`, then pick **Upload 1** in the View menu.
- **Dry run:** add `--dry-run` to any simulator command to see what it would send.

## The simulator's limits

- Targets must be an IPv4 literal in 127.0.0.0/8 (`127.0.0.1` by default); hostnames, IPv6 and other networks are refused, and the check repeats before every packet.
- At most 1,000 packets per run and at most 1,000 packets per second.

## Troubleshooting

| Symptom | Fix |
|---|---|
| Dashboard says "Reconnecting…" | The backend is not running, or not on port 8000. Check terminal 1. |
| Backend log shows `PermissionError` and no alerts arrive | Capture needs root: start the backend with `sudo`. |
| Header shows "Connected" but never "capturing on lo" | Wait 1–2 seconds for the first stats message; if it never appears, check terminal 1 for errors. |
| `Port 3000 is in use` / `address already in use` | Stop whatever uses port 3000 or 8000; both ports are fixed. |
| "No detection model is loaded" banner | The `models/` files are missing or changed; restore them with `git checkout models/`. |

Stop everything with Ctrl+C in each terminal.
