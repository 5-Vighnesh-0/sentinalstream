"""Record each simulator mode on lo into tests/fixtures/sim_<mode>.pcap (needs root, run once).

Each capture is filtered to that mode's own ports, so other loopback traffic stays out of the fixture.

Usage: sudo .venv/bin/python tests/fixtures/record_simulator_pcaps.py
"""
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from scapy.sendrecv import AsyncSniffer
from scapy.utils import wrpcap

from backend.capture.sniffer import listen_socket

FILTERS = {
    "portscan": "tcp and host 127.0.0.1 and (dst portrange 1-200 or src portrange 1-200)",
    "udp_flood": "(udp and port 40000) or icmp",
    "syn_flood": "tcp and port 40001",
}

for mode, bpf in FILTERS.items():
    sniffer = AsyncSniffer(opened_socket=listen_socket("lo", bpf), store=True)
    sniffer.start()
    time.sleep(1)
    subprocess.run([sys.executable, str(REPO / "simulator" / "simulate_attack.py"), mode], check=True)
    time.sleep(1)
    packets = sniffer.stop()
    out = Path(__file__).with_name(f"sim_{mode}.pcap")
    wrpcap(str(out), packets)
    print(f"{mode}: {len(packets)} packets -> {out}")
