"""Loopback-only attack simulator for the SentinelStream demo.

Modes:
  portscan   TCP connect to ports 1..N on the target (no root needed)
  udp_flood  UDP datagrams on one fixed 5-tuple (no root needed)
  syn_flood  raw TCP SYNs on one fixed 5-tuple (needs root: Scapy builds the packets)

The target must be an IPv4 address literal inside 127.0.0.0/8; it is checked again before every packet.
Packet count and rate are hard-capped.

Usage:
  python simulator/simulate_attack.py portscan [--target 127.0.0.1] [--count N] [--interval SECONDS] [--dry-run]
"""
import argparse
import ipaddress
import os
import socket
import sys
import time

MAX_COUNT = 1000
MIN_INTERVAL_S = 0.001  # at most 1,000 packets per second
DEFAULTS = {"portscan": (200, 0.01), "udp_flood": (1000, 0.001), "syn_flood": (1000, 0.001)}
LOOPBACK = ipaddress.IPv4Network("127.0.0.0/8")
UDP_SPORT, UDP_DPORT = 40000, 9  # fixed 5-tuple: one flow the detectors can see as a whole
SYN_SPORT, SYN_DPORT = 40001, 80


def loopback_target(text: str) -> str:
    """Accept only an IPv4 literal in 127.0.0.0/8: no hostnames (no DNS), no IPv6 or ::ffff: forms, no octal."""
    try:
        addr = ipaddress.IPv4Address(text)
    except ipaddress.AddressValueError:
        raise ValueError(f"target must be an IPv4 address literal in 127.0.0.0/8, got {text!r}") from None
    if addr not in LOOPBACK:
        raise ValueError(f"target must be in 127.0.0.0/8 (loopback only), got {text!r}")
    return str(addr)


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=DEFAULTS)
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--count", type=int, help=f"packets/probes to send (1..{MAX_COUNT})")
    parser.add_argument("--interval", type=float, help=f"seconds between packets (>= {MIN_INTERVAL_S})")
    parser.add_argument("--dry-run", action="store_true", help="print what would be sent, send nothing")
    args = parser.parse_args(argv)
    default_count, default_interval = DEFAULTS[args.mode]
    args.count = default_count if args.count is None else args.count
    args.interval = default_interval if args.interval is None else args.interval
    if not 1 <= args.count <= MAX_COUNT:
        parser.error(f"--count must be between 1 and {MAX_COUNT}")
    if args.interval < MIN_INTERVAL_S:
        parser.error(f"--interval must be at least {MIN_INTERVAL_S} s")
    try:
        args.target = loopback_target(args.target)
    except ValueError as e:
        parser.error(str(e))
    return args


def portscan(target: str, count: int, interval: float) -> None:
    for port in range(1, count + 1):
        loopback_target(target)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        s.connect_ex((target, port))
        s.close()
        time.sleep(interval)


def udp_flood(target: str, count: int, interval: float) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", UDP_SPORT))
    try:
        for _ in range(count):
            loopback_target(target)
            s.sendto(b"x" * 64, (target, UDP_DPORT))
            time.sleep(interval)
    finally:
        s.close()


def syn_flood(target: str, count: int, interval: float) -> None:
    from scapy.config import conf
    from scapy.layers.inet import IP, TCP
    from scapy.sendrecv import send
    from scapy.supersocket import L3RawSocket

    conf.L3socket = L3RawSocket  # Scapy's default L3 socket cannot send to 127.0.0.0/8 on Linux
    for seq in range(count):
        pkt = IP(dst=target) / TCP(sport=SYN_SPORT, dport=SYN_DPORT, flags="S", seq=seq)
        loopback_target(pkt[IP].dst)  # checked on the packet actually sent
        send(pkt, verbose=False)
        time.sleep(interval)


MODES = {"portscan": portscan, "udp_flood": udp_flood, "syn_flood": syn_flood}


def main(argv=None) -> None:
    args = parse_args(argv)
    seconds = args.count * args.interval
    if args.dry_run:
        print(f"would send {args.count} {args.mode} packets to {args.target}, one every {args.interval} s (~{seconds:.1f} s)")
        return
    if args.mode == "syn_flood" and os.geteuid() != 0:
        sys.exit("syn_flood needs root (raw packets): run it with sudo. portscan and udp_flood do not.")
    print(f"sending {args.count} {args.mode} packets to {args.target}, one every {args.interval} s (~{seconds:.1f} s)")
    MODES[args.mode](args.target, args.count, args.interval)
    print("done")


if __name__ == "__main__":
    main()
