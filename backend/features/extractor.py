"""Group packets into bidirectional 5-tuple flows and compute the shared features."""
from dataclasses import dataclass
from datetime import datetime, timezone

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

from backend.features.feature_set import FEATURES, packets_per_s

PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMP"}


@dataclass
class PacketInfo:
    ts: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload_len: int
    flags: str  # TCP flag letters, e.g. "SA"; empty for non-TCP. Not a model feature; Phase 2 uses FIN/RST to end flows.


def parse_packet(pkt) -> PacketInfo | None:
    """Pull the fields we need from a Scapy packet; None for non-IP packets."""
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None:
        return None
    proto_num = ip.proto if isinstance(ip, IP) else ip.nh
    sport = dport = 0
    flags = ""
    if TCP in pkt:
        sport, dport, flags = pkt[TCP].sport, pkt[TCP].dport, str(pkt[TCP].flags)
        payload_len = len(pkt[TCP].payload)
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
        payload_len = len(pkt[UDP].payload)
    elif ICMP in pkt:
        payload_len = len(pkt[ICMP].payload)
    else:
        payload_len = len(ip.payload)
    return PacketInfo(
        float(pkt.time), ip.src, ip.dst, sport, dport, PROTOCOLS.get(proto_num, "OTHER"), payload_len, flags
    )


def canonical_key(p: PacketInfo) -> tuple:
    """Same key for both directions of a conversation."""
    a, b = (p.src_ip, p.src_port), (p.dst_ip, p.dst_port)
    return (p.protocol, *min(a, b), *max(a, b))


@dataclass
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    first_ts: float
    last_ts: float
    fwd_packets: int = 0
    bwd_packets: int = 0
    total_bytes: int = 0

    @classmethod
    def start(cls, p: PacketInfo) -> "Flow":
        # The first packet's sender defines the forward direction.
        return cls(p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.protocol, p.ts, p.ts)

    def add(self, p: PacketInfo) -> None:
        self.last_ts = max(self.last_ts, p.ts)
        if (p.src_ip, p.src_port) == (self.src_ip, self.src_port):
            self.fwd_packets += 1
        else:
            self.bwd_packets += 1
        self.total_bytes += p.payload_len

    @property
    def flow_key(self) -> str:
        return f"{self.protocol}|{self.src_ip}|{self.src_port}|{self.dst_ip}|{self.dst_port}"

    @property
    def end_time(self) -> str:
        dt = datetime.fromtimestamp(self.last_ts, tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def features(self) -> dict:
        duration = self.last_ts - self.first_ts
        values = {
            "flow_duration_s": duration,
            "fwd_packets": self.fwd_packets,
            "bwd_packets": self.bwd_packets,
            "total_bytes": self.total_bytes,
            "packets_per_s": float(packets_per_s(self.fwd_packets + self.bwd_packets, duration)),
        }
        return {name: values[name] for name in FEATURES}


def flows_from_pcap(path) -> list[Flow]:
    """Read a PCAP/PCAPNG and return one Flow per bidirectional 5-tuple, in first-seen order.

    shortcut: no idle/active timeout offline, so a reused 5-tuple merges into one flow; Phase 2's flow table adds timeouts.
    """
    flows: dict[tuple, Flow] = {}
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            p = parse_packet(pkt)
            if p is None:
                continue
            key = canonical_key(p)
            if key not in flows:
                flows[key] = Flow.start(p)
            flows[key].add(p)
    return list(flows.values())
