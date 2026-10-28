"""Group packets into bidirectional 5-tuple flows and compute the shared features."""
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
from scapy.packet import Padding
from scapy.utils import PcapReader

from backend.features.feature_set import FEATURES, packets_per_s

PROTOCOLS = {6: "TCP", 17: "UDP", 1: "ICMP", 58: "ICMP"}
# pcap (both byte orders, µs and ns) and pcapng. Anything else is rejected, notably gzip,
# which Scapy would decompress transparently and so bypass upload size limits.
CAPTURE_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
MAX_TS = 4_102_444_800  # 2100-01-01; larger values are corrupt and overflow datetime


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


def is_non_first_fragment(pkt) -> bool:
    """Non-first fragments carry no transport header; they are skipped and counted, not reassembled."""
    if IP in pkt and pkt[IP].frag > 0:
        return True
    return IPv6ExtHdrFragment in pkt and pkt[IPv6ExtHdrFragment].offset > 0


def parse_packet(pkt) -> PacketInfo | None:
    """Pull the fields we need from a Scapy packet; None for non-IP packets."""
    ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
    if ip is None:
        return None
    ts = float(pkt.time)
    if not 0 <= ts < MAX_TS:
        raise ValueError(f"timestamp out of range: {ts}")
    padding = len(pkt[Padding]) if Padding in pkt else 0  # Ethernet trailer, not payload
    sport = dport = 0
    flags = ""
    # Protocol comes from the transport layer found, not ip.nh, which is an extension header type on IPv6.
    if TCP in pkt:
        protocol, sport, dport, flags = "TCP", pkt[TCP].sport, pkt[TCP].dport, str(pkt[TCP].flags)
        payload_len = len(pkt[TCP].payload) - padding
    elif UDP in pkt:
        protocol, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
        payload_len = len(pkt[UDP].payload) - padding
    elif ICMP in pkt:
        protocol, payload_len = "ICMP", len(pkt[ICMP].payload) - padding
    else:
        protocol = PROTOCOLS.get(ip.proto if isinstance(ip, IP) else ip.nh, "OTHER")
        payload_len = max(len(ip.payload) - padding, 0)
    return PacketInfo(ts, ip.src, ip.dst, sport, dport, protocol, payload_len, flags)


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
        self.first_ts = min(self.first_ts, p.ts)
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


def check_capture_file(path) -> None:
    with open(path, "rb") as f:
        if f.read(4) not in CAPTURE_MAGICS:
            raise ValueError(f"{path}: not a pcap/pcapng file (gzip and other formats are rejected)")


def flows_from_pcap(path) -> tuple[list[Flow], Counter]:
    """Read a PCAP/PCAPNG and return (flows, stats): one Flow per bidirectional 5-tuple, in first-seen order.

    shortcut: no idle/active timeout or flow cap offline, so a reused 5-tuple merges into one flow;
    Phase 2's timestamp-driven flow table (D5) replaces this loop for offline, upload and live paths.
    """
    check_capture_file(path)
    flows: dict[tuple, Flow] = {}
    stats = Counter()
    with PcapReader(str(path)) as reader:
        packets = iter(reader)
        while True:
            try:
                pkt = next(packets)
            except StopIteration:
                break
            except Exception:  # truncated or corrupt file: keep what was read
                stats["truncated"] += 1
                break
            stats["packets"] += 1
            try:
                if is_non_first_fragment(pkt):
                    stats["skipped_fragments"] += 1
                    continue
                p = parse_packet(pkt)
            except Exception:  # hostile input: one bad packet must not abort the file
                stats["skipped_errors"] += 1
                continue
            if p is None:
                stats["skipped_non_ip"] += 1
                continue
            key = canonical_key(p)
            if key not in flows:
                flows[key] = Flow.start(p)
            flows[key].add(p)
    return list(flows.values()), stats
