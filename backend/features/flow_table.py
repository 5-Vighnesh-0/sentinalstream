"""Active-flow table shared by offline detection, PCAP upload and live capture (D5).

Time always comes from the caller (packet timestamps offline, wall clock live), so the same
traffic is cut into the same flows whichever path it arrives by.
"""
from collections import Counter, OrderedDict

from scapy.utils import PcapReader

from backend.features.extractor import Flow, canonical_key, check_capture_file, is_non_first_fragment, parse_packet

IDLE_TIMEOUT_S = 5.0
ACTIVE_TIMEOUT_S = 10.0
FIN_GRACE_S = 1.0  # after both FINs, wait for the closing ACK so it doesn't start a 1-packet flow
TICK_S = 1.0
MAX_FLOWS = 100_000


class FlowTable:
    def __init__(self, max_flows: int = MAX_FLOWS):
        self.max_flows = max_flows
        self.evicted = 0
        self._flows: OrderedDict[tuple, Flow] = OrderedDict()  # least recently active first

    def __len__(self) -> int:
        return len(self._flows)

    def add(self, p) -> list[Flow]:
        """Add one packet; return flows it finished (RST, or a flow evicted at the cap)."""
        done = []
        key = canonical_key(p)
        flow = self._flows.pop(key, None)
        if flow is None:
            if len(self._flows) >= self.max_flows:
                done.append(self._flows.popitem(last=False)[1])
                self.evicted += 1
            flow = Flow.start(p)
        flow.add(p)
        if flow.rst:
            done.append(flow)
        else:
            self._flows[key] = flow
        return done

    def expire(self, now: float) -> list[Flow]:
        """Return flows idle for 5 s, active for 10 s, or closed by both FINs, as of `now`."""
        keys = [k for k, f in self._flows.items() if _finished(f, now)]
        return [self._flows.pop(k) for k in keys]

    def flush(self) -> list[Flow]:
        flows = list(self._flows.values())
        self._flows.clear()
        return flows


def _finished(f: Flow, now: float) -> bool:
    return (
        now - f.last_ts >= IDLE_TIMEOUT_S
        or now - f.first_ts >= ACTIVE_TIMEOUT_S
        or (f.fin_fwd and f.fin_bwd and now - f.last_ts >= FIN_GRACE_S)
    )


def flows_from_pcap(path) -> tuple[list[Flow], Counter]:
    """Read a PCAP/PCAPNG through a FlowTable ticking on packet time; return (flows, stats)."""
    check_capture_file(path)
    table, done, stats = FlowTable(), [], Counter()
    next_tick = None
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
            if next_tick is None:
                next_tick = p.ts + TICK_S
            elif p.ts >= next_tick:
                done += table.expire(p.ts)
                next_tick = p.ts + TICK_S
            done += table.add(p)
    done += table.flush()
    stats["evicted_flows"] = table.evicted
    return done, stats
