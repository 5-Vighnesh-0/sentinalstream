"""Cross-flow port-scan rule.

Each probe of a scan is its own tiny flow, which per-flow models can't tell from benign short flows.
This rule looks across flows: one source touching many distinct (dst_ip, dst_port) pairs in a short window.
"""
from collections import OrderedDict, deque


class ScanDetector:
    def __init__(self, min_ports: int = 20, window_s: float = 10.0, max_sources: int = 10_000):
        self.min_ports = min_ports
        self.window_s = window_s
        self.max_sources = max_sources
        self._recent: OrderedDict[str, deque] = OrderedDict()  # src_ip -> (ts, (dst_ip, dst_port)), oldest source first
        self._quiet_until: dict[str, float] = {}  # src_ip -> end of its current alerted burst

    def observe(self, flow) -> bool:
        """Feed flows in first_ts order. True means: raise one PortScan alert for flow.src_ip now.

        One alert per burst: after an alert, every new target the source touches extends its quiet period, so a
        burst ends only after a full window with no new target, and a stale window can't re-fire on the next
        unrelated flow (Phase 7 gate: a DNS lookup 10.5 s after a scan raised a second PortScan).
        """
        if flow.protocol not in ("TCP", "UDP"):
            return False
        ts, src = float(flow.first_ts), flow.src_ip
        # maxlen bounds memory under a flood; the rule only needs to know whether min_ports targets exist.
        recent = self._recent.pop(src, None) or deque(maxlen=4 * self.min_ports)
        self._recent[src] = recent
        if len(self._recent) > self.max_sources:
            evicted, _ = self._recent.popitem(last=False)
            self._quiet_until.pop(evicted, None)
        target = (flow.dst_ip, flow.dst_port)
        while recent and recent[0][0] < ts - self.window_s:
            recent.popleft()
        is_new = all(t != target for _, t in recent)
        recent.append((ts, target))
        if ts < self._quiet_until.get(src, float("-inf")):
            if is_new:
                self._quiet_until[src] = ts + self.window_s  # still scanning: same burst
            return False
        if len({t for _, t in recent}) < self.min_ports:
            return False
        self._quiet_until[src] = ts + self.window_s
        return True
