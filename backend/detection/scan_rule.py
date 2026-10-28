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
        self._last_alert: dict[str, float] = {}

    def observe(self, flow) -> bool:
        """Feed flows in first_ts order. True means: raise one PortScan alert for flow.src_ip now."""
        if flow.protocol not in ("TCP", "UDP"):
            return False
        ts, src = float(flow.first_ts), flow.src_ip
        # maxlen bounds memory under a flood; the rule only needs to know whether min_ports targets exist.
        recent = self._recent.pop(src, None) or deque(maxlen=4 * self.min_ports)
        self._recent[src] = recent
        if len(self._recent) > self.max_sources:
            evicted, _ = self._recent.popitem(last=False)
            self._last_alert.pop(evicted, None)
        recent.append((ts, (flow.dst_ip, flow.dst_port)))
        while recent[0][0] < ts - self.window_s:
            recent.popleft()
        if len({target for _, target in recent}) < self.min_ports:
            return False
        last = self._last_alert.get(src)
        if last is not None and ts - last < self.window_s:
            return False
        self._last_alert[src] = ts
        return True
