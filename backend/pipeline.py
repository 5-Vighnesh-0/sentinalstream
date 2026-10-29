"""Live pipeline: capture -> flow table -> inference -> alerts (in memory; Phase 3 adds SQLite and WebSocket).

Alerts are printed to stdout as JSON lines, stats to stderr every 10 s and a summary at the end.
Capturing needs root or CAP_NET_RAW.

Usage:
  sudo .venv/bin/python backend/pipeline.py --iface lo --duration 60 [--queue-size 50000]
"""
import argparse
import json
import logging
import os
import queue
import sys
import threading
import time
from collections import Counter
from pathlib import Path

from scapy.arch.linux import L2ListenSocket
from scapy.sendrecv import sniff as scapy_sniff

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # allow `python backend/pipeline.py`

from backend.capture.sniffer import QUEUE_SIZE, CaptureThread  # noqa: E402
from backend.detection.detectors import SCORED_PROTOCOLS, Detectors  # noqa: E402
from backend.features.extractor import is_non_first_fragment, parse_packet  # noqa: E402
from backend.features.flow_table import TICK_S, FlowTable  # noqa: E402
from backend.ml import train_baseline  # noqa: E402

log = logging.getLogger("sentinelstream.pipeline")

FLOW_QUEUE_SIZE = 1_000  # batches, one per tick
STATS_EVERY_S = 10
# Until Phase 5 trains the Random Forest, the live default is the Isolation Forest.
DEFAULT_MODEL = os.environ.get("SENTINEL_MODEL_PATH", train_baseline.DEFAULT_OUT)


class Pipeline:
    def __init__(self, iface, model_path=DEFAULT_MODEL, queue_size=QUEUE_SIZE, flow_queue_size=FLOW_QUEUE_SIZE,
                 sniff=scapy_sniff, listen=L2ListenSocket, clock=time.time, on_alert=None):
        self.packets: queue.Queue = queue.Queue(maxsize=queue_size)
        self.flows: queue.Queue = queue.Queue(maxsize=flow_queue_size)
        self.capture = CaptureThread(iface, self.packets, sniff, listen)
        self.table = FlowTable()
        self.detectors = Detectors(model_path)
        self.clock = clock
        self.on_alert = on_alert or (lambda alert: None)
        self.alerts: list[dict] = []
        self.stats = Counter()
        self.max_delay_s = 0.0  # flow end -> scored, includes the idle/FIN wait by design
        self._stop = threading.Event()
        self._flow_thread = threading.Thread(target=self._flow_loop, name="flow-table", daemon=True)
        self._inference_thread = threading.Thread(target=self._inference_loop, name="inference", daemon=True)

    def start(self) -> None:
        self.capture.start()
        self._flow_thread.start()
        self._inference_thread.start()

    def stop(self) -> None:
        """Flush open flows, score them, and stop. The capture thread is a daemon and ends with the process."""
        self._stop.set()
        self._flow_thread.join()
        self.flows.put(None)  # tells inference that the last batch is in
        self._inference_thread.join()

    def _emit(self, flows) -> None:
        if not flows:
            return
        try:
            self.flows.put_nowait(flows)
        except queue.Full:
            self.stats["dropped_flows"] += len(flows)
            log.warning("flow queue full: dropped %d flows so far", self.stats["dropped_flows"])

    def _flow_loop(self) -> None:
        pending = []  # RST-closed and evicted flows wait for the next tick, so inference runs once per tick
        next_tick = self.clock() + TICK_S
        while not self._stop.is_set():
            try:
                pkt = self.packets.get(timeout=TICK_S)
            except queue.Empty:
                pkt = None
            if pkt is not None:
                self.stats["packets"] += 1
                try:
                    p = None if is_non_first_fragment(pkt) else parse_packet(pkt)
                except Exception:  # hostile input: one bad packet must not stop capture
                    self.stats["skipped_errors"] += 1
                    p = None
                if p is not None:
                    pending += self.table.add(p)
            if self.clock() >= next_tick:
                self._emit(pending + self.table.expire(self.clock()))
                pending = []
                next_tick = self.clock() + TICK_S
        self._emit(pending + self.table.flush())

    def _inference_loop(self) -> None:
        while (batch := self.flows.get()) is not None:
            now = self.clock()
            self.stats["flows_scored"] += sum(f.protocol in SCORED_PROTOCOLS for f in batch)
            self.stats["flows_unscored"] += sum(f.protocol not in SCORED_PROTOCOLS for f in batch)
            self.max_delay_s = max([self.max_delay_s] + [now - float(f.last_ts) for f in batch])
            for alert in self.detectors.score(batch):
                self.alerts.append(alert)
                self.on_alert(alert)


def summary(pipeline: Pipeline, elapsed_s: float) -> dict:
    by_source = Counter(a["source"] for a in pipeline.alerts)
    hours = elapsed_s / 3600
    return {
        "elapsed_s": round(elapsed_s, 1),
        **pipeline.stats,
        "dropped_packets": pipeline.capture.dropped,
        "kernel_dropped_packets": pipeline.capture.kernel_dropped(),
        "active_flows": len(pipeline.table),
        "evicted_flows": pipeline.table.evicted,
        "max_delay_s": round(pipeline.max_delay_s, 2),
        "alerts": dict(by_source),
        "alerts_per_hour": {s: round(n / hours, 1) for s, n in by_source.items()} if hours else {},
    }


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--iface", default=os.environ.get("SENTINEL_IFACE", "lo"))
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--duration", type=float, default=0, help="seconds to run; 0 = until Ctrl+C")
    parser.add_argument("--queue-size", type=int, default=QUEUE_SIZE, help="packet queue size (small values test overflow)")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)

    pipeline = Pipeline(args.iface, args.model, args.queue_size, on_alert=lambda a: print(json.dumps(a), flush=True))
    started = time.monotonic()
    pipeline.start()
    log.info("capturing on %s with %s", args.iface, args.model)
    try:
        while not args.duration or time.monotonic() - started < args.duration:
            remaining = args.duration - (time.monotonic() - started) if args.duration else STATS_EVERY_S
            time.sleep(max(min(STATS_EVERY_S, remaining), 0.1))
            if not pipeline.capture.is_alive():
                sys.exit("capture thread stopped (capturing needs root or CAP_NET_RAW)")
            log.info("stats %s", json.dumps(summary(pipeline, time.monotonic() - started)))
    except KeyboardInterrupt:
        pass
    finally:
        pipeline.stop()
        log.info("summary %s", json.dumps(summary(pipeline, time.monotonic() - started)))


if __name__ == "__main__":
    main()
