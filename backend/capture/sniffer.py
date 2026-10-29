"""Live packet capture on one interface, in a daemon thread that never blocks and never runs ML."""
import logging
import queue
import threading

from scapy.sendrecv import sniff as scapy_sniff

log = logging.getLogger(__name__)

BPF_FILTER = "not port 8000 and not port 3000"  # don't score the dashboard's own API and UI traffic
QUEUE_SIZE = 50_000


class CaptureThread(threading.Thread):
    def __init__(self, iface: str, packets: queue.Queue, sniff=scapy_sniff):
        super().__init__(name="capture", daemon=True)
        self.iface = iface
        self.packets = packets
        self.dropped = 0
        self._sniff = sniff

    def run(self) -> None:
        # store=False: Scapy would otherwise keep every packet in memory for the life of the capture.
        self._sniff(iface=self.iface, filter=BPF_FILTER, prn=self.enqueue, store=False)

    def enqueue(self, pkt) -> None:
        """Sniff callback. queue.Queue has no drop-oldest, so on Full discard one old packet and retry once."""
        try:
            self.packets.put_nowait(pkt)
            return
        except queue.Full:
            pass
        try:
            self.packets.get_nowait()
        except queue.Empty:
            pass
        try:
            self.packets.put_nowait(pkt)
        except queue.Full:
            pass  # refilled in between; either way exactly one packet is lost
        self.dropped += 1
        if self.dropped == 1 or self.dropped % 1000 == 0:
            log.warning("packet queue full: dropped %d packets so far", self.dropped)
