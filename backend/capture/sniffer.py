"""Live packet capture on one interface, in a daemon thread that never blocks and never runs ML."""
import logging
import queue
import struct
import threading

from scapy.arch.linux import L2ListenSocket
from scapy.sendrecv import sniff as scapy_sniff

log = logging.getLogger(__name__)

BPF_FILTER = "not port 8000 and not port 3000"  # don't score the dashboard's own API and UI traffic
QUEUE_SIZE = 50_000
SOL_PACKET, PACKET_STATISTICS = 263, 6  # linux/socket.h, linux/if_packet.h; not exported by Python's socket module


class CaptureThread(threading.Thread):
    def __init__(self, iface: str, packets: queue.Queue, sniff=scapy_sniff, listen=L2ListenSocket):
        super().__init__(name="capture", daemon=True)
        self.iface = iface
        self.packets = packets
        self.dropped = 0  # our queue's drops; the kernel's are in kernel_dropped()
        self._sniff = sniff
        self._listen = listen
        self._sock = None
        self._kernel_dropped = 0

    def run(self) -> None:
        # Open the socket ourselves so kernel_dropped() can read its statistics.
        self._sock = self._listen(iface=self.iface, filter=BPF_FILTER)
        # store=False: Scapy would otherwise keep every packet in memory for the life of the capture.
        self._sniff(opened_socket=self._sock, iface=self.iface, filter=BPF_FILTER, prn=self.enqueue, store=False)

    def kernel_dropped(self) -> int:
        """Packets the kernel discarded before Scapy read them (socket buffer full during a burst).

        Reading PACKET_STATISTICS resets the kernel's counter, so the total is accumulated here.
        """
        sock = getattr(self._sock, "ins", None)
        if sock is not None:
            try:
                _, drops = struct.unpack("II", sock.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))
                self._kernel_dropped += drops
            except OSError:
                pass  # socket already closed
        return self._kernel_dropped

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
