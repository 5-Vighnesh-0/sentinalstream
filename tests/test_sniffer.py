import logging
import queue
import struct
import threading
import time

from backend.capture import sniffer
from backend.capture.sniffer import BPF_FILTER, CaptureThread


def test_full_queue_drops_oldest_and_warns(caplog):
    packets = queue.Queue(maxsize=2)
    capture = CaptureThread("lo", packets)
    with caplog.at_level(logging.WARNING):
        for n in range(5):
            capture.enqueue(n)
    assert [packets.get_nowait(), packets.get_nowait()] == [3, 4]  # newest kept
    assert capture.dropped == 3
    assert "dropped 1 packets" in caplog.text


def test_capture_thread_survives_overflow():
    stop = threading.Event()
    seen, sniffed = {}, {}

    def fake_sniff(**kwargs):
        sniffed.update(kwargs)
        n = 0
        while not stop.is_set():
            kwargs["prn"](n)
            n += 1

    capture = CaptureThread("lo", queue.Queue(maxsize=10), sniff=fake_sniff, listen=lambda **kw: seen.update(kw))
    capture.start()
    deadline = time.monotonic() + 5
    while capture.dropped < 1000 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert capture.dropped >= 1000
    assert capture.is_alive()
    stop.set()
    capture.join(timeout=2)
    assert (seen["iface"], seen["filter"], sniffed["store"]) == ("lo", BPF_FILTER, False)
    # Given iface as well, Scapy opens a second, unfiltered socket and every packet is read 3 times.
    assert "iface" not in sniffed and "filter" not in sniffed


def test_kernel_drops_accumulate_across_reads():
    class FakeSocket:  # PACKET_STATISTICS resets on every read, like the kernel's
        def getsockopt(self, level, option, size):
            return struct.pack("II", 10, 3)

    capture = CaptureThread("lo", queue.Queue())
    capture._sock = type("L2", (), {"ins": FakeSocket()})()
    capture.kernel_dropped()
    assert capture.kernel_dropped() == 6


def test_kernel_drops_zero_before_capture_starts():
    assert CaptureThread("lo", queue.Queue()).kernel_dropped() == 0


def test_loopback_drops_outgoing_duplicate_other_ifaces_keep_it(monkeypatch):
    monkeypatch.setattr(sniffer, "L2ListenSocket", lambda iface, filter: filter)
    assert sniffer.listen_socket(iface="lo", filter=BPF_FILTER) == f"inbound and {BPF_FILTER}"
    assert sniffer.listen_socket(iface="eth0", filter=BPF_FILTER) == BPF_FILTER
