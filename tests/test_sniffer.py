import logging
import queue
import threading
import time

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
    seen = {}

    def fake_sniff(**kwargs):
        seen.update(kwargs)
        n = 0
        while not stop.is_set():
            kwargs["prn"](n)
            n += 1

    capture = CaptureThread("lo", queue.Queue(maxsize=10), sniff=fake_sniff)
    capture.start()
    deadline = time.monotonic() + 5
    while capture.dropped < 1000 and time.monotonic() < deadline:
        time.sleep(0.01)
    assert capture.dropped >= 1000
    assert capture.is_alive()
    stop.set()
    capture.join(timeout=2)
    assert (seen["iface"], seen["filter"], seen["store"]) == ("lo", BPF_FILTER, False)
