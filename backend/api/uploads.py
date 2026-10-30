"""PCAP upload handling: untrusted files are parsed and scored in a separate, resource-limited process."""
import ctypes
import multiprocessing as mp
import queue
import re
import resource
import shutil
import tempfile
import time
from pathlib import Path

MAX_UPLOAD_BYTES = 50 * 1024 * 1024
EXTENSIONS = (".pcap", ".pcapng")
UPLOAD_DIR = Path(tempfile.gettempdir()) / "sentinelstream-uploads"
CHILD_MEMORY_BYTES = 2 * 1024**3  # address space: Python + scikit-learn + Scapy need a few hundred MB
CHILD_CPU_S = 120
CHILD_WALL_S = 180
PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 47, 4  # linux/prctl.h
_CAP_VERSION_3 = 0x20080522  # linux/capability.h


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]


def drop_capabilities() -> None:
    """Empty this process's capability sets (dropping needs no privilege): the parser must not keep CAP_NET_RAW."""
    libc = ctypes.CDLL(None, use_errno=True)  # process symbols already include libc; find_library may spawn ldconfig/gcc
    if libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_CAP_AMBIENT_CLEAR_ALL) failed")
    if libc.capset(ctypes.byref(_CapHeader(_CAP_VERSION_3, 0)), (_CapData * 2)()) != 0:
        raise OSError(ctypes.get_errno(), "capset failed")


def sanitise_filename(name: str) -> str:
    """Display-only copy of the client filename; it is never used as a path."""
    return re.sub(r"[^A-Za-z0-9._ -]", "_", name or "upload")[:255]


def reset_upload_dir() -> Path:
    """Wipe leftovers from a previous run (crash mid-upload) and return the empty directory."""
    shutil.rmtree(UPLOAD_DIR, ignore_errors=True)
    UPLOAD_DIR.mkdir(mode=0o700, parents=True)
    return UPLOAD_DIR


def _child(path: str, model_path: str, out) -> None:
    try:
        drop_capabilities()  # first: a failed drop is reported and the upload fails closed
        resource.setrlimit(resource.RLIMIT_AS, (CHILD_MEMORY_BYTES, CHILD_MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (CHILD_CPU_S, CHILD_CPU_S))
        from backend.detection.detectors import Detectors  # imported after the limits apply
        from backend.features.flow_table import flows_from_pcap

        flows, _ = flows_from_pcap(path)
        out.put(("ok", Detectors(model_path).score(flows)))
    except BaseException as e:  # noqa: BLE001 - MemoryError and parser crashes included: report, don't hang the parent
        out.put(("error", f"{type(e).__name__}: {e}"))


def analyse_upload(path, model_path, wall_s: float = CHILD_WALL_S) -> list[dict]:
    """Score one capture in a spawned child with memory, CPU and wall-clock limits; raise RuntimeError on failure."""
    ctx = mp.get_context("spawn")
    out = ctx.Queue()
    child = ctx.Process(target=_child, args=(str(path), str(model_path), out), daemon=True)
    child.start()
    deadline = time.monotonic() + wall_s
    try:
        while True:
            try:
                status, result = out.get(timeout=1)
                break
            except queue.Empty:
                if not child.is_alive():  # killed by RLIMIT_CPU/AS before it could report
                    status, result = "error", f"parser died (exit code {child.exitcode})"
                    break
                if time.monotonic() > deadline:
                    status, result = "error", f"no result within {wall_s} s"
                    break
    finally:
        child.join(timeout=5)
        if child.is_alive():
            child.kill()
    if status != "ok":
        raise RuntimeError(result)
    return result
