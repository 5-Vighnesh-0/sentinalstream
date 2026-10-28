# Weak-Spot Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the Phase 1 weak spots in code (packet parsing, Isolation Forest scoring/severity, port-scan rule, model integrity, committed models) and write every later-phase fix into the docs and phase gates, per `docs/superpowers/specs/2026-10-28-weak-spot-hardening-design.md`.

**Architecture:** Parsing fixes stay in `backend/features/extractor.py`; severity and model integrity in `backend/features/feature_set.py`; Isolation Forest scoring in `backend/ml/train_baseline.py`; the new cross-flow port-scan rule in its own module `backend/detection/scan_rule.py`; `backend/detect_offline.py` combines Isolation Forest + scan rule. Models are committed to git (compressed, sha256-checked).

**Tech Stack:** Python 3.11+ (local 3.14.4), Scapy 2.8.0, pandas 3.1.0, NumPy 2.5.4, scikit-learn 1.9.1, pytest 9.2.0.

## Global Constraints

- Shared features, in order: `flow_duration_s, fwd_packets, bwd_packets, total_bytes, packets_per_s`. No TCP flag features.
- Isolation Forest flags when anomaly score > 99th percentile of benign training scores. IF-only alerts: severity `low`, or `medium` at ≥ p99.9; never `high` (D6).
- Named detections (scan rule, Random Forest): `high` ≥ 0.90, `medium` ≥ 0.70, else `low`.
- Scan rule: ≥ 20 distinct (dst_ip, dst_port) from one source within 10 s → one `PortScan` alert, `source="rule"`; at most one alert per source per 10 s.
- Alert `source` ∈ {`rule`, `random_forest`, `isolation_forest`}.
- Models committed to git with `joblib` `compress=3`; sidecar `sha256` verified before loading.
- No new dependencies. Every number in docs must come from a command in this repo.
- Ask before deleting any file. No FastAPI/React/Docker/simulator code in this pass.
- Run commands from the repo root `/home/vighnesh/Desktop/projects/sentinelstream` with `.venv/bin/python` / `.venv/bin/pytest`.

## Deviation from the spec

The spec puts "model path must be under `models/`" in `load_model` (Phase 1). The CLI's `--model` comes from a trusted local user and tests load models from `tmp_path`, so the path restriction moves to Phase 3, where `SENTINEL_MODEL_PATH` is read by the API. The sha256 check stays in Phase 1. Task 6 updates the spec row.

## File map

| File | Change | Responsibility |
|---|---|---|
| `backend/features/extractor.py` | modify | Packet parsing, flows, capture-file magic check, flow cap |
| `backend/features/feature_set.py` | modify | Severity (D6), compressed save, sha256 load check |
| `backend/ml/train_baseline.py` | modify | Tail quantiles, threshold, held-out FPR report |
| `backend/detection/__init__.py`, `backend/detection/scan_rule.py` | create | Cross-flow `ScanDetector` |
| `backend/detect_offline.py` | modify | IF + scan rule, `source`/`flow_key` columns |
| `tests/test_extractor.py` | create | Packet-level parsing tests |
| `tests/test_scan_rule.py` | create | Scan rule tests |
| `tests/test_features.py`, `tests/test_detect_offline.py` | modify | New interfaces, path-independent |
| `.gitignore` | modify | Stop ignoring `models/` (D3) |
| `models/isolation_forest.joblib`, `.features.json` | regenerate + commit | D3 |
| docs (`PHASES`, `ARCHITECTURE`, `DATA_MODEL`, `API_SPEC`, `LIMITATIONS`, `EVALUATION`, `PRD`, `README`, `AGENTS`, `PHASE1_RESULTS`, spec) | modify | Decisions D1–D6 and later-phase gates |

---

### Task 1: Packet parsing hardening (`extractor.py`)

**Files:**
- Modify: `backend/features/extractor.py` (full rewrite below)
- Create: `tests/test_extractor.py`
- Modify: `tests/test_features.py` (fixture uses new return type, paths from `__file__`)

**Interfaces:**
- Produces: `parse_packet(pkt) -> PacketInfo | None` (raises `ValueError` on out-of-range timestamp); `is_non_first_fragment(pkt) -> bool`; `check_capture_file(path) -> None` (raises `ValueError`); `flows_from_pcap(path, max_flows=MAX_FLOWS) -> tuple[list[Flow], collections.Counter]` with stats keys `packets`, `skipped_non_ip`, `skipped_fragments`, `skipped_errors`, `evicted_flows`, `truncated`; `Flow` (slots dataclass) with `first_ts`/`last_ts` as `Decimal`, `flow_key`, `end_time`, `features()`; `PacketInfo.is_reply: bool | None`.

- [ ] **Step 1: Write the failing tests** — `tests/test_extractor.py`:

```python
import gzip
from collections import Counter
from decimal import Decimal
from pathlib import Path

import pytest
from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6, IPv6ExtHdrHopByHop
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from backend.features import extractor
from backend.features.extractor import Flow, flows_from_pcap, is_non_first_fragment, parse_packet

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "sample.pcap"
LO = "127.0.0.1"


def timed(pkt, ts):
    pkt.time = ts
    return pkt


def test_ethernet_padding_is_not_payload():
    frame = Ether(src="00:00:00:00:00:01", dst="00:00:00:00:00:02") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags="A")
    padded = timed(Ether(bytes(frame).ljust(60, b"\0")), 1.0)
    assert parse_packet(padded).payload_len == 0


def test_loopback_ping_has_both_directions():
    req = timed(IP(bytes(IP(src=LO, dst=LO) / ICMP(type=8, id=5) / Raw(b"a" * 56))), 1.0)
    rep = timed(IP(bytes(IP(src=LO, dst=LO) / ICMP(type=0, id=5) / Raw(b"a" * 56))), 1.001)
    p1, p2 = parse_packet(req), parse_packet(rep)
    assert (p1.protocol, p1.src_port, p1.is_reply, p2.is_reply) == ("ICMP", 5, False, True)
    flow = Flow.start(p1)
    flow.add(p1)
    flow.add(p2)
    assert (flow.fwd_packets, flow.bwd_packets, flow.total_bytes) == (1, 1, 112)


def test_ipv6_extension_header_keeps_tcp():
    pkt = timed(IPv6(bytes(IPv6(src="::1", dst="::1") / IPv6ExtHdrHopByHop() / TCP(sport=1234, dport=80, flags="S"))), 1.0)
    p = parse_packet(pkt)
    assert (p.protocol, p.src_port, p.dst_port, p.flags) == ("TCP", 1234, 80, "S")


def test_icmpv6_echo():
    req = timed(IPv6(bytes(IPv6(src="::1", dst="::1") / ICMPv6EchoRequest(id=7, data=b"x" * 10))), 1.0)
    rep = timed(IPv6(bytes(IPv6(src="::1", dst="::1") / ICMPv6EchoReply(id=7, data=b"x" * 10))), 1.1)
    p1, p2 = parse_packet(req), parse_packet(rep)
    assert (p1.protocol, p1.src_port, p1.payload_len, p1.is_reply, p2.is_reply) == ("ICMP", 7, 10, False, True)


def test_non_first_fragment_detected():
    assert is_non_first_fragment(IP(src=LO, dst=LO, proto=17, frag=10) / Raw(b"x" * 20))
    assert not is_non_first_fragment(IP(src=LO, dst=LO) / TCP())


def test_out_of_order_packets_extend_duration():
    late = parse_packet(timed(IP(src=LO, dst=LO) / TCP(sport=1, dport=2), 5.0))
    early = parse_packet(timed(IP(src=LO, dst=LO) / TCP(sport=1, dport=2), 3.0))
    flow = Flow.start(late)
    flow.add(late)
    flow.add(early)
    assert flow.features()["flow_duration_s"] == 2.0


def test_sub_microsecond_timestamps_keep_precision():
    a = parse_packet(timed(IP(src=LO, dst=LO) / TCP(sport=1, dport=2), Decimal("1700000000.0000001")))
    b = parse_packet(timed(IP(src=LO, dst=LO) / TCP(sport=1, dport=2), Decimal("1700000000.0000002")))
    flow = Flow.start(a)
    flow.add(a)
    flow.add(b)
    assert flow.features()["flow_duration_s"] == pytest.approx(1e-7)


def test_out_of_range_timestamp_rejected():
    with pytest.raises(ValueError, match="timestamp"):
        parse_packet(timed(IP(src=LO, dst=LO) / TCP(), 1e12))


def test_bad_packet_is_skipped_not_fatal(monkeypatch):
    real = extractor.parse_packet
    calls = Counter()

    def flaky(pkt):
        calls["n"] += 1
        if calls["n"] == 1:
            raise ValueError("boom")
        return real(pkt)

    monkeypatch.setattr(extractor, "parse_packet", flaky)
    flows, stats = flows_from_pcap(SAMPLE)
    assert stats["skipped_errors"] == 1
    assert stats["packets"] == 600
    assert len(flows) == 71  # the first packet only opened a benign flow that later packets reopen


def test_gzip_capture_rejected(tmp_path):
    gz = tmp_path / "sample.pcap"
    gz.write_bytes(gzip.compress(SAMPLE.read_bytes()))
    with pytest.raises(ValueError, match="pcap"):
        flows_from_pcap(gz)


def test_flow_cap_evicts_but_keeps_flows():
    flows, stats = flows_from_pcap(SAMPLE, max_flows=10)
    assert len(flows) == 71
    assert stats["evicted_flows"] == 61
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `.venv/bin/pytest tests/test_extractor.py -q`
Expected: FAIL (`ImportError: cannot import name 'is_non_first_fragment'`).

- [ ] **Step 3: Implement** — replace `backend/features/extractor.py` with:

```python
"""Group packets into bidirectional 5-tuple flows and compute the shared features."""
from collections import Counter, OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6, IPv6ExtHdrFragment
from scapy.packet import Padding
from scapy.utils import PcapReader

from backend.features.feature_set import FEATURES, packets_per_s

# pcap (both byte orders, µs and ns resolution) and pcapng. Anything else, including gzip, is rejected:
# Scapy would otherwise decompress gzip transparently and bypass upload size limits.
CAPTURE_MAGICS = {b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x0a\x0d\x0d\x0a"}
MAX_FLOWS = 100_000
MAX_TS = 4_102_444_800  # 2100-01-01; larger values are corrupt and overflow datetime


@dataclass(slots=True)
class PacketInfo:
    ts: Decimal
    src_ip: str
    dst_ip: str
    src_port: int  # ICMP echo: the echo id
    dst_port: int
    protocol: str
    payload_len: int
    flags: str  # TCP flag letters, e.g. "SA"; empty for non-TCP. Not a model feature; Phase 2 uses FIN/RST to end flows.
    is_reply: bool | None = None  # ICMP echo only: on loopback src == dst, so direction comes from request/reply


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
    ts = Decimal(pkt.time)
    if not 0 <= ts < MAX_TS:
        raise ValueError(f"timestamp out of range: {ts}")
    padding = len(pkt[Padding]) if Padding in pkt else 0  # Ethernet trailer, not payload
    sport = dport = 0
    flags = ""
    is_reply = None
    echo6 = pkt.getlayer(ICMPv6EchoReply) or pkt.getlayer(ICMPv6EchoRequest)
    if TCP in pkt:
        protocol, sport, dport, flags = "TCP", pkt[TCP].sport, pkt[TCP].dport, str(pkt[TCP].flags)
        payload_len = len(pkt[TCP].payload) - padding
    elif UDP in pkt:
        protocol, sport, dport = "UDP", pkt[UDP].sport, pkt[UDP].dport
        payload_len = len(pkt[UDP].payload) - padding
    elif ICMP in pkt:
        protocol = "ICMP"
        payload_len = len(pkt[ICMP].payload) - padding
        if pkt[ICMP].type in (0, 8):
            sport = dport = pkt[ICMP].id
            is_reply = pkt[ICMP].type == 0
    elif echo6 is not None:
        protocol, sport, dport = "ICMP", echo6.id, echo6.id
        payload_len = len(echo6.data)
        is_reply = isinstance(echo6, ICMPv6EchoReply)
    else:
        is_icmp6 = any(layer.__name__.startswith("ICMPv6") for layer in pkt.layers())
        protocol = "ICMP" if is_icmp6 else "OTHER"
        payload_len = max(len(ip.payload) - padding, 0)
    return PacketInfo(ts, ip.src, ip.dst, sport, dport, protocol, payload_len, flags, is_reply)


def canonical_key(p: PacketInfo) -> tuple:
    """Same key for both directions of a conversation."""
    a, b = (p.src_ip, p.src_port), (p.dst_ip, p.dst_port)
    return (p.protocol, *min(a, b), *max(a, b))


@dataclass(slots=True)
class Flow:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    first_ts: Decimal
    last_ts: Decimal
    fwd_is_reply: bool | None = None
    fwd_packets: int = 0
    bwd_packets: int = 0
    total_bytes: int = 0

    @classmethod
    def start(cls, p: PacketInfo) -> "Flow":
        # The first packet's sender defines the forward direction.
        return cls(p.src_ip, p.dst_ip, p.src_port, p.dst_port, p.protocol, p.ts, p.ts, p.is_reply)

    def add(self, p: PacketInfo) -> None:
        self.first_ts = min(self.first_ts, p.ts)
        self.last_ts = max(self.last_ts, p.ts)
        if p.is_reply is not None and self.fwd_is_reply is not None:
            forward = p.is_reply == self.fwd_is_reply
        else:
            forward = (p.src_ip, p.src_port) == (self.src_ip, self.src_port)
        if forward:
            self.fwd_packets += 1
        else:
            self.bwd_packets += 1
        self.total_bytes += p.payload_len

    @property
    def flow_key(self) -> str:
        return f"{self.protocol}|{self.src_ip}|{self.src_port}|{self.dst_ip}|{self.dst_port}"

    @property
    def end_time(self) -> str:
        dt = datetime.fromtimestamp(float(self.last_ts), tz=timezone.utc)
        return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    def features(self) -> dict:
        duration = float(self.last_ts - self.first_ts)
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
        magic = f.read(4)
    if magic not in CAPTURE_MAGICS:
        raise ValueError(f"{path}: not a pcap/pcapng file (gzip and other formats are rejected)")


def flows_from_pcap(path, max_flows: int = MAX_FLOWS) -> tuple[list[Flow], Counter]:
    """Read a PCAP/PCAPNG and return (flows, stats). One Flow per bidirectional 5-tuple.

    shortcut: no idle/active timeout offline, so a reused 5-tuple merges into one flow; Phase 2's
    timestamp-driven flow table (D5) replaces this loop for offline, upload and live paths.
    """
    check_capture_file(path)
    active: OrderedDict[tuple, Flow] = OrderedDict()
    done: list[Flow] = []
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
            flow = active.get(key)
            if flow is None:
                if len(active) >= max_flows:
                    done.append(active.popitem(last=False)[1])  # least recently active
                    stats["evicted_flows"] += 1
                flow = active[key] = Flow.start(p)
            else:
                active.move_to_end(key)
            flow.add(p)
    return done + list(active.values()), stats
```

Note on `test_bad_packet_is_skipped_not_fatal`: `flows_from_pcap` calls `parse_packet` through the module global, so the monkeypatch takes effect.

- [ ] **Step 4: Update `tests/test_features.py`** — replace the header and fixture:

```python
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from backend.features.extractor import flows_from_pcap
from backend.features.feature_set import FEATURES, from_cicids, load_model, packets_per_s, save_model, severity

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "sample.pcap"


@pytest.fixture(scope="module")
def flows():
    flows, _ = flows_from_pcap(SAMPLE)
    return {f.flow_key: f for f in flows}
```

Also keep the existing callers working with the new return type. In `backend/detect_offline.py` change `flows = flows_from_pcap(pcap)` to `flows, _ = flows_from_pcap(pcap)`, and in `tests/test_detect_offline.py` change `flows_from_pcap(SAMPLE)` to `flows_from_pcap(SAMPLE)[0]`.

- [ ] **Step 5: Run tests**

Run: `.venv/bin/pytest -q`
Expected: PASS (whole suite stays green between tasks).

- [ ] **Step 6: Commit**

```bash
git add backend/features/extractor.py backend/detect_offline.py tests/test_extractor.py tests/test_features.py tests/test_detect_offline.py
git commit -m "Harden packet parsing: padding, ICMP direction, IPv6, fragments, bad packets, flow cap, gzip rejection"
```

---

### Task 2: Severity (D6) and model integrity (`feature_set.py`)

**Files:**
- Modify: `backend/features/feature_set.py`
- Modify: `tests/test_features.py`

**Interfaces:**
- Produces: `severity(confidence: float, named: bool = True) -> str`; `ANOMALY_MEDIUM = 0.999`; `file_sha256(path) -> str`; `save_model(model, model_path, **metadata)` now writes `compress=3` and `sha256`; `load_model(path)` raises `ValueError` on sha256 mismatch and warns (`UserWarning`) on sklearn version mismatch.

- [ ] **Step 1: Write the failing tests** — in `tests/test_features.py` replace `test_severity_thresholds` and `test_load_model_rejects_wrong_feature_order`, add one test:

```python
def test_severity_named_detections():
    assert [severity(c) for c in (0.95, 0.9, 0.8, 0.7, 0.69)] == ["high", "high", "medium", "medium", "low"]


def test_severity_unnamed_anomalies_never_high():
    assert [severity(c, named=False) for c in (1.0, 0.999, 0.995, 0.99)] == ["medium", "medium", "low", "low"]


def test_load_model_rejects_wrong_feature_order(tmp_path):
    path = tmp_path / "m.joblib"
    save_model({"dummy": True}, path)
    _, meta = load_model(path)
    assert meta["feature_order"] == FEATURES

    sidecar = tmp_path / "m.features.json"
    sidecar.write_text(sidecar.read_text().replace('"fwd_packets"', '"renamed"'))
    with pytest.raises(ValueError, match="feature order"):
        load_model(path)


def test_load_model_rejects_tampered_file(tmp_path):
    path = tmp_path / "m.joblib"
    save_model({"dummy": True}, path)
    path.write_bytes(path.read_bytes() + b"\0")
    with pytest.raises(ValueError, match="sha256"):
        load_model(path)
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest tests/test_features.py -q`
Expected: FAIL (`severity() got an unexpected keyword argument 'named'`; tampered file loads).

- [ ] **Step 3: Implement** — in `backend/features/feature_set.py`:

Add imports `hashlib`, `warnings`. Replace the severity block and the save/load functions:

```python
SEVERITY_HIGH = 0.90
SEVERITY_MEDIUM = 0.70
ANOMALY_MEDIUM = 0.999  # Isolation-Forest-only alerts: above p99.9 of benign training scores


def severity(confidence: float, named: bool = True) -> str:
    """Named detections (scan rule, Random Forest) can be high; an unnamed anomaly is a triage hint, never high."""
    if not named:
        return "medium" if confidence >= ANOMALY_MEDIUM else "low"
    if confidence >= SEVERITY_HIGH:
        return "high"
    if confidence >= SEVERITY_MEDIUM:
        return "medium"
    return "low"
```

```python
def file_sha256(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def save_model(model, model_path, **metadata) -> None:
    model_path = Path(model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path, compress=3)
    meta = {
        "model": model_path.stem,
        "feature_order": FEATURES,
        "sklearn_version": sklearn.__version__,
        "created_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "sha256": file_sha256(model_path),
        **metadata,
    }
    sidecar_path(model_path).write_text(json.dumps(meta, indent=2))


def load_model(model_path):
    """Load a model this repo trained. Refuse it if the file doesn't match its sidecar or the feature order differs."""
    meta = json.loads(sidecar_path(model_path).read_text())
    if meta["feature_order"] != FEATURES:
        raise ValueError(f"{model_path}: feature order {meta['feature_order']} does not match {FEATURES}")
    if meta.get("sha256") != file_sha256(model_path):
        raise ValueError(f"{model_path}: file does not match the sha256 in its sidecar")
    if meta["sklearn_version"] != sklearn.__version__:
        warnings.warn(f"{model_path} was trained with scikit-learn {meta['sklearn_version']}, running {sklearn.__version__}")
    return joblib.load(model_path), meta
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/pytest tests/test_features.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/features/feature_set.py tests/test_features.py
git commit -m "Severity tiers for unnamed anomalies (D6); compressed models with sha256 check"
```

---

### Task 3: Isolation Forest tail quantiles, threshold, held-out evaluation (`train_baseline.py`)

**Files:**
- Modify: `backend/ml/train_baseline.py`
- Modify: `tests/test_detect_offline.py` (train-CLI test moves to `tests/test_train_baseline.py`)
- Create: `tests/test_train_baseline.py`

**Interfaces:**
- Consumes: `from_cicids`, `save_model`, `FEATURES` (Task 2).
- Produces: `PROBS` (1,100 probabilities: 100 from 0 to <0.99, 1,000 from 0.99 to 1.0), `FLAG_INDEX = 100`; `train(X) -> (model, scoring: dict)` with keys `flag_quantile`, `threshold`, `score_probs`, `score_quantiles`; `score(model, meta, X) -> (flagged: ndarray[bool], confidence: ndarray[float])`; CLI flag `--eval-csv PATH...`; sidecar key `evaluation: {name: {label: {"rows": int, "flagged": int}}}` with a `training_csv_holdout` entry.

- [ ] **Step 1: Write the failing tests** — `tests/test_train_baseline.py`:

```python
import json

import numpy as np
import pandas as pd

from backend.features.feature_set import FEATURES
from backend.ml import train_baseline


def cicids_frame(rows, labels):
    return pd.DataFrame({
        " Flow Duration": [1_000_000 + i for i in range(rows)],
        " Total Fwd Packets": [3 + i % 5 for i in range(rows)],
        " Total Backward Packets": [2] * rows,
        "Total Length of Fwd Packets": [120] * rows,
        " Total Length of Bwd Packets": [800] * rows,
        " Fwd Header Length": [60] * rows,
        " Fwd Header Length.1": [60] * rows,  # CICIDS2017 duplicates this column
        " SYN Flag Count": [1] * rows,
        " Label": labels,
    })


def test_flagged_flows_always_have_confidence_at_least_p99():
    rng = np.random.default_rng(0)
    benign = pd.DataFrame(rng.lognormal(size=(2000, len(FEATURES))), columns=FEATURES)
    model, scoring = train_baseline.train(benign)
    probe = pd.concat([benign, benign * 50], ignore_index=True)
    flagged, confidence = train_baseline.score(model, scoring, probe)
    assert flagged.any()
    assert confidence[flagged].min() >= train_baseline.FLAG_QUANTILE
    assert scoring["threshold"] == scoring["score_quantiles"][train_baseline.FLAG_INDEX]
    assert scoring["score_probs"][train_baseline.FLAG_INDEX] == train_baseline.FLAG_QUANTILE


def test_train_cli_records_holdout_and_eval(tmp_path):
    train_csv, eval_csv = tmp_path / "Monday.csv", tmp_path / "Tuesday.csv"
    cicids_frame(300, ["BENIGN"] * 300).to_csv(train_csv, index=False)
    cicids_frame(40, ["BENIGN"] * 30 + ["DoS Hulk"] * 10).to_csv(eval_csv, index=False)
    out = tmp_path / "isolation_forest.joblib"

    train_baseline.main(["--csv", str(train_csv), "--sample", "100", "--eval-csv", str(eval_csv), "--out", str(out)])

    meta = json.loads((tmp_path / "isolation_forest.features.json").read_text())
    assert meta["feature_order"] == FEATURES
    assert (meta["n_train_rows"], meta["benign_rows"]) == (100, 300)
    assert meta["evaluation"]["training_csv_holdout"]["BENIGN"]["rows"] == 100
    assert meta["evaluation"]["Tuesday.csv"]["DoS Hulk"]["rows"] == 10
    assert len(meta["sha256"]) == 64
```

In `tests/test_detect_offline.py` delete `test_train_baseline_cli_on_cicids_shaped_csv` and the now-unused `import json` (the CLI test is rewritten in Task 5).

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest tests/test_train_baseline.py -q`
Expected: FAIL (`KeyError: 'threshold'` / unknown `--eval-csv`).

- [ ] **Step 3: Implement** — replace `backend/ml/train_baseline.py` from the constants through `main()` with:

```python
DEFAULT_OUT = "models/isolation_forest.joblib"
RANDOM_STATE = 42
# Flag flows more anomalous than this fraction of benign training flows; contamination="auto"
# flagged far too many benign Monday rows to be a usable alarm (see PROGRESS.md, Phase 1).
FLAG_QUANTILE = 0.99
# Coarse below the threshold, fine (1e-5 steps) in the tail so severity can tell p99 from p99.9.
PROBS = np.concatenate([np.linspace(0, FLAG_QUANTILE, 100, endpoint=False), np.linspace(FLAG_QUANTILE, 1, 1000)])
FLAG_INDEX = 100  # PROBS[FLAG_INDEX] == FLAG_QUANTILE


def build_model():
    # Features are heavy-tailed counts and rates; log1p keeps Isolation Forest splits from being dominated by outliers.
    return make_pipeline(
        FunctionTransformer(np.log1p),
        IsolationForest(n_estimators=200, random_state=RANDOM_STATE),
    )


def anomaly_scores(model, X: pd.DataFrame) -> np.ndarray:
    """Higher = more anomalous."""
    return -model.score_samples(X[FEATURES])


def train(X: pd.DataFrame) -> tuple[object, dict]:
    """Fit on benign feature rows; return (model, scoring metadata to save in the sidecar)."""
    model = build_model().fit(X[FEATURES])
    quantiles = np.quantile(anomaly_scores(model, X), PROBS)
    return model, {
        "flag_quantile": FLAG_QUANTILE,
        "threshold": float(quantiles[FLAG_INDEX]),
        "score_probs": PROBS.tolist(),
        "score_quantiles": quantiles.tolist(),
    }


def score(model, meta: dict, X: pd.DataFrame) -> tuple[np.ndarray, np.ndarray]:
    """Return (flagged, confidence). Confidence = share of benign training flows with a lower anomaly score."""
    s = anomaly_scores(model, X)
    quantiles, probs = np.asarray(meta["score_quantiles"]), np.asarray(meta["score_probs"])
    idx = np.searchsorted(quantiles, s, side="right") - 1
    confidence = np.where(idx >= 0, probs[np.clip(idx, 0, None)], 0.0)
    # threshold == quantiles[FLAG_INDEX], so every flagged flow has confidence >= FLAG_QUANTILE.
    return s > meta["threshold"], confidence


def flagged_counts(model, meta: dict, X: pd.DataFrame, labels: pd.Series) -> dict:
    flagged, _ = score(model, meta, X)
    counts = pd.DataFrame({"label": labels.to_numpy(), "flagged": flagged}).groupby("label")["flagged"].agg(["size", "sum"])
    return {label: {"rows": int(row["size"]), "flagged": int(row["sum"])} for label, row in counts.iterrows()}


def read_cicids(path) -> tuple[pd.DataFrame, pd.Series, int, int]:
    raw = pd.read_csv(path, usecols=lambda c: c.strip() in CICIDS_NEEDED, low_memory=False)
    X, labels, dropped = from_cicids(raw)
    return X, labels, len(raw), dropped


def load_benign(csv_paths: list[str], sample: int) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Return (training sample, disjoint held-out sample of the same size, stats)."""
    frames, stats = [], {"rows_read": 0, "rows_dropped_invalid": 0, "benign_rows": 0}
    for path in csv_paths:
        X, labels, read, dropped = read_cicids(path)
        stats["rows_read"] += read
        stats["rows_dropped_invalid"] += dropped
        frames.append(X[labels == "BENIGN"])
    benign = pd.concat(frames, ignore_index=True)
    stats["benign_rows"] = len(benign)
    train_rows = benign.sample(n=min(sample, len(benign)), random_state=RANDOM_STATE)
    rest = benign.drop(train_rows.index)
    holdout = rest.sample(n=min(sample, len(rest)), random_state=RANDOM_STATE)
    return train_rows.reset_index(drop=True), holdout.reset_index(drop=True), stats


def print_evaluation(evaluation: dict) -> None:
    print(f"{'file':52s} {'label':28s} {'rows':>9s} {'flagged':>8s} {'rate':>7s}")
    for name, by_label in evaluation.items():
        for label, c in by_label.items():
            print(f"{name:52s} {label:28s} {c['rows']:9d} {c['flagged']:8d} {c['flagged'] / c['rows']:7.2%}")


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--csv", nargs="+", required=True, help="CICIDS2017 CSV file(s) to train on (BENIGN rows)")
    parser.add_argument("--sample", type=int, default=50_000, help="max benign rows to train on (same size held out)")
    parser.add_argument("--eval-csv", nargs="*", default=[], help="other CICIDS2017 CSVs to report flag rates on")
    parser.add_argument("--out", default=DEFAULT_OUT)
    args = parser.parse_args(argv)

    X, holdout, stats = load_benign(args.csv, args.sample)
    if X.empty:
        sys.exit("no BENIGN rows found in the given CSV(s)")
    model, scoring = train(X)

    evaluation = {}
    if not holdout.empty:
        evaluation["training_csv_holdout"] = flagged_counts(model, scoring, holdout, pd.Series(["BENIGN"] * len(holdout)))
    for path in args.eval_csv:
        if path in args.csv:
            print(f"skipping {path}: it is a training file")
            continue
        E, labels, _, _ = read_cicids(path)
        evaluation[Path(path).name] = flagged_counts(model, scoring, E, labels)

    save_model(model, args.out, trained_on=args.csv, n_train_rows=len(X), random_state=RANDOM_STATE,
               evaluation=evaluation, **stats, **scoring)
    print(f"read {stats['rows_read']} rows, dropped {stats['rows_dropped_invalid']} invalid, "
          f"{stats['benign_rows']} benign; trained on {len(X)}; threshold {scoring['threshold']:.4f}; saved {args.out}")
    print_evaluation(evaluation)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests**

Run: `.venv/bin/pytest tests/test_train_baseline.py tests/test_features.py tests/test_extractor.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/ml/train_baseline.py tests/test_train_baseline.py tests/test_detect_offline.py
git commit -m "Isolation Forest: tail quantiles, exact threshold, held-out and cross-day flag rates"
```

---

### Task 4: Cross-flow port-scan rule (`scan_rule.py`, D2)

**Files:**
- Create: `backend/detection/__init__.py` (empty), `backend/detection/scan_rule.py`
- Create: `tests/test_scan_rule.py`

**Interfaces:**
- Consumes: `Flow` (Task 1) — uses `src_ip`, `dst_ip`, `dst_port`, `protocol`, `first_ts`.
- Produces: `ScanDetector(min_ports=20, window_s=10.0, max_sources=10_000)` with `observe(flow) -> bool` (True = emit one `PortScan` alert for this flow's source). Flows must be fed in `first_ts` order.

- [ ] **Step 1: Write the failing tests** — `tests/test_scan_rule.py`:

```python
from decimal import Decimal
from pathlib import Path

from backend.detection.scan_rule import ScanDetector
from backend.features.extractor import Flow, flows_from_pcap

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "sample.pcap"


def flow(dport, ts, src="10.0.0.9", proto="TCP"):
    t = Decimal(str(ts))
    return Flow(src, "10.0.0.1", 40000, dport, proto, t, t)


def alerts(detector, flows):
    return sum(detector.observe(f) for f in flows)


def test_fast_scan_raises_one_alert():
    assert alerts(ScanDetector(), [flow(p, p * 0.01) for p in range(1, 51)]) == 1


def test_below_threshold_is_quiet():
    assert alerts(ScanDetector(), [flow(p, p * 0.01) for p in range(1, 20)]) == 0


def test_slow_scan_outside_window_is_quiet():
    assert alerts(ScanDetector(), [flow(p, p * 1.0) for p in range(1, 26)]) == 0


def test_long_scan_alerts_once_per_window():
    assert alerts(ScanDetector(), [flow(p, p * 0.1) for p in range(1, 101)]) == 1  # 10 s of scanning
    assert alerts(ScanDetector(), [flow(p, p * 0.1) for p in range(1, 301)]) == 3  # 30 s of scanning


def test_repeat_connections_to_one_port_are_not_a_scan():
    assert alerts(ScanDetector(), [flow(8080, i * 0.01) for i in range(200)]) == 0


def test_icmp_ignored():
    assert alerts(ScanDetector(), [flow(p, p * 0.01, proto="ICMP") for p in range(1, 51)]) == 0


def test_source_state_is_bounded():
    detector = ScanDetector(max_sources=2)
    for i in range(5):
        detector.observe(flow(1, i, src=f"10.0.0.{i}"))
    assert len(detector._recent) == 2


def test_sample_pcap_scan_detected_once():
    flows, _ = flows_from_pcap(SAMPLE)
    detector = ScanDetector()
    hits = [f for f in sorted(flows, key=lambda f: f.first_ts) if detector.observe(f)]
    assert len(hits) == 1
    assert hits[0].src_port == 55555
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest tests/test_scan_rule.py -q`
Expected: FAIL (`ModuleNotFoundError: backend.detection`).

- [ ] **Step 3: Implement** — `backend/detection/scan_rule.py`:

```python
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
        self._recent: OrderedDict[str, deque] = OrderedDict()  # src_ip -> (ts, (dst_ip, dst_port))
        self._last_alert: dict[str, float] = {}

    def observe(self, flow) -> bool:
        """Feed flows in first_ts order. True means: raise one PortScan alert for flow.src_ip now."""
        if flow.protocol not in ("TCP", "UDP"):
            return False
        ts, src = float(flow.first_ts), flow.src_ip
        recent = self._recent.pop(src, None) or deque(maxlen=4 * self.min_ports)
        self._recent[src] = recent  # most recently seen source last
        if len(self._recent) > self.max_sources:
            evicted, _ = self._recent.popitem(last=False)
            self._last_alert.pop(evicted, None)
        recent.append((ts, (flow.dst_ip, flow.dst_port)))
        while recent and recent[0][0] < ts - self.window_s:
            recent.popleft()
        if len({target for _, target in recent}) < self.min_ports:
            return False
        last = self._last_alert.get(src)
        if last is not None and ts - last < self.window_s:
            return False
        self._last_alert[src] = ts
        return True
```

Why `deque(maxlen=4 * min_ports)`: bounds memory under a flood from one source; the rule only needs to know whether ≥ `min_ports` distinct targets exist in the window.

Check of `test_long_scan_alerts_once_per_window` (100 ports at 0.1 s steps): threshold first reached at the 20th distinct port (t = 2.0 s) → alert; the next eligible time is t ≥ 12.0, beyond the last probe (t = 10.0) → 1 alert. 300 ports (to t = 30.0): alerts at t = 2.0, 12.0, 22.0 → 3.

- [ ] **Step 4: Run tests**

Run: `.venv/bin/pytest tests/test_scan_rule.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add backend/detection tests/test_scan_rule.py
git commit -m "Add cross-flow port-scan rule (D2)"
```

---

### Task 5: Offline CLI combines detectors; retrain and commit the model (D3)

**Files:**
- Modify: `backend/detect_offline.py`
- Modify: `tests/test_detect_offline.py` (rewrite)
- Modify: `.gitignore`
- Regenerate + add: `models/isolation_forest.joblib`, `models/isolation_forest.features.json`

**Interfaces:**
- Consumes: `flows_from_pcap` (Task 1), `severity`/`load_model` (Task 2), `train_baseline.score`/`DEFAULT_OUT` (Task 3), `ScanDetector` (Task 4).
- Produces: `COLUMNS = ["timestamp", "src_ip", "dst_ip", "attack_type", "score", "severity", "source", "flow_key"]`; `detect(pcap, model_path) -> (DataFrame, total_flows: int, stats: Counter)`; stdout line `"{n} flows scored, {k} alerts ({i} isolation_forest, {r} rule) -> {out}"`.

- [ ] **Step 1: Write the failing test** — replace `tests/test_detect_offline.py`:

```python
import subprocess
import sys
from pathlib import Path

import pandas as pd

from backend.detect_offline import COLUMNS

REPO = Path(__file__).resolve().parents[1]
SAMPLE = REPO / "tests" / "fixtures" / "sample.pcap"
FLOOD = "TCP|127.0.0.1|60000|127.0.0.1|80"


def test_cli_with_committed_model(tmp_path):
    out = tmp_path / "out.csv"
    result = subprocess.run(
        [sys.executable, "backend/detect_offline.py", "--pcap", str(SAMPLE), "--out", str(out)],
        cwd=REPO, capture_output=True, text=True, check=True,
    )
    df = pd.read_csv(out)
    assert list(df.columns) == COLUMNS
    iforest = df[df["source"] == "isolation_forest"]
    rule = df[df["source"] == "rule"]
    assert iforest["flow_key"].tolist() == [FLOOD]
    assert set(iforest["attack_type"]) == {"anomaly"}
    assert iforest["score"].min() >= 0.99
    assert set(iforest["severity"]) <= {"low", "medium"}
    assert rule["attack_type"].tolist() == ["PortScan"]
    assert rule["flow_key"].str.contains("|55555|", regex=False).all()
    assert not df["flow_key"].str.contains("|8080", regex=False).any()  # no benign session flagged
    assert "71 flows scored, 2 alerts (1 isolation_forest, 1 rule)" in result.stdout


def test_cli_rejects_non_capture_file(tmp_path):
    bogus = tmp_path / "x.pcap"
    bogus.write_text("not a capture")
    result = subprocess.run(
        [sys.executable, "backend/detect_offline.py", "--pcap", str(bogus), "--out", str(tmp_path / "o.csv")],
        cwd=REPO, capture_output=True, text=True,
    )
    assert result.returncode != 0
    assert "not a pcap/pcapng file" in result.stderr
```

- [ ] **Step 2: Run to verify failure**

Run: `.venv/bin/pytest tests/test_detect_offline.py -q`
Expected: FAIL (CSV has no `source` column; model sidecar lacks `threshold`).

- [ ] **Step 3: Implement** — replace `backend/detect_offline.py`:

```python
"""Score every flow in a PCAP and write alerts to CSV.

Detectors: Isolation Forest (per flow, unnamed "anomaly") and the cross-flow port-scan rule ("PortScan").

Usage:
  python backend/detect_offline.py --pcap tests/fixtures/sample.pcap [--model models/isolation_forest.joblib] [--out alerts.csv]
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # allow `python backend/detect_offline.py`

from backend.detection.scan_rule import ScanDetector  # noqa: E402
from backend.features.extractor import flows_from_pcap  # noqa: E402
from backend.features.feature_set import FEATURES, load_model, severity  # noqa: E402
from backend.ml import train_baseline  # noqa: E402

COLUMNS = ["timestamp", "src_ip", "dst_ip", "attack_type", "score", "severity", "source", "flow_key"]


def alert_row(flow, attack_type: str, confidence: float, source: str) -> dict:
    return {
        "timestamp": flow.end_time,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "attack_type": attack_type,
        "score": round(float(confidence), 4),
        "severity": severity(confidence, named=source != "isolation_forest"),
        "source": source,
        "flow_key": flow.flow_key,
    }


def detect(pcap, model_path):
    """Return (alerts, total flows, parse stats)."""
    model, meta = load_model(model_path)
    flows, stats = flows_from_pcap(pcap)
    rows = []
    if flows:
        X = pd.DataFrame([f.features() for f in flows], columns=FEATURES)
        flagged, confidence = train_baseline.score(model, meta, X)
        # Isolation Forest can't name attacks; named types come from the scan rule and (Phase 5) the Random Forest.
        rows += [alert_row(f, "anomaly", c, "isolation_forest") for f, hit, c in zip(flows, flagged, confidence) if hit]
        scans = ScanDetector()
        rows += [alert_row(f, "PortScan", 1.0, "rule") for f in sorted(flows, key=lambda f: f.first_ts) if scans.observe(f)]
    alerts = pd.DataFrame(rows, columns=COLUMNS).sort_values("timestamp", kind="stable", ignore_index=True)
    return alerts, len(flows), stats


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pcap", required=True)
    parser.add_argument("--model", default=train_baseline.DEFAULT_OUT)
    parser.add_argument("--out", default="data/detections.csv")
    args = parser.parse_args(argv)

    if not Path(args.pcap).is_file():
        sys.exit(f"PCAP not found: {args.pcap}")
    if not Path(args.model).is_file():
        sys.exit(f"model not found: {args.model} (train it with backend/ml/train_baseline.py)")

    try:
        alerts, total, stats = detect(args.pcap, args.model)
    except ValueError as e:
        sys.exit(str(e))
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    alerts.to_csv(args.out, index=False)
    by_source = alerts["source"].value_counts()
    print(f"{total} flows scored, {len(alerts)} alerts "
          f"({by_source.get('isolation_forest', 0)} isolation_forest, {by_source.get('rule', 0)} rule) -> {args.out}")
    skipped = {k: v for k, v in stats.items() if k != "packets" and v}
    print(f"{stats['packets']} packets read" + (f"; {skipped}" if skipped else ""))


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Stop ignoring models (D3)** — in `.gitignore` replace

```
# Datasets, databases and trained models stay local (large / reproducible)
data/*
!data/.gitkeep
models/*
!models/.gitkeep
```

with

```
# Datasets and databases stay local (large, licence-gated). Trained models are committed (D3).
data/*
!data/.gitkeep
```

- [ ] **Step 5: Retrain with cross-day evaluation** (requires `data/raw/cicids2017/MachineLearningCSV.zip`, no download):

```bash
unzip -q -o data/raw/cicids2017/MachineLearningCSV.zip -d data/raw/cicids2017/
D=data/raw/cicids2017/MachineLearningCVE
.venv/bin/python backend/ml/train_baseline.py --csv $D/Monday-WorkingHours.pcap_ISCX.csv \
  --eval-csv $D/Tuesday-WorkingHours.pcap_ISCX.csv $D/Wednesday-workingHours.pcap_ISCX.csv \
  $D/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv $D/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv \
  $D/Friday-WorkingHours-Morning.pcap_ISCX.csv $D/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv \
  $D/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

Expected: `read 529918 rows, dropped 15 invalid, 529903 benign; trained on 50000; threshold …` followed by a per-file/per-label table. If a CSV fails with `UnicodeDecodeError`, stop and report it (the review's latin-1 claim was not confirmed; don't guess).

- [ ] **Step 6: Run the full suite**

Run: `.venv/bin/pytest -q`
Expected: PASS. Also run once from another directory: `cd /tmp && /home/vighnesh/Desktop/projects/sentinelstream/.venv/bin/pytest -q /home/vighnesh/Desktop/projects/sentinelstream/tests` → PASS (path independence).

- [ ] **Step 7: Commit**

```bash
git add .gitignore backend/detect_offline.py tests/test_detect_offline.py models/isolation_forest.joblib models/isolation_forest.features.json
git commit -m "Offline CLI: Isolation Forest + scan rule with source/flow_key; commit compressed model (D3)"
```

---

### Task 6: Docs — decisions, later-phase gates, limitations

**Files:** `docs/PHASES.md`, `docs/ARCHITECTURE.md`, `docs/DATA_MODEL.md`, `docs/API_SPEC.md`, `docs/LIMITATIONS.md`, `docs/EVALUATION.md`, `docs/PRD.md`, `README.md`, `AGENTS.md`, `docs/superpowers/specs/2026-10-28-weak-spot-hardening-design.md`.

No code; verification is the grep in Step 10.

- [ ] **Step 1: `AGENTS.md` fixed decisions** — replace the bullet "Isolation Forest only outputs `anomaly` + score. Attack names come only from the supervised classifier." with:

```
- Isolation Forest only outputs `anomaly` + score. Attack names come from the supervised classifier and, since the Phase 1 hardening pass (human-approved D2), from the cross-flow port-scan rule (`source="rule"`).
- Models are committed to git, compressed, and refused at load if their sha256 doesn't match the sidecar (D3).
- Design decisions D1–D6: docs/superpowers/specs/2026-10-28-weak-spot-hardening-design.md.
```

- [ ] **Step 2: `docs/DATA_MODEL.md`**
  - `alerts` table: add rows after `severity`:
    `| source | TEXT | NOT NULL, CHECK IN (rule, random_forest, isolation_forest) | Which detector raised it (D2) |`,
    `| count | INTEGER | NOT NULL DEFAULT 1 | Detections merged into this alert (D4) |`,
    `| last_seen | TEXT | NOT NULL | Latest merged detection; timestamp is the first (D4) |`.
    Change the `timestamp` note to "First detection (flow end time) — `first_seen` in D4 terms".
  - Add under the table: "**Aggregation (D4):** a detection with the same (`src_ip`, `dst_ip`, `attack_type`) as an alert whose `last_seen` is < 30 s old updates that alert (`count` + 1, `last_seen`, max `confidence`/`severity`) instead of inserting."
  - Attack types table: `PortScan` source becomes "Scan rule (Phase 1) and Random Forest (Phase 5)".
  - Flows (runtime) export rule: "or TCP FIN from both sides, or any RST".
  - Model artifacts: sidecar example gains `"sha256": "…"`, replaces `benign_score_quantiles` with `"score_probs": […1100 values…]`, `"score_quantiles": […]`, adds `"evaluation": {"training_csv_holdout": {"BENIGN": {"rows": 50000, "flagged": 0}}}` (illustrative values), and notes "Models are committed (compressed, `compress=3`)".
  - Offline detection CSV: add rows `source` (`isolation_forest`) and `flow_key` (`TCP|127.0.0.1|60000|127.0.0.1|80`).

- [ ] **Step 3: `docs/API_SPEC.md`**
  - Alert object gains `"source": "rule"`, `"count": 1`, `"last_seen": "2026-10-28T10:15:30.123Z"`.
  - Header bullets: add "Host header must be `localhost` or `127.0.0.1` (TrustedHostMiddleware) → else 400." and "Never `allow_origins=['*']`."
  - `GET /health` response: `{"status": "ok", "model_loaded": true}` with note "`model_loaded` false when no model file is present; the dashboard banner shows it." (Phase 3 gate still checks `status == "ok"`.)
  - `POST /upload-pcap` validation becomes: (1) `Origin` ∈ {`http://localhost:3000`, `http://127.0.0.1:3000`} and header `X-Sentinel-Upload: 1` → else 403; (2) extension; (3) size while streaming; (4) first 4 bytes are a pcap/pcapng magic number → else 400 `{"detail": "Not a pcap/pcapng file"}`; (5) at most 1 running + 2 queued uploads → else 429; (6) parsing runs in a subprocess with memory/CPU limits and a timeout; failures mark the batch `failed`. Filename stored after sanitising to `[A-Za-z0-9._ -]`.
  - `WS /ws/alerts`: "The server closes the connection with code 1008 unless `Origin` is `http://localhost:3000` or `http://127.0.0.1:3000`." and "`alert` messages are rate-capped (aggregated alerts are re-sent with the new `count` at most once per second)."
  - `stats` message gains `"dropped_flows": 0, "dropped_alerts": 0`.

- [ ] **Step 4: `docs/ARCHITECTURE.md`**
  - Detection logic: Isolation Forest bullet mentions "on `log1p` of the features"; severity bullet becomes D6 wording; add bullet "**Port-scan rule** (Phase 1, D2): ≥ 20 distinct (dst_ip, dst_port) from one source within 10 s → one `PortScan` alert per source per 10 s, `source="rule"`, confidence 1.0." Combination bullet: "Random Forest label wins, then the scan rule, then Isolation Forest `anomaly`."
  - Components table: add `backend/detection/scan_rule.py` (1). Flow table row: "driven by packet timestamps; the same table serves offline CLI, PCAP upload and live capture (D5)".
  - Threads: capture uses `store=False` and BPF filter `not port 8000 and not port 3000`; all queues bounded with drop counters; inference batch-predicts per tick.
  - Trust boundary: HTTP/WS row control text replaced with the Host/Origin/upload-header controls from Step 3; upload row adds magic-byte check and subprocess limits; model row: "sha256 verified against the sidecar; `SENTINEL_MODEL_PATH` must resolve under `models/` (Phase 3)".
  - Deployment: `cap_drop: [ALL]`, `cap_add: [NET_RAW]` (no NET_ADMIN), `security_opt: [no-new-privileges:true]`, `read_only: true`, `models/` read-only mount, uvicorn `--host 127.0.0.1`, frontend published as `127.0.0.1:3000:3000`, `.dockerignore` excludes `data/`, `.venv/`, `node_modules/`.

- [ ] **Step 5: `docs/PHASES.md`** — append a "Hardening additions" block to each phase:
  - **Phase 2** deliverables: timestamp-driven flow table shared with `detect_offline.py` (D5); `store=False`; BPF filter excluding ports 8000/3000; bounded flow queue with drop counter; batch predict per tick; non-TCP/UDP flows recorded but not scored. Gate replaces the ping loop with: "On `lo`, a `curl` loop against `python -m http.server` on 127.0.0.1 produces scored flows in near real time; a deliberately overfilled queue logs a warning and the capture thread stays alive; 30 minutes of normal loopback use is recorded and alerts/hour per detector reported in PHASE2_RESULTS.md."
  - **Phase 3** deliverables: D4 aggregation + `source` column; Host/Origin checks; upload header, magic check, subprocess limits, 429 backlog, temp dir wiped at startup, stale batches → `failed`; retention (max 100,000 alerts, oldest deleted); bounded writer/asyncio queues; `SENTINEL_MODEL_PATH` must resolve under `models/`; filename sanitising. Gate adds: "`tests/test_api.py` covers bad Host → 400, bad WS Origin → 1008, upload without header → 403, gzip upload → 400, 1,000 scan probes → 1 aggregated alert."
  - **Phase 4** deliverables: "no model loaded" banner from `/health`; uploaded-batch alerts shown under the batch filter with "capture time" label; no `dangerouslySetInnerHTML` (checked by grep in CI).
  - **Phase 5** deliverables: merge/drop classes with < 100 rows, report support per class; PR-AUC and recall at 1% FPR for all detectors; one extra run holding out one attack family; benchmark loads the committed model files and prints their sha256; RF capped in depth/trees so the compressed file stays small and is committed.
  - **Phase 6** deliverables: target must be an IPv4 literal in 127.0.0.0/8 (no DNS, no IPv6, no `::ffff:` forms), re-checked on every packet, L3 send on `lo` only; floods use one fixed 5-tuple; one pcap per mode committed under `tests/fixtures/` and a test asserting ≥ 1 alert per mode.
  - **Phase 7** deliverables: container hardening from Step 4; actions and base images pinned by SHA/digest; `permissions: contents: read`; `pip install --require-hashes` from a compiled lockfile; `npm ci --ignore-scripts`; CI never uploads `data/` or `models/` as artifacts. Gate adds `docker inspect` capability output and `ss -ltnp` showing 127.0.0.1-only listeners.

- [ ] **Step 6: `docs/LIMITATIONS.md`**
  - Feature approximation: replace the flow-boundary bullet with "CICFlowMeter uses a 120 s flow timeout and ends a flow at the first FIN; SentinelStream uses 5 s idle / 10 s active timeouts and both FINs or any RST, so long flows become chunks the models never saw in training." Add "CICIDS2017 has documented labelling and flow-construction errors (Engelen et al., 2021, 'Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study')." Add "First IP fragments count only their own slice; later fragments are skipped and counted, not reassembled."
  - What it cannot detect: replace the port-scan bullet with "Slow scans (fewer than 20 targets in 10 s) evade the scan rule; random-source-port floods spread over many 1-packet flows evade the Isolation Forest; CICIDS2017 has no SYN-flood or UDP-flood class, so floods can only appear as `anomaly`."
  - Isolation Forest thresholding: replace the severity bullet with D6 wording ("IF-only alerts are `low`, or `medium` above p99.9 of benign scores; never `high`").
  - Add "Scan rule thresholds (20 targets / 10 s) are untuned guesses; the rule can't be benchmarked on CICIDS2017 MachineLearningCSV, which has no IPs or timestamps."
  - Scale and storage: replace with retention (100,000 alerts), bounded queues with drop counters, ≤ 2 s of already-broadcast alerts lost from SQLite on a crash, uploaded PCAP alerts keep their original capture timestamps.
  - Add "Privacy: on a real interface, alerts store IP addresses (personal data in many jurisdictions). Keep `data/` local."

- [ ] **Step 7: `docs/EVALUATION.md`** — datasets row adds citation line: "Sharafaldin, Lashkari, Ghorbani, 'Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization', ICISSP 2018." Metrics table adds `PR-AUC` and `Recall at 1% FPR`. Add section "Not benchmarked: the port-scan rule (needs source IPs and timestamps, absent from MachineLearningCSV); tested on fixtures only." Add "Extra run: hold out one attack family from training." Results template gains columns PR-AUC and Recall@1%FPR.

- [ ] **Step 8: `docs/PRD.md` and `README.md`** — PRD Goal 2 becomes "Combine a cross-flow scan rule, a supervised classifier (named attack types) and an unsupervised anomaly detector; Phase 5 measures whether the combination helps." README "Detection" bullet becomes "a port-scan rule and (Phase 5) a Random Forest that name attack types, plus an Isolation Forest that flags unnamed anomalies"; add a "Citation" section with the EVALUATION citation; Status line "Phase 1 — offline detection (hardened)".

- [ ] **Step 9: Spec deviation** — in the spec's Case 6 row "Model file not tied to sidecar", change "Lands" to "Phase 1 (sha256) / Phase 3 (path under `models/`)".

- [ ] **Step 10: Verify and commit**

```bash
grep -rnE "predict\(\) == -1|names come only|benign_score_quantiles|FIN/RST from both sides" docs README.md AGENTS.md || echo "no stale text"
git add docs README.md AGENTS.md
git commit -m "Docs: hardening decisions D1-D6 and later-phase gates"
```
Expected: `no stale text`.

---

### Task 7: Gate re-run, results, progress

**Files:** `docs/PHASE1_RESULTS.md`, `PROGRESS.md`, `plans/phase-1-PLAN.md`.

- [ ] **Step 1: Gate commands** (capture output to the scratchpad):

```bash
.venv/bin/pytest -q
.venv/bin/python backend/detect_offline.py --pcap tests/fixtures/sample.pcap --out data/phase1_detections.csv
cat data/phase1_detections.csv
grep -rliE "fastapi|react" backend/ tests/ || echo "no FastAPI/React code"
```

- [ ] **Step 2: Clean-clone reproduction** — clone HEAD into the scratchpad, fresh venv from `requirements.txt`, run pytest and the detect command **without** the CICIDS data (the committed model must make this work), `diff` the CSV against the working copy.

- [ ] **Step 3: Rewrite `docs/PHASE1_RESULTS.md`** from the actual outputs: model table (threshold, rows), cross-day flag-rate table copied from the Task 5 Step 5 output (benign FPR per day, flagged share per attack label — reported as measured, no interpretation beyond what the numbers show), sample PCAP table (benign 0/20, scan rule 1 alert, IF flood flagged + its severity), detection CSV verbatim, Reproduce section (no CICIDS needed for detection; needed only to retrain).

- [ ] **Step 4: `PROGRESS.md`** — add a "Phase 1 hardening pass" section: decisions D1–D6 with dates, task checklist, evidence blocks (gate, clean clone, training output), blockers. Update `plans/phase-1-PLAN.md` file table with the new files.

- [ ] **Step 5: Commit**

```bash
git add docs/PHASE1_RESULTS.md PROGRESS.md plans/phase-1-PLAN.md
git commit -m "Phase 1 hardening: gate evidence and results"
```

Push happens only after the human types `phase 1 accepted`.
