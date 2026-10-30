"""SQLite persistence: schema, alert aggregation (D4) and the batched writer thread."""
import json
import logging
import queue
import sqlite3
import threading
import time
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger(__name__)

SCHEMA = """
CREATE TABLE IF NOT EXISTS upload_batches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'processing', 'done', 'failed'))
);
CREATE TABLE IF NOT EXISTS flows (
    id TEXT PRIMARY KEY,
    flow_key TEXT NOT NULL,
    feature_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    src_port INTEGER NOT NULL,
    dst_port INTEGER NOT NULL,
    protocol TEXT NOT NULL CHECK (protocol IN ('TCP', 'UDP', 'ICMP', 'OTHER')),
    attack_type TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high')),
    source TEXT NOT NULL CHECK (source IN ('rule', 'random_forest', 'isolation_forest')),
    count INTEGER NOT NULL DEFAULT 1,
    last_seen TEXT NOT NULL,
    batch_id INTEGER REFERENCES upload_batches(id),
    flow_id TEXT REFERENCES flows(id)
);
CREATE INDEX IF NOT EXISTS alerts_timestamp ON alerts (timestamp DESC);
CREATE INDEX IF NOT EXISTS alerts_severity ON alerts (severity);
CREATE INDEX IF NOT EXISTS alerts_attack_type ON alerts (attack_type);
CREATE INDEX IF NOT EXISTS alerts_batch_id ON alerts (batch_id);
CREATE INDEX IF NOT EXISTS flows_flow_key ON flows (flow_key);
"""
ALERT_FIELDS = ["id", "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "attack_type",
                "confidence", "severity", "source", "count", "last_seen", "batch_id", "flow_id"]
AGGREGATE_WINDOW_S = 30.0
BATCH_SIZE = 50
BATCH_EVERY_S = 2.0
MAX_ALERTS = 100_000


def connect(db_path) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL")  # API reads don't block the writer
    conn.executescript(SCHEMA)
    return conn


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AlertAggregator:
    """D4: a detection matching an open alert (same batch, src_ip, dst_ip, attack_type, last seen < 30 s ago)
    updates it instead of creating a new one, so one scan or one noisy stream is one alert with a count."""

    def __init__(self, window_s: float = AGGREGATE_WINDOW_S, max_open: int = 10_000):
        self.window_s = window_s
        self.max_open = max_open
        self._open: OrderedDict[tuple, dict] = OrderedDict()  # least recently updated first

    def add(self, row: dict, batch_id: int | None = None) -> tuple[dict, dict | None]:
        """Return (alert, flow): flow is the flows-table row for a new alert, None when an open alert was updated."""
        ts = datetime.fromisoformat(row["timestamp"]).timestamp()
        key = (batch_id, row["src_ip"], row["dst_ip"], row["attack_type"])
        alert = self._open.pop(key, None)
        if alert is not None and ts - alert["_last_ts"] < self.window_s:
            alert["count"] += 1
            if ts > alert["_last_ts"]:
                alert["_last_ts"], alert["last_seen"] = ts, row["timestamp"]
            if row["score"] > alert["confidence"]:  # severity follows the strongest detection
                alert["confidence"], alert["severity"] = row["score"], row["severity"]
            self._open[key] = alert
            return _public(alert), None
        flow = {"id": uuid.uuid4().hex, "flow_key": row["flow_key"],
                "feature_json": json.dumps(row["features"]), "created_at": now_iso()}
        alert = {
            "id": uuid.uuid4().hex, "timestamp": row["timestamp"], "src_ip": row["src_ip"], "dst_ip": row["dst_ip"],
            "src_port": row["src_port"], "dst_port": row["dst_port"], "protocol": row["protocol"],
            "attack_type": row["attack_type"], "confidence": row["score"], "severity": row["severity"],
            "source": row["source"], "count": 1, "last_seen": row["timestamp"], "batch_id": batch_id,
            "flow_id": flow["id"], "_last_ts": ts,
        }
        self._open[key] = alert
        if len(self._open) > self.max_open:
            self._open.popitem(last=False)
        return _public(alert), flow


def _public(alert: dict) -> dict:
    return {k: alert[k] for k in ALERT_FIELDS}


class Writer(threading.Thread):
    """The only thread that writes alerts: one long-lived connection, upserts batched by 50 or every 2 s."""

    _STOP = object()

    def __init__(self, db_path, queue_size: int = 10_000, max_alerts: int = MAX_ALERTS):
        super().__init__(name="db-writer", daemon=True)
        self.db_path = db_path
        self.max_alerts = max_alerts
        self.queue: queue.Queue = queue.Queue(maxsize=queue_size)
        self.dropped = 0

    def submit(self, alert: dict, flow: dict | None) -> None:
        try:
            self.queue.put_nowait((alert, flow))
        except queue.Full:
            self.dropped += 1
            log.warning("writer queue full: dropped %d alerts so far", self.dropped)

    def stop(self) -> None:
        self.queue.put(self._STOP)
        self.join()

    def run(self) -> None:
        conn = connect(self.db_path)
        pending: list = []
        deadline = time.monotonic() + BATCH_EVERY_S
        while True:
            try:
                item = self.queue.get(timeout=max(deadline - time.monotonic(), 0))
            except queue.Empty:
                item = None
            if item is self._STOP:
                self._flush(conn, pending)
                conn.close()
                return
            if item is not None:
                pending.append(item)
            if len(pending) >= BATCH_SIZE or time.monotonic() >= deadline:
                self._flush(conn, pending)
                pending = []
                deadline = time.monotonic() + BATCH_EVERY_S

    def _flush(self, conn: sqlite3.Connection, pending: list) -> None:
        if not pending:
            return
        with conn:
            conn.executemany("INSERT INTO flows VALUES (:id, :flow_key, :feature_json, :created_at)",
                             [flow for _, flow in pending if flow is not None])
            conn.executemany(
                f"INSERT INTO alerts ({', '.join(ALERT_FIELDS)}) VALUES ({', '.join(':' + f for f in ALERT_FIELDS)}) "
                "ON CONFLICT(id) DO UPDATE SET count = excluded.count, last_seen = excluded.last_seen, "
                "confidence = excluded.confidence, severity = excluded.severity",
                [alert for alert, _ in pending],
            )
            conn.execute("DELETE FROM alerts WHERE id IN (SELECT id FROM alerts ORDER BY timestamp "
                         "LIMIT MAX((SELECT COUNT(*) FROM alerts) - ?, 0))", (self.max_alerts,))
            conn.execute("DELETE FROM flows WHERE id NOT IN (SELECT flow_id FROM alerts WHERE flow_id IS NOT NULL)")
