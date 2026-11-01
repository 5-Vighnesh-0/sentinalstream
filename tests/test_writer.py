import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from backend.db.writer import AlertAggregator, Writer, connect
from backend.detection.detectors import Detectors
from backend.features.extractor import Flow

T0 = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
MODEL = Path(__file__).resolve().parents[1] / "models" / "isolation_forest.joblib"


def row(seconds, attack_type="anomaly", score=0.991, severity="low", src="10.0.0.9"):
    ts = (T0 + timedelta(seconds=seconds)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {"timestamp": ts, "src_ip": src, "dst_ip": "10.0.0.1", "src_port": 40000, "dst_port": 80,
            "protocol": "TCP", "attack_type": attack_type, "score": score, "severity": severity,
            "source": "isolation_forest", "flow_key": f"TCP|{src}|40000|10.0.0.1|80", "features": {"fwd_packets": 1}}


def test_repeats_within_30_s_merge_into_one_alert():
    agg = AlertAggregator()
    first, flow = agg.add(row(0))
    second, no_flow = agg.add(row(20, score=0.9995, severity="medium"))
    assert flow is not None and no_flow is None
    assert second["id"] == first["id"]
    assert (second["count"], second["last_seen"], second["confidence"], second["severity"]) == (2, row(20)["timestamp"], 0.9995, "medium")
    assert second["timestamp"] == row(0)["timestamp"]  # first detection


def test_gap_over_30_s_starts_a_new_alert():
    agg = AlertAggregator()
    assert agg.add(row(0))[0]["id"] != agg.add(row(31))[0]["id"]


def test_upload_batches_never_merge_with_live_alerts():
    agg = AlertAggregator()
    assert agg.add(row(0))[0]["id"] != agg.add(row(1), batch_id=7)[0]["id"]


def test_open_alerts_are_bounded():
    agg = AlertAggregator(max_open=2)
    for i in range(5):
        agg.add(row(0, src=f"10.0.0.{i}"))
    assert len(agg._open) == 2


def test_1000_scan_probes_become_one_alert():
    probes = [Flow("10.0.0.9", "10.0.0.1", 40000, port, "TCP", i * 0.025, i * 0.025) for i, port in enumerate(range(1, 1001))]
    for p in probes:
        p.fwd_packets = 1
    agg = AlertAggregator()
    alerts = {a["id"]: a for a, _ in (agg.add(r) for r in Detectors(MODEL).score(probes) if r["attack_type"] == "PortScan")}
    assert len(alerts) == 1  # the rule fires once per 10 s of the 25 s scan; aggregation merges those


def test_writer_upserts_and_keeps_newest(tmp_path):
    db = tmp_path / "a.db"
    writer = Writer(db, max_alerts=2)
    writer.start()
    agg = AlertAggregator()
    for seconds in (0, 100, 200):
        writer.submit(*agg.add(row(seconds, src=f"10.0.0.{seconds}")))
    updated, _ = agg.add(row(205, src="10.0.0.200"))
    writer.submit(updated, None)
    writer.stop()

    conn = sqlite3.connect(db)
    rows = conn.execute("select src_ip, count from alerts order by timestamp").fetchall()
    assert rows == [("10.0.0.100", 1), ("10.0.0.200", 2)]  # oldest deleted by retention, update applied
    assert conn.execute("select count(*) from flows").fetchone()[0] == 2  # orphaned flow deleted too


def test_existing_database_gains_acknowledged_at_and_keeps_rows(tmp_path):
    db = tmp_path / "old.db"
    agg = AlertAggregator()
    writer = Writer(db)
    writer.start()
    writer.submit(*agg.add(row(0)))
    writer.stop()
    with sqlite3.connect(db) as old:  # make it a database from before the column existed
        old.execute("ALTER TABLE alerts DROP COLUMN acknowledged_at")
    conn = connect(db)
    assert "acknowledged_at" in {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
    assert conn.execute("SELECT src_ip, acknowledged_at FROM alerts").fetchall() == [("10.0.0.9", None)]


def test_a_rule_that_matches_everything_is_refused(tmp_path):
    conn = connect(tmp_path / "a.db")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("INSERT INTO suppressions (created_at) VALUES ('2026-10-29T12:00:00.000Z')")


def test_a_repeat_clears_the_acknowledgement(tmp_path):
    db = tmp_path / "a.db"
    agg = AlertAggregator()
    first, flow = agg.add(row(0))
    writer = Writer(db)
    writer.start()
    writer.submit(first, flow)
    writer.stop()
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE alerts SET acknowledged_at = '2026-10-29T12:00:05.000Z'")
    repeat, _ = agg.add(row(10))
    writer = Writer(db)
    writer.start()
    writer.submit(repeat, None)
    writer.stop()
    assert sqlite3.connect(db).execute("SELECT count, acknowledged_at FROM alerts").fetchone() == (2, None)
