import gzip
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from backend.api import main, uploads

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "sample.pcap"
DASHBOARD = {"origin": "http://localhost:3000"}
UPLOAD_HEADERS = {**DASHBOARD, "x-sentinel-upload": "1"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(uploads, "UPLOAD_DIR", tmp_path / "uploads")
    with TestClient(main.create_app(capture=False), base_url="http://localhost") as c:
        yield c


def row(seconds, attack_type="anomaly", src="10.0.0.9"):
    return {"timestamp": f"2026-10-29T12:00:{seconds:02d}.000Z", "src_ip": src, "dst_ip": "10.0.0.1",
            "src_port": 40000, "dst_port": 80, "protocol": "TCP", "attack_type": attack_type, "score": 0.991,
            "severity": "low", "source": "isolation_forest", "flow_key": f"TCP|{src}|40000|10.0.0.1|80", "features": {}}


def wait_for(fn, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if result := fn():
            return result
        time.sleep(0.2)
    raise AssertionError("condition not met in time")


def test_health(client):
    assert client.get("/health").json() == {"status": "ok", "model_loaded": True}


def test_unknown_host_rejected(client):
    assert client.get("/health", headers={"host": "evil.example"}).status_code == 400


def test_alerts_query_filters_and_paginates(client):
    hub = client.app.state.hub
    hub.publish(row(0, src="10.0.0.1"))
    hub.publish(row(1, attack_type="PortScan", src="10.0.0.2"))
    hub.publish(row(2, src="10.0.0.3"))
    wait_for(lambda: client.get("/alerts").json()["total"] == 3)

    page = client.get("/alerts", params={"limit": 2}).json()
    assert (page["total"], len(page["items"]), page["items"][0]["src_ip"]) == (3, 2, "10.0.0.3")  # newest first
    assert client.get("/alerts", params={"attack_type": "PortScan"}).json()["total"] == 1
    assert client.get("/alerts", params={"severity": "critical"}).status_code == 422
    assert client.get("/alerts", params={"limit": 0}).status_code == 422


def test_websocket_rejects_foreign_origin(client):
    with pytest.raises(WebSocketDisconnect) as e:
        with client.websocket_connect("ws://localhost/ws/alerts", headers={"origin": "http://evil.example"}) as ws:
            ws.receive_json()
    assert e.value.code == 1008


def test_websocket_receives_alert_published_from_another_thread(client):
    with client.websocket_connect("ws://localhost/ws/alerts", headers=DASHBOARD) as ws:
        threading.Thread(target=client.app.state.hub.publish, args=(row(5),)).start()
        message = ws.receive_json()
        while message["type"] != "alert":
            message = ws.receive_json()
    assert (message["data"]["src_ip"], message["data"]["count"]) == ("10.0.0.9", 1)


def test_upload_needs_dashboard_origin_and_header(client):
    files = {"file": ("x.pcap", SAMPLE.read_bytes())}
    assert client.post("/upload-pcap", files=files).status_code == 403
    assert client.post("/upload-pcap", files=files, headers=DASHBOARD).status_code == 403


def test_upload_rejects_bad_extension_gzip_and_oversize(client, monkeypatch):
    post = lambda name, data: client.post("/upload-pcap", files={"file": (name, data)}, headers=UPLOAD_HEADERS)  # noqa: E731
    assert post("x.txt", SAMPLE.read_bytes()).status_code == 400
    assert post("x.pcap", gzip.compress(SAMPLE.read_bytes())).status_code == 400
    monkeypatch.setattr(uploads, "MAX_UPLOAD_BYTES", 1000)
    assert post("x.pcap", SAMPLE.read_bytes()).status_code == 413


def test_upload_is_analysed_into_its_own_batch(client):
    response = client.post("/upload-pcap", files={"file": ("../../etc/passwd\nx.pcap", SAMPLE.read_bytes())},
                           headers=UPLOAD_HEADERS)
    assert response.status_code == 202
    batch_id = response.json()["batch_id"]
    alerts = wait_for(lambda: (items := client.get("/alerts", params={"batch_id": batch_id}).json()["items"])
                      and len(items) == 2 and items)
    assert sorted(a["source"] for a in alerts) == ["isolation_forest", "rule"]
    assert list(uploads.UPLOAD_DIR.iterdir()) == []  # temp file removed


def test_upload_backlog_full_returns_429(client, monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(main, "analyse_upload", lambda path, model: release.wait(10) and [])
    post = lambda: client.post("/upload-pcap", files={"file": ("x.pcap", SAMPLE.read_bytes())}, headers=UPLOAD_HEADERS)  # noqa: E731
    assert post().status_code == 202
    wait_for(lambda: client.app.state.uploads.empty())  # the worker is busy with the first upload
    assert [post().status_code for _ in range(3)] == [202, 202, 429]
    release.set()


def test_model_path_outside_models_dir_refused(monkeypatch, tmp_path):
    monkeypatch.setenv("SENTINEL_MODEL_PATH", str(tmp_path / "evil.joblib"))
    with pytest.raises(ValueError, match="must be under"):
        main.create_app(capture=False)
