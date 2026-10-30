# Phase 3 Plan — API and persistence

## Tasks

1. `backend/db/writer.py`
   - `SCHEMA` (alerts, flows, upload_batches per DATA_MODEL.md, WAL mode, indexes).
   - `AlertAggregator` (D4): same (src_ip, dst_ip, attack_type) with `last_seen` < 30 s → update count/last_seen/max confidence instead of a new alert; bounded memory.
   - `Writer` thread: one long-lived connection, bounded queue with drop counter, upsert batches of 50 or every 2 s, flows row on first detection, retention 100,000 alerts.
2. `backend/api/uploads.py` — `analyse_upload(path, model_path)`: parse + score in a spawned subprocess with `RLIMIT_AS`, `RLIMIT_CPU` and a wall-clock timeout; magic-byte check; filename sanitising; dedicated temp dir.
3. `backend/api/main.py` — `create_app(capture=True)`:
   - Lifespan: schema, stale batches → `failed`, temp dir wiped, writer + upload worker (1 running + 2 queued), live `Pipeline` (if `capture` and a model is present), broadcaster task (alerts + `stats` every 1 s + `batch` messages).
   - `TrustedHostMiddleware` (`localhost`, `127.0.0.1`), CORS for the two dashboard origins only.
   - `GET /health`, `GET /alerts`, `POST /upload-pcap`, `WS /ws/alerts` per API_SPEC.md; bridge `loop.call_soon_threadsafe(...)` into a bounded `asyncio.Queue` with a drop counter.
   - `SENTINEL_MODEL_PATH` must resolve under `models/`; default falls back to the committed Isolation Forest until Phase 5.
4. `backend/detection/detectors.py` — alert rows also carry `src_port`, `dst_port`, `protocol`, `features` (needed by the API and flows table; the offline CSV still selects its 8 columns).
5. `backend/pipeline.py` — keep at most 10,000 alerts in memory (it now runs inside a long-lived server).
6. `tests/test_api.py` and `tests/test_writer.py`.
7. Gate run with `sudo uvicorn backend.api.main:app`, a WebSocket client, a loopback scan and a SQLite query.

## Trimmed (ponytail ultra)

- No per-alert WebSocket rate cap: detectors already emit at most once per flow, and the scan rule once per 10 s per source.
- No SQLModel/ORM: stdlib `sqlite3` as the brief says.

## Files

| Action | Path |
|---|---|
| create | backend/db/__init__.py, backend/db/writer.py, backend/api/__init__.py, backend/api/uploads.py, backend/api/main.py |
| modify | backend/detection/detectors.py, backend/pipeline.py, requirements.txt |
| create | tests/test_writer.py, tests/test_api.py |
| update | PROGRESS.md, docs (if contracts change) |

## Acceptance gate (from docs/PHASES.md)

> `uvicorn backend.api.main:app` starts, `GET /health` returns `{"status":"ok"}`, a WebSocket client receives an alert from loopback traffic, and SQLite holds the same alert.
>
> Gate additions: `tests/test_api.py` also covers bad Host → 400, bad WebSocket Origin → 1008, upload without the header → 403, gzip upload → 400, and 1,000 scan probes → 1 aggregated alert.

## Checks

```bash
.venv/bin/pytest -q
sudo .venv/bin/uvicorn backend.api.main:app --host 127.0.0.1 --port 8000   # human runs (sudo)
curl -s -H 'Host: localhost' http://127.0.0.1:8000/health
.venv/bin/python <ws client with Origin http://localhost:3000>  # waits for an alert
.venv/bin/python <30-port connect scan on 127.0.0.1>
sqlite3 data/sentinelstream.db "select id, attack_type, count from alerts where id = '<id from ws>'"
```
