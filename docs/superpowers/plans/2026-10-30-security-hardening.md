# Security Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the six open risks in `docs/superpowers/specs/2026-10-29-security-hardening-design.md`: root API, unauthenticated API, swappable pickled models, missing browser headers, world-readable data, unlimited WebSocket clients.

**Architecture:** A small `backend/api/auth.py` owns the dashboard token; `create_app` sets the umask, warns when run as root, checks the token on `/alerts`, `/upload-pcap` and the WebSocket (as a subprotocol), and caps WebSocket clients. Model trust is an allowlist in `feature_set.py`. The upload child empties its capability sets before parsing. The dashboard keeps the token in `localStorage` and shows a paste form when it is missing or rejected. Nginx adds the security headers.

**Tech Stack:** Python 3.12 (stdlib `secrets`, `ctypes`), FastAPI/Starlette, React 18 + Vitest, Nginx. No new dependencies.

## Global Constraints

- No new dependencies (AGENTS.md approved list only).
- Token: `secrets.token_urlsafe(32)`, file `<parent of SENTINEL_DB_PATH>/api-token`, mode 600, reused across restarts, rotated by deleting the file; compared with `secrets.compare_digest`.
- REST: `GET /alerts`, `POST /upload-pcap` need `Authorization: Bearer <token>` → else **401** `{"detail": "Missing or wrong dashboard token"}`. `GET /health` stays open.
- WebSocket: client offers subprotocols `["sentinelstream", <token>]`; server accepts with subprotocol `sentinelstream`; wrong/missing token or Origin → close **1008**; more than 20 clients → close **1013**.
- Trusted model hashes: `bb2cd31c1e40f45ef07622b5a1771fa1b429920c6f7ebcaa4db3e6d9346c7025` (random_forest), `df1aaacc4d8a73b375571d3505e7b6185b1827c947dff26f625a59f7766c9d92` (isolation_forest).
- Backend process `os.umask(0o077)`.
- Nginx CSP exactly: `default-src 'self'; connect-src 'self' http://127.0.0.1:8000 ws://127.0.0.1:8000; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`; plus `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. Vite dev/preview: same minus CSP.
- Never put the token in a URL or in a reply to the user.
- Commands run from the repo root with `.venv/bin/...`.

## Deviation from the spec

The spec has the dashboard show the token form "after any 401 or a 1008 close". A browser never sees 1008 here: a WebSocket refused before the handshake surfaces as close code 1006, the same as "backend down". So a bad token is detected through the REST 401 from `GET /alerts`, which the dashboard calls on every (re)connect; the WebSocket keeps its normal backoff. Task 6 records this in API_SPEC.md.

## File map

| File | Change |
|---|---|
| `backend/features/feature_set.py` | `TRUSTED_MODEL_SHA256`, `load_model(..., trusted=...)` |
| `backend/ml/train_supervised.py`, `backend/ml/train_baseline.py` | print the pin line after saving |
| `backend/api/uploads.py` | `drop_capabilities()`, called first in the child |
| `backend/api/auth.py` | new: token file, bearer/subprotocol parsing, constant-time match |
| `backend/api/main.py` | umask, root warning, token printout, `require_token`, CORS header, WebSocket token + cap |
| `frontend/src/token.ts`, `frontend/src/components/TokenForm.tsx` | new |
| `frontend/src/useWebSocket.ts`, `frontend/src/App.tsx`, `frontend/src/components/PCAPUpload.tsx` | send the token, show the form |
| `frontend/nginx.conf`, `frontend/vite.config.js` | headers |
| tests: `tests/test_features.py`, `tests/test_uploads.py` (new), `tests/test_api.py`, `frontend/src/useWebSocket.test.tsx`, `frontend/src/App.test.tsx` | |
| docs: API_SPEC, DEMO, README, ARCHITECTURE, LIMITATIONS, PROGRESS | |

---

### Task 1: Model hash pins

**Files:** Modify `backend/features/feature_set.py`, `backend/ml/train_supervised.py`, `backend/ml/train_baseline.py`; Test `tests/test_features.py`

**Interfaces:** Produces `TRUSTED_MODEL_SHA256: frozenset[str]`; `load_model(model_path, trusted=TRUSTED_MODEL_SHA256) -> (model, meta)` raising `ValueError` containing `"not a trusted model"`.

- [ ] **Step 1: Failing tests** — in `tests/test_features.py`, add `file_sha256, TRUSTED_MODEL_SHA256` to the `feature_set` import and add:

```python
REPO = Path(__file__).resolve().parents[1]


def test_untrusted_model_refused_before_unpickling(tmp_path):
    path = tmp_path / "m.joblib"
    save_model({"dummy": True}, path)
    with pytest.raises(ValueError, match="not a trusted model"):
        load_model(path)


def test_committed_models_are_pinned():
    for name in ("random_forest", "isolation_forest"):
        sha = json.loads((REPO / "models" / f"{name}.features.json").read_text())["sha256"]
        assert sha in TRUSTED_MODEL_SHA256, f"{name}: retrained? paste its pin into TRUSTED_MODEL_SHA256"
```

Add `import json`. In the three existing tests that load a throwaway model (`test_load_model_rejects_wrong_feature_order` twice, `test_load_model_rejects_tampered_file`), pass `trusted={file_sha256(path)}` to each `load_model(path)` call, computed right after `save_model` (before tampering).

- [ ] **Step 2:** `.venv/bin/pytest tests/test_features.py -q` → FAIL (`ImportError: TRUSTED_MODEL_SHA256`).

- [ ] **Step 3: Implement** in `backend/features/feature_set.py` (after `ANOMALY_MEDIUM`):

```python
# Models are pickles, which run code when loaded: load_model refuses any file not listed here.
# After retraining, the trainers print the line to paste in.
TRUSTED_MODEL_SHA256 = frozenset({
    "bb2cd31c1e40f45ef07622b5a1771fa1b429920c6f7ebcaa4db3e6d9346c7025",  # models/random_forest.joblib
    "df1aaacc4d8a73b375571d3505e7b6185b1827c947dff26f625a59f7766c9d92",  # models/isolation_forest.joblib
})
```

and replace `load_model` with:

```python
def load_model(model_path, trusted=TRUSTED_MODEL_SHA256):
    """Load a model this repo trained: pinned hash, matching sidecar, matching feature order."""
    meta = json.loads(sidecar_path(model_path).read_text())
    if meta["feature_order"] != FEATURES:
        raise ValueError(f"{model_path}: feature order {meta['feature_order']} does not match {FEATURES}")
    sha = file_sha256(model_path)
    if meta.get("sha256") != sha:
        raise ValueError(f"{model_path}: file does not match the sha256 in its sidecar")
    if sha not in trusted:
        raise ValueError(f"{model_path}: not a trusted model (sha256 {sha}); "
                         "add it to TRUSTED_MODEL_SHA256 in backend/features/feature_set.py after retraining")
    return joblib.load(model_path), meta
```

Trainers — after each `save_model(...)` call add a print of the pin. In `train_supervised.py` after the RF save and after the IF save:

```python
    print(f'pin for TRUSTED_MODEL_SHA256: "{file_sha256(RF_OUT)}",  # {RF_OUT}')
```

```python
    print(f'pin for TRUSTED_MODEL_SHA256: "{file_sha256(IF_OUT)}",  # {IF_OUT}')
```

and in `train_baseline.py` after its `save_model(...)`:

```python
    print(f'pin for TRUSTED_MODEL_SHA256: "{file_sha256(args.out)}",  # {args.out}')
```

(import `file_sha256` from `backend.features.feature_set` in both.)

- [ ] **Step 4:** `.venv/bin/pytest -q` → all pass (callers of `load_model` use the committed, pinned models).
- [ ] **Step 5:** `git commit -am "Pin trusted model hashes; refuse other pickles before loading"`

---

### Task 2: Least privilege — upload child drops capabilities, root warning

**Files:** Modify `backend/api/uploads.py`, `backend/api/main.py`; Create `tests/test_uploads.py`

**Interfaces:** Produces `drop_capabilities() -> None` (raises `OSError` on failure).

- [ ] **Step 1: Failing tests** — `tests/test_uploads.py`:

```python
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


def test_drop_capabilities_empties_every_set():
    code = ("from backend.api.uploads import drop_capabilities; drop_capabilities(); "
            "print(open('/proc/self/status').read())")
    status = subprocess.run([sys.executable, "-c", code], cwd=REPO, capture_output=True, text=True, check=True).stdout
    caps = dict(line.split(":\t") for line in status.splitlines() if line.startswith("Cap"))
    assert int(caps["CapEff"], 16) == int(caps["CapPrm"], 16) == int(caps["CapAmb"], 16) == 0
```

and in `tests/test_api.py`:

```python
def test_root_outside_a_container_is_warned(monkeypatch, tmp_path, caplog):
    monkeypatch.setenv("SENTINEL_DB_PATH", str(tmp_path / "t.db"))
    monkeypatch.setattr(main.os, "geteuid", lambda: 0)
    main.create_app(capture=False)
    assert "running as root" in caplog.text
```

- [ ] **Step 2:** `.venv/bin/pytest tests/test_uploads.py tests/test_api.py -q -k "capabilities or root"` → FAIL.

- [ ] **Step 3: Implement** — `backend/api/uploads.py`: add `import ctypes` and `import ctypes.util`, then:

```python
PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL = 47, 4  # linux/prctl.h
_CAP_VERSION_3 = 0x20080522  # linux/capability.h


class _CapHeader(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]


class _CapData(ctypes.Structure):
    _fields_ = [("effective", ctypes.c_uint32), ("permitted", ctypes.c_uint32), ("inheritable", ctypes.c_uint32)]


def drop_capabilities() -> None:
    """Empty this process's capability sets (dropping needs no privilege): the parser must not keep CAP_NET_RAW."""
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    if libc.prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_CAP_AMBIENT_CLEAR_ALL) failed")
    if libc.capset(ctypes.byref(_CapHeader(_CAP_VERSION_3, 0)), (_CapData * 2)()) != 0:
        raise OSError(ctypes.get_errno(), "capset failed")
```

In `_child`, move the two `setrlimit` calls inside the `try:` and call `drop_capabilities()` first, so a failed drop is reported and the upload fails closed:

```python
def _child(path: str, model_path: str, out) -> None:
    try:
        drop_capabilities()
        resource.setrlimit(resource.RLIMIT_AS, (CHILD_MEMORY_BYTES, CHILD_MEMORY_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (CHILD_CPU_S, CHILD_CPU_S))
        from backend.detection.detectors import Detectors  # imported after the limits apply
        from backend.features.flow_table import flows_from_pcap

        flows, _ = flows_from_pcap(path)
        out.put(("ok", Detectors(model_path).score(flows)))
    except BaseException as e:  # noqa: BLE001 - MemoryError and parser crashes included: report, don't hang the parent
        out.put(("error", f"{type(e).__name__}: {e}"))
```

`backend/api/main.py`, first lines of `create_app`:

```python
    if os.geteuid() == 0 and not Path("/.dockerenv").exists():
        log.warning("running as root: start uvicorn with only CAP_NET_RAW instead (see docs/DEMO.md)")
```

- [ ] **Step 4:** `.venv/bin/pytest -q` → all pass.
- [ ] **Step 5:** `git commit -am "Upload parser drops all capabilities; warn when the API runs as root"`

---

### Task 3: API token, owner-only files, WebSocket cap

**Files:** Create `backend/api/auth.py`; Modify `backend/api/main.py`; Test `tests/test_api.py`

**Interfaces:** Consumes nothing new. Produces `auth.SUBPROTOCOL = "sentinelstream"`, `auth.TOKEN_FILE = "api-token"`, `load_or_create_token(data_dir: Path) -> str`, `matches(expected: str, presented: str | None) -> bool`, `from_bearer(header) -> str | None`, `from_subprotocols(header) -> str | None`; `app.state.token`; `main.MAX_WS_CLIENTS = 20`.

- [ ] **Step 1: Failing tests** — `tests/test_api.py`. Change the `client` fixture so existing tests carry the token, and add `TOKEN_PROTOCOL` for WebSocket calls:

```python
@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(uploads, "UPLOAD_DIR", tmp_path / "uploads")
    with TestClient(main.create_app(capture=False), base_url="http://localhost") as c:
        c.headers["Authorization"] = f"Bearer {c.app.state.token}"
        yield c


def ws(client, origin="http://localhost:3000", token=None):
    token = client.app.state.token if token is None else token
    protocols = ["sentinelstream", token] if token else []
    return client.websocket_connect("ws://localhost/ws/alerts", headers={"origin": origin}, subprotocols=protocols)
```

Replace the two existing `client.websocket_connect(...)` calls with `ws(client)` / `ws(client, origin="http://evil.example")`. Add:

```python
def test_alerts_and_upload_need_the_token(client):
    assert client.get("/alerts", headers={"Authorization": ""}).status_code == 401
    assert client.get("/alerts", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/health", headers={"Authorization": ""}).status_code == 200
    files = {"file": ("x.pcap", SAMPLE.read_bytes())}
    assert client.post("/upload-pcap", files=files, headers={**UPLOAD_HEADERS, "Authorization": ""}).status_code == 401


def test_websocket_needs_the_token_as_subprotocol(client):
    for token in ("", "wrong"):
        with pytest.raises(WebSocketDisconnect) as e, ws(client, token=token) as s:
            s.receive_json()
        assert e.value.code == 1008
    with ws(client) as s:
        assert s.accepted_subprotocol == "sentinelstream"


def test_websocket_clients_are_capped(client, monkeypatch):
    monkeypatch.setattr(main, "MAX_WS_CLIENTS", 1)
    with ws(client):
        with pytest.raises(WebSocketDisconnect) as e, ws(client) as second:
            second.receive_json()
        assert e.value.code == 1013


def test_token_file_is_owner_only_reused_and_rotatable(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_DB_PATH", str(tmp_path / "data" / "t.db"))
    first = main.create_app(capture=False).state.token
    token_file = tmp_path / "data" / "api-token"
    assert token_file.stat().st_mode & 0o777 == 0o600
    assert main.create_app(capture=False).state.token == first
    token_file.unlink()
    assert main.create_app(capture=False).state.token != first
```

- [ ] **Step 2:** `.venv/bin/pytest tests/test_api.py -q` → FAIL (`app.state.token` missing).

- [ ] **Step 3: Implement** — `backend/api/auth.py`:

```python
"""Dashboard token: one random secret in the data directory, required by the REST API and the WebSocket."""
import os
import secrets
from pathlib import Path

TOKEN_FILE = "api-token"
SUBPROTOCOL = "sentinelstream"


def load_or_create_token(data_dir: Path) -> str:
    """Reuse the token across restarts; delete the file to rotate it."""
    path = data_dir / TOKEN_FILE
    data_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.exists() and (token := path.read_text().strip()):
        return token
    token = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token)
    return token


def matches(expected: str, presented: str | None) -> bool:
    return presented is not None and secrets.compare_digest(expected.encode(), presented.encode())


def from_bearer(header: str | None) -> str | None:
    return header[len("Bearer "):] if header and header.startswith("Bearer ") else None


def from_subprotocols(header: str | None) -> str | None:
    """Browsers can't set WebSocket headers, so the client offers ["sentinelstream", <token>] as subprotocols."""
    parts = [p.strip() for p in (header or "").split(",")]
    return parts[1] if len(parts) == 2 and parts[0] == SUBPROTOCOL else None
```

`backend/api/main.py`:
- imports: add `import sys`, `Depends` to the fastapi import, and `from backend.api.auth import SUBPROTOCOL, TOKEN_FILE, from_bearer, from_subprotocols, load_or_create_token, matches`.
- constant: `MAX_WS_CLIENTS = 20`.
- `create_app` begins (the Task 2 warning stays right after the umask):

```python
def create_app(capture: bool = True) -> FastAPI:
    os.umask(0o077)  # data/, the database and the token file are owner-only
    if os.geteuid() == 0 and not Path("/.dockerenv").exists():
        log.warning("running as root: start uvicorn with only CAP_NET_RAW instead (see docs/DEMO.md)")
    db_path = repo_path("SENTINEL_DB_PATH", "data/sentinelstream.db")
    token = load_or_create_token(db_path.parent)
    # stderr, not logging: uvicorn's default config would hide an INFO line from this logger.
    print(f"Dashboard token: {token} (stored in {db_path.parent / TOKEN_FILE}; delete the file to rotate it)",
          file=sys.stderr, flush=True)
```

- after `upload_lock = threading.Lock()`:

```python
    def require_token(authorization: Annotated[str | None, Header()] = None) -> None:
        if not matches(token, from_bearer(authorization)):
            raise HTTPException(401, "Missing or wrong dashboard token")
```

- `app.state.token = token`; CORS `allow_headers=["X-Sentinel-Upload", "Authorization"]`.
- decorators: `@app.get("/alerts", dependencies=[Depends(require_token)])`, `@app.post("/upload-pcap", status_code=202, dependencies=[Depends(require_token)])`.
- WebSocket handler start:

```python
    @app.websocket("/ws/alerts")
    async def ws_alerts(websocket: WebSocket) -> None:
        offered = from_subprotocols(websocket.headers.get("sec-websocket-protocol"))
        # CORS doesn't cover WebSockets, and browsers can only send the token as a subprotocol.
        if websocket.headers.get("origin") not in ALLOWED_ORIGINS or not matches(token, offered):
            await websocket.close(code=1008)
            return
        if len(hub.clients) >= MAX_WS_CLIENTS:
            await websocket.close(code=1013)
            return
        await websocket.accept(subprotocol=SUBPROTOCOL)
```

- [ ] **Step 4:** `.venv/bin/pytest -q` and `.venv/bin/ruff check backend tests simulator` → pass.
- [ ] **Step 5:** `git commit -am "Dashboard token for REST and WebSocket; owner-only data files; cap WebSocket clients"`

---

### Task 4: Dashboard sends the token

**Files:** Create `frontend/src/token.ts`, `frontend/src/components/TokenForm.tsx`; Modify `frontend/src/useWebSocket.ts`, `frontend/src/App.tsx`, `frontend/src/components/PCAPUpload.tsx`; Test `frontend/src/useWebSocket.test.tsx`, `frontend/src/App.test.tsx`

**Interfaces:** `loadToken(): string`, `saveToken(token: string): void`, `authHeader(token) -> {Authorization}`; `useWebSocket(url: string | null, handlers, protocols?: string[])` (no socket while `url` is null); `TokenForm({ onSave, rejected })`; `PCAPUpload` gains prop `token: string` and `onRejected: () => void`.

- [ ] **Step 1: Failing tests** — `frontend/src/useWebSocket.test.tsx`: give `FakeSocket` a `protocols` field set from a second constructor argument, then add:

```tsx
test("no socket while the url is null; protocols are offered", () => {
  const { rerender } = renderHook(({ url }) => useWebSocket(url, { onMessage: () => {} }, ["sentinelstream", "t0k"]), {
    initialProps: { url: null as string | null },
  });
  expect(FakeSocket.instances).toHaveLength(0);
  rerender({ url: "ws://test" });
  expect(latest().protocols).toEqual(["sentinelstream", "t0k"]);
});
```

`frontend/src/App.test.tsx` — add:

```tsx
import { render, screen, waitFor, act } from "@testing-library/react";
import { afterEach, beforeEach, vi } from "vitest";
import App from "./App";

class FakeWS {
  static last: FakeWS;
  protocols: string[];
  onopen?: () => void;
  onmessage?: (e: { data: string }) => void;
  onclose?: () => void;
  constructor(_url: string, protocols: string[]) {
    this.protocols = protocols;
    FakeWS.last = this;
  }
  close() {}
}

beforeEach(() => {
  localStorage.clear();
  vi.stubGlobal("WebSocket", FakeWS);
});
afterEach(() => vi.unstubAllGlobals());

test("asks for the token when none is stored", () => {
  vi.stubGlobal("fetch", vi.fn());
  render(<App />);
  expect(screen.getByText("Paste the dashboard token")).toBeTruthy();
});

test("sends the stored token to the WebSocket and the REST API", async () => {
  localStorage.setItem("sentinelstream.token", "t0k");
  const fetchMock = vi.fn().mockResolvedValue({ status: 200, ok: true, json: async () => ({ items: [], model_loaded: true }) });
  vi.stubGlobal("fetch", fetchMock);
  render(<App />);
  expect(FakeWS.last.protocols).toEqual(["sentinelstream", "t0k"]);
  act(() => FakeWS.last.onopen?.());
  await waitFor(() => expect(fetchMock.mock.calls.some(([url, init]) => String(url).includes("/alerts") && init?.headers?.Authorization === "Bearer t0k")).toBe(true));
});

test("a 401 brings back the token form", async () => {
  localStorage.setItem("sentinelstream.token", "old");
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ status: 401, ok: false, json: async () => ({}) }));
  render(<App />);
  act(() => FakeWS.last.onopen?.());
  await waitFor(() => expect(screen.getByText(/rejected that token/)).toBeTruthy());
});
```

- [ ] **Step 2:** `npm --prefix frontend test` → FAIL.

- [ ] **Step 3: Implement.**

`frontend/src/token.ts`:

```ts
const KEY = "sentinelstream.token";

// Per-browser convenience only: if storage is unavailable the dashboard simply asks again.
export function loadToken(): string {
  try {
    return localStorage.getItem(KEY) ?? "";
  } catch {
    return "";
  }
}

export function saveToken(token: string): void {
  try {
    localStorage.setItem(KEY, token);
  } catch {
    // ask again next time
  }
}

export const authHeader = (token: string) => ({ Authorization: `Bearer ${token}` });
```

`frontend/src/components/TokenForm.tsx`:

```tsx
import { useState } from "react";

export default function TokenForm({ onSave, rejected }: { onSave: (token: string) => void; rejected: boolean }) {
  const [value, setValue] = useState("");
  return (
    <section className="rounded-lg border border-hairline bg-surface p-4">
      <h2 className="text-lg font-semibold">Paste the dashboard token</h2>
      <p className="mt-1 text-sm text-muted">
        {rejected && "The backend rejected that token. "}
        The backend prints it when it starts and keeps it in data/api-token (with Docker: docker compose logs backend).
      </p>
      <form
        className="mt-3 flex gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (value.trim()) onSave(value.trim());
        }}
      >
        <label className="sr-only" htmlFor="dashboard-token">Dashboard token</label>
        <input
          id="dashboard-token"
          type="password"
          autoComplete="off"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          className="min-w-0 flex-1 rounded border border-hairline px-2 py-1 text-sm"
        />
        <button type="submit" className="rounded bg-ink px-3 py-1.5 text-sm text-white">Save</button>
      </form>
    </section>
  );
}
```

`frontend/src/useWebSocket.ts`: signature `useWebSocket(url: string | null, handlers: Handlers, protocols: string[] = [])`; at the top of the effect `if (url === null) return;`; `socket = new WebSocket(url, protocols);`; effect deps `[url, protocols.join(",")]`; in the cleanup guard `socket?.close()` (`let socket: WebSocket | undefined`).

`frontend/src/App.tsx`:
- imports: `TokenForm`, `{ authHeader, loadToken, saveToken } from "./token"`.
- state: `const [token, setToken] = useState(loadToken);` and `const [rejected, setRejected] = useState(false);`
- `loadAlerts`:

```tsx
  const loadAlerts = useCallback(async (batchId: number | null) => {
    const query = batchId === null ? "limit=200" : `limit=500&batch_id=${batchId}`;
    try {
      const response = await fetch(`${API_URL}/alerts?${query}`, { headers: authHeader(token) });
      if (response.status === 401) {
        setRejected(true);
        return;
      }
      const page = await response.json();
      setAlerts((prev) => upsert(prev, page.items));
    } catch {
      // the connection banner already says the backend is unreachable
    }
  }, [token]);
```

- socket: `const status = useWebSocket(token && !rejected ? WS_URL : null, { onMessage, onOpen }, ["sentinelstream", token]);`
- save handler: `function saveNewToken(t: string) { saveToken(t); setToken(t); setRejected(false); }`
- render: inside the grid's left column, replace `<AlertFeed .../>` (and its View label) with `{!token || rejected ? <TokenForm onSave={saveNewToken} rejected={rejected} /> : (<>…existing View label and AlertFeed…</>)}`; pass `token={token}` and `onRejected={() => setRejected(true)}` to `PCAPUpload`.

`frontend/src/components/PCAPUpload.tsx`: props add `token: string; onRejected: () => void`; fetch headers `{ ...authHeader(token), "X-Sentinel-Upload": "1" }`; before the generic error handling: `if (response.status === 401) { onRejected(); setError("The backend rejected the dashboard token."); return; }` (import `authHeader`).

- [ ] **Step 4:** `npm --prefix frontend test` and `npm --prefix frontend run build` → pass; `grep -rn dangerouslySetInnerHTML frontend/src` → nothing.
- [ ] **Step 5:** `git add frontend/src && git commit -m "Dashboard asks for the token once and sends it to REST and the WebSocket"`

---

### Task 5: Browser security headers

**Files:** Modify `frontend/nginx.conf`, `frontend/vite.config.js`

- [ ] **Step 1:** `frontend/nginx.conf`:

```nginx
server {
    listen 3000;
    root /usr/share/nginx/html;

    add_header Content-Security-Policy "default-src 'self'; connect-src 'self' http://127.0.0.1:8000 ws://127.0.0.1:8000; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer" always;

    location / {
        try_files $uri /index.html;
    }
}
```

`frontend/vite.config.js`: add `const headers = { "X-Frame-Options": "DENY", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" }; // no CSP in dev: hot reload needs inline scripts` and `headers` to both `server` and `preview`.

- [ ] **Step 2:** `docker build -t sentinelstream-frontend frontend && docker run -d --rm --name hdrcheck -p 127.0.0.1:3999:3000 sentinelstream-frontend && sleep 2 && curl -sI http://127.0.0.1:3999/ | grep -iE "content-security|x-frame|nosniff|referrer"; docker stop hdrcheck` → four header lines.
- [ ] **Step 3:** `git commit -am "Dashboard security headers (CSP, framing, nosniff, referrer)"`

---

### Task 6: Docs

**Files:** `docs/API_SPEC.md`, `docs/DEMO.md`, `README.md`, `docs/ARCHITECTURE.md`, `docs/LIMITATIONS.md`

- [ ] **Step 1:**
  - API_SPEC: header bullet "Authentication: `GET /alerts` and `POST /upload-pcap` need `Authorization: Bearer <token>` → else **401**; the token is in `data/api-token` (mode 600) and printed at startup; `/health` is open." WebSocket section: client offers subprotocols `sentinelstream, <token>`; server accepts `sentinelstream`; wrong or missing token → **1008**; more than 20 clients → **1013**. CORS allows the `Authorization` header.
  - DEMO step 2: replace the command with the `setpriv` command from the spec §1 and one sentence on why (runs as you with only `CAP_NET_RAW`). Step 3: "Paste the token printed in terminal 1 (also in `data/api-token`) into the dashboard once." Troubleshooting: row for "Paste the dashboard token" form.
  - README quick start: "Paste the token from `docker compose logs backend` when the dashboard asks."
  - ARCHITECTURE trust boundary: HTTP/WS row gains the token; model row "sha256 pinned in code"; deployment section unchanged.
  - LIMITATIONS trust boundary: replace "No authentication" with the token, its scope (single shared secret, no users or expiry, readable by anyone who can read `data/`), the root-in-container upload-child note from the spec §1, and "local runs drop root via `setpriv`".
- [ ] **Step 2:** `grep -rn "sudo .venv/bin/uvicorn" docs README.md` → only the `setpriv` form remains.
- [ ] **Step 3:** `git commit -am "Docs: token, least-privilege run, pinned models"`

---

### Task 7: Gate and evidence

Needs `sudo` once (human-approved before running).

- [ ] **Step 1: Local least-privilege run** — in a terminal tab: the DEMO step 2 `setpriv` command. Then (no root): `pid=$(pgrep -f "uvicorn backend.api.main"); grep -E "^(Uid|CapEff|CapAmb)" /proc/$pid/status; capsh --decode=$(grep CapEff /proc/$pid/status | awk '{print $2}')` → Uid = your uid, CapEff = `cap_net_raw` only.
- [ ] **Step 2: Token in the browser** — open the dev dashboard (`npm --prefix frontend run dev` via the preview tool), confirm the token form, paste the token from `data/api-token` (do not echo it in chat), run `simulator/simulate_attack.py portscan`, confirm the High PortScan row.
- [ ] **Step 3: Negative checks** — `curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8000/alerts` → 401; a `websockets` client without subprotocols → closed 1008; `stat -c %a data data/api-token data/sentinelstream.db` → 700 600 600.
- [ ] **Step 4: Docker** — `docker compose -f docker-compose.yml -f docker-compose.demo.yml up --build -d`; token via `docker compose logs backend`; open http://localhost:3000, paste it, confirm the alert and zero CSP violations in the console (`read_console_messages`); `docker compose down`.
- [ ] **Step 5:** full `pytest`, `ruff check`, `npm test`, `npm run build`; append evidence to PROGRESS.md under a new "Post-v1 sub-project 1: security hardening" section; commit; ask before pushing.
