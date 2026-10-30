# Post-v1 improvements: roadmap and sub-project 1 (security hardening) — design

Date: 2026-10-29 · Status: **design approved; spec for review** · Method: superpowers brainstorming after all seven phases were accepted.

## Roadmap (agreed order)

| # | Sub-project | Scope | Status |
|---|---|---|---|
| 1 | **Security hardening** | This document | Designed |
| 2 | Repo + CI polish | Branch protection with required checks, SECURITY.md, Dependabot (pip, npm, actions, docker digests), `pip-audit` + `npm audit` + Trivy in CI, the Docker demo run end to end in CI, README screenshot, repo description/topics, `v1.0.0` release | Own spec later |
| 3 | Analyst features | Suppress "known benign" patterns, acknowledge/resolve alerts, list past uploads, CSV export, measure the Random Forest's live false-positive rate. Needs a SQLite schema change (frozen since Phase 3): explicit human approval step | Own spec later |
| 4 | Detection quality | Time-based split, thresholds for small classes, richer features, real-interface / Zeek path | Own spec later |

Context that drove the order: open security risks first; then CI that protects `main` and scans dependencies; the schema change needs approval; detection work benefits from suppression (fair live FP measurement) and from CI catching regressions.

## Sub-project 1: risks addressed

| Risk (found 2026-10-29) | Severity | Control |
|---|---|---|
| The local demo runs the whole API as root (`sudo uvicorn`) to get capture | High | §1 least-privilege capture |
| Any local process or user can read alerts and upload (no auth; only the 127.0.0.1 bind) | Medium | §2 API token |
| Model files are pickles; file and sidecar sha256 can be swapped together, or `SENTINEL_MODEL_PATH` pointed at a planted file under `models/` | Medium | §3 hash pins in code |
| Dashboard sends no security headers (framing, MIME sniffing) | Medium | §4 headers |
| SQLite file and `data/` world-readable (IP addresses are personal data) | Low | §4 umask |
| Unlimited WebSocket clients | Low | §4 cap |

Out of scope here (other sub-projects or documented limits): dependency freshness and scanning (2), evasion by slow scans and sub-threshold floods (4, documented in LIMITATIONS.md).

## §1 Least-privilege capture

- **Local run:** docs/DEMO.md step 2 becomes

  ```bash
  sudo setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups --inh-caps=+net_raw --ambient-caps=+net_raw \
    .venv/bin/uvicorn backend.api.main:app --host 127.0.0.1 --port 8000
  ```

  `$(id -u)` expands in the user's shell before `sudo`, so uvicorn runs as the invoking user holding only `CAP_NET_RAW` (ambient, so it survives `exec` and reaches the `tcpdump` that Scapy runs to compile BPF filters). No system configuration changes.
- **Root warning:** at startup, if `os.geteuid() == 0` and `/.dockerenv` does not exist, the backend logs a warning naming DEMO.md's command. It does not refuse to start.
- **Upload child drops capabilities:** the first thing `backend/api/uploads.py`'s child does is call `capset(2)` with empty effective, permitted and inheritable sets and clear the ambient set (`prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL)`), via `ctypes`. Dropping needs no privilege. Then it applies the existing `RLIMIT_AS` / `RLIMIT_CPU` limits.
- **Docker:** unchanged (`cap_drop: ALL` + `NET_RAW`, read-only root). The upload child there is uid 0 with no capabilities on a read-only filesystem and can still write `/tmp` and the data volume; documented in LIMITATIONS.md.

## §2 API token, pasted once

- **Token:** at startup the backend reads `<data dir>/api-token`, or creates it with `secrets.token_urlsafe(32)` and mode 600. `<data dir>` is the parent of `SENTINEL_DB_PATH`. It logs once: `Dashboard token: <token> (stored in <path>; delete the file to rotate it)`. Restarting keeps the same token; deleting the file rotates it.
- **REST:** `GET /alerts` and `POST /upload-pcap` require `Authorization: Bearer <token>` (compared with `secrets.compare_digest`), else **401** `{"detail": "Missing or wrong dashboard token"}`. The upload route keeps its existing Origin and `X-Sentinel-Upload` checks; the token is checked first. `GET /health` stays open (Docker healthcheck, dashboard banner).
- **WebSocket:** browsers cannot set headers on a WebSocket, so the client offers subprotocols `["sentinelstream", <token>]`. The server checks the token (constant time) and accepts with subprotocol `sentinelstream`; a missing or wrong token closes with **1008**, as a wrong Origin already does. `token_urlsafe` output is valid subprotocol syntax.
- **CORS:** `allow_headers` adds `Authorization`.
- **Dashboard:** the token is kept in `localStorage` (wrapped in try/catch; the page still works if storage is unavailable, it just asks again). With no stored token, or after any 401 or a 1008 close, the feed area shows a form, "Paste the dashboard token from the backend's log", instead of alerts. `fetch` calls add the `Authorization` header; `useWebSocket` passes the subprotocols. No token is ever put in a URL.
- **Docs:** API_SPEC.md (401s, WebSocket subprotocol, token file), DEMO.md step 3 (where to find the token: terminal 1 or `data/api-token`; with Docker, `docker compose logs backend`), README quick start, ARCHITECTURE.md trust boundary.

## §3 Model hash pins

- `backend/features/feature_set.py` gets `TRUSTED_MODEL_SHA256`, the committed files' hashes: `bb2cd31c1e40f45ef07622b5a1771fa1b429920c6f7ebcaa4db3e6d9346c7025` (random_forest) and `df1aaacc4d8a73b375571d3505e7b6185b1827c947dff26f625a59f7766c9d92` (isolation_forest).
- `load_model(path, trusted=TRUSTED_MODEL_SHA256)` refuses a file whose sha256 is not in `trusted` with `ValueError("… is not a trusted model …")`, before `joblib.load`. The existing sidecar and feature-order checks stay.
- Tests that train throwaway models pass `trusted={that model's sha256}`.
- `train_supervised.py` and `train_baseline.py` print the new pin line after saving, so retraining is: retrain → paste pins → commit.
- A test asserts each committed model's sidecar sha256 is in `TRUSTED_MODEL_SHA256` (drift fails CI).

## §4 Smaller controls

- **Dashboard headers (nginx):** `Content-Security-Policy: default-src 'self'; connect-src 'self' http://127.0.0.1:8000 ws://127.0.0.1:8000; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`, plus `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`. Vite dev server: the same minus the CSP (dev hot reload needs inline scripts). If the browser reports a CSP violation during the gate, the policy is adjusted to the specific source, never loosened to `unsafe-*` wholesale.
- **File permissions:** the backend calls `os.umask(0o077)` at startup, before creating the data directory, database or token, so they are owner-only.
- **WebSocket cap:** at most 20 open clients; the next is closed with **1013** ("try again later").

## Testing

Unit (no root):

- REST: no token → 401, wrong token → 401, right token → 200; `/health` open without a token.
- WebSocket: right token as subprotocol → accepted with subprotocol `sentinelstream`; missing/wrong → 1008; 21st client → 1013.
- Upload: right token but no `X-Sentinel-Upload` → 403; header but no token → 401.
- Token file: created with mode 600, reused across `create_app` calls, rotated when deleted.
- Models: an untrusted file is refused before unpickling; committed models' hashes are pinned.
- Upload child: after the drop, `/proc/self/status` `CapEff`, `CapPrm`, `CapAmb` are all zero.
- Frontend (Vitest): the token form appears with no stored token and after a 401; `fetch` and the WebSocket send the token.

Gate (human-approved `sudo` once):

1. Local demo with the `setpriv` command: `/proc/<uvicorn pid>/status` shows the invoking user's uid and `CapEff` = `cap_net_raw` only; a port scan still produces the High PortScan alert in the dashboard after pasting the token.
2. `docker compose up --build`: the token is in `docker compose logs backend`; the dashboard (nginx) shows no CSP violations in the browser console; the alert appears.
3. Without a token, `curl /alerts` → 401 and a WebSocket client → 1008.

## Out of scope

Multi-user accounts, roles, TLS, token expiry, rate limiting, and anything in sub-projects 2–4.
