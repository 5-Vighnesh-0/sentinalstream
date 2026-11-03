# Analyst features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Acknowledge alerts, mute benign patterns without losing evidence, restore upload tabs, export CSV, and measure the live false-positive rate.

**Architecture:** One new column and one new table. Analyst writes (ack, rules) use a short API-side connection; the writer thread stays the only writer of detections and clears an acknowledgement when an aggregated repeat lands. Mute rules live in memory in the API and are matched at read and broadcast time, so alerts are always stored. The dashboard gains actions in the detail panel, two feed toggles, a rules panel, restored tabs, and a browser-side CSV export.

**Tech Stack:** FastAPI, SQLite, React 18, Vitest, pytest.

Spec: [docs/superpowers/specs/2026-10-31-analyst-features-design.md](../specs/2026-10-31-analyst-features-design.md)

## Global Constraints

- Every new endpoint requires the dashboard token (`dependencies=[Depends(require_token)]`).
- Mute matching: non-NULL rule fields must all equal the alert's (`src_ip`, `dst_ip`, `dst_port`, `attack_type`); lowest rule id wins; an all-NULL rule is refused (DB CHECK and 422).
- An aggregated repeat clears `acknowledged_at`.
- CSV: RFC 4180 quoting; a cell starting with `=`, `+`, `-` or `@` gets a leading `'`.
- `docs/API_SPEC.md` and `docs/DATA_MODEL.md` change in the same PR as the code.
- No new dependencies. Light only; DESIGN.md rules apply (blue only on pressables, severity colours only for severity).
- All work lands by PR with the six required checks.

---

### Task 1: Schema, migration, clear-on-repeat

**Files:** `backend/db/writer.py`, `backend/api/main.py` (create_app), `tests/test_writer.py`

- [ ] **Step 1: Failing tests** in `tests/test_writer.py`:
  - a database created by the old schema (alerts without `acknowledged_at`) gains the column after `connect()`, with its rows intact;
  - `suppressions` exists and refuses an all-NULL row (`sqlite3.IntegrityError`);
  - writer upsert of an aggregated repeat sets `acknowledged_at` back to NULL (insert an alert, set `acknowledged_at`, flush the same id with count 2 → NULL).
- [ ] **Step 2: Implement.** In `SCHEMA`: add `acknowledged_at TEXT` to `alerts`; add
  ```sql
  CREATE TABLE IF NOT EXISTS suppressions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      src_ip TEXT, dst_ip TEXT, dst_port INTEGER, attack_type TEXT,
      created_at TEXT NOT NULL,
      CHECK (src_ip IS NOT NULL OR dst_ip IS NOT NULL OR dst_port IS NOT NULL OR attack_type IS NOT NULL)
  );
  ```
  In `connect()` after `executescript`: `if "acknowledged_at" not in {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}: conn.execute("ALTER TABLE alerts ADD COLUMN acknowledged_at TEXT")` (a pre-Phase-3 DB was created without it). Append `"acknowledged_at"` to `ALERT_FIELDS`; the aggregator's new alert dict sets `"acknowledged_at": None`; the upsert's `DO UPDATE SET` adds `acknowledged_at = NULL`. In `create_app`, run `connect(db_path).close()` once so the API's read-only connections never see the old schema.
- [ ] **Step 3:** `pytest -q` passes. **Commit:** "Schema: alerts.acknowledged_at, suppressions table; a repeat clears the acknowledgement"

### Task 2: Mute rules (pure logic)

**Files:** create `backend/api/suppressions.py`, `tests/test_suppressions.py`

- [ ] **Step 1: Failing tests:** exact rule matches only its pattern; a rule with `dst_port=None` matches any port; lowest id wins when two match; `validate({})` raises `ValueError`; bad IP, port 70000, 65-char attack type raise `ValueError`.
- [ ] **Step 2: Implement**
  ```python
  """Mute rules: a NULL field means "any"; matched at read and broadcast time so muted alerts stay stored."""
  import ipaddress

  FIELDS = ("src_ip", "dst_ip", "dst_port", "attack_type")


  def validate(rule: dict) -> dict:
      clean = {f: rule.get(f) for f in FIELDS}
      if all(v is None for v in clean.values()):
          raise ValueError("A rule needs at least one field; an all-'any' rule would mute everything")
      for f in ("src_ip", "dst_ip"):
          if clean[f] is not None:
              clean[f] = str(ipaddress.ip_address(clean[f]))
      if clean["dst_port"] is not None and not 0 <= int(clean["dst_port"]) <= 65535:
          raise ValueError("dst_port must be 0-65535")
      if clean["attack_type"] is not None and not 0 < len(clean["attack_type"]) <= 64:
          raise ValueError("attack_type must be 1-64 characters")
      return clean


  def suppressed_by(rules: list[dict], alert: dict) -> int | None:
      """Rules are sorted by id, so the lowest-id match wins."""
      for rule in rules:
          if all(rule[f] is None or rule[f] == alert[f] for f in FIELDS):
              return rule["id"]
      return None
  ```
- [ ] **Step 3:** tests pass. **Commit:** "Mute rule validation and matching"

### Task 3: API endpoints

**Files:** `backend/api/main.py`, `tests/test_api.py`

- [ ] **Step 1: Failing tests:**
  - `PUT /alerts/{id}/ack` sets and clears `acknowledged_at`; unknown id → 404; no token → 401;
  - `POST /suppressions` → 201 and the rule; all-null → 422; `GET` lists it; `DELETE` → 204, then 404;
  - `GET /alerts` items carry `suppressed_by` (the rule id after a matching POST, null after DELETE) and `acknowledged_at`;
  - a WebSocket alert published after a matching rule carries `suppressed_by`;
  - `GET /uploads` lists batches newest first;
  - every new endpoint returns 401 without the token.
- [ ] **Step 2: Implement.**
  - The `Alert` model gains `acknowledged_at: str | None = None` and `suppressed_by: int | None = None`.
  - `Hub` gains `rules: list[dict]`, loaded in `create_app` (`SELECT … FROM suppressions ORDER BY id`).
  - `publish` sets `alert["suppressed_by"] = suppressed_by(hub.rules, alert)` before broadcasting. The writer ignores the extra key, because it inserts `ALERT_FIELDS` only.
  - `list_alerts` adds the same to each row.
  - New endpoints, each opening `connect(db_path)` with `closing(...)` for its write:
    - `PUT /alerts/{id}/ack`: `UPDATE alerts SET acknowledged_at = ? WHERE id = ?`. 404 if `rowcount == 0`; return the row.
    - `GET`, `POST` and `DELETE /suppressions`. POST runs `validate` (`ValueError` → 422), inserts with `now_iso()`, then appends to `hub.rules`. DELETE removes the rule from `hub.rules`.
    - `GET /uploads`: `SELECT id, filename, uploaded_at, status FROM upload_batches ORDER BY id DESC`.
  - CORS `allow_methods` adds `"PUT"` and `"DELETE"`.
- [ ] **Step 3:** `pytest -q`, `ruff check .` pass. **Commit:** "API: acknowledge alerts, mute rules, upload history"

### Task 4: Contracts

**Files:** `docs/API_SPEC.md`, `docs/DATA_MODEL.md`

- [ ] **Step 1:** DATA_MODEL:
  - add `acknowledged_at` to the alerts table, and note that a repeat clears it;
  - add the `suppressions` table and its CHECK;
  - note that analyst writes use a short API connection while the writer stays the only writer of detections.
- [ ] **Step 2:** API_SPEC:
  - document the four new endpoints with their status codes;
  - add the two new alert fields;
  - note that mutes apply at read and broadcast time and never delete.
- [ ] **Step 3: Commit:** "Docs: analyst features in the API and data contracts"

### Task 5: Dashboard — acknowledge and mute in the detail panel

**Files:** `frontend/src/components/AlertFeed.tsx` (type), `AlertDetail.tsx`, create `frontend/src/components/MuteEditor.tsx`, `frontend/src/api.ts` (new: token-authed `fetch` helpers `ackAlert(id, bool)`, `createRule(rule)`, `deleteRule(id)`, `listRules()`, `listUploads()`), tests.

- [ ] **Step 1: Failing Vitest:**
  - **Acknowledge:** clicking Acknowledge calls `PUT /alerts/{id}/ack` with `{"acknowledged": true}` and shows "Acknowledged HH:MM:SS".
  - **Mute editor:**
    - it defaults every field to "this value";
    - Save is disabled when all four fields are "any";
    - a warning appears when Attack type is "any";
    - Save POSTs only the fields left as "this value".
- [ ] **Step 2: Implement.**
  - `AlertItem` gains `acknowledged_at: string | null` and `suppressed_by: number | null`.
  - The detail panel gets an actions row: an Acknowledge or Undo button (accent, a pressable), and "Mute alerts like this", which toggles the `MuteEditor` inline.
  - `MuteEditor` shows four rows of radio pairs, "this value" (`<mono value>`) or "any", plus Save and Cancel. It has a polite live region for its result.
  - The App owns the state updates: on ack, upsert the returned alert; on rule create or delete, refresh `rules` and recompute.
- [ ] **Step 3:** tests and build pass. **Commit:** "Dashboard: acknowledge and mute from the alert details"

### Task 6: Dashboard — feed toggles, counts, rules panel, restored tabs

**Files:** `AlertFeed.tsx`, `InEffectStrip.tsx` (consumer only), `App.tsx`, create `frontend/src/components/MutedPatterns.tsx`, tests.

- [ ] **Step 1: Failing Vitest:**
  - **Feed:**
    - muted alerts are hidden by default, and "N muted · Show" reveals them;
    - "Needs attention" shows only unacknowledged alerts;
    - acknowledged rows show "Acknowledged".
  - **Counts:** the strip excludes muted alerts; the tab title counts unacknowledged, unmuted live High alerts, including expired ones.
  - **Rules panel:** lists rules in words and its Delete button calls DELETE.
  - **Upload tabs:** on load, `GET /uploads` restores `done` batches as tabs with their filenames.
- [ ] **Step 2: Implement.**
  - **App:**
    - fetches rules and uploads after a token is accepted, alongside `loadAlerts`;
    - computes `muted = a.suppressed_by !== null`;
    - passes `visible.filter(!muted)` to the strip and the chart (or all alerts when "Show muted" is on);
    - sets the title from unacknowledged, unmuted live High alerts.
  - **Feed:** gains the `needsAttention` and `showMuted` toggles. They are buttons with `aria-pressed`, in the header next to the filters, and "Clear filters" resets both.
  - **`MutedPatterns`:** a panel under PCAPUpload, rendered only when rules exist. Each rule reads like "Anomaly from 127.0.0.1 to 127.0.0.1:42361", with "any …" for wildcards, plus a Delete button.
- [ ] **Step 3:** tests and build pass. **Commit:** "Dashboard: needs-attention and muted toggles, rules panel, restored upload tabs"

### Task 7: CSV export

**Files:** create `frontend/src/csv.ts`, `frontend/src/csv.test.ts`; `AlertFeed.tsx` (button)

- [ ] **Step 1: Failing tests:** `toCsv` quotes commas, quotes and newlines (RFC 4180); prefixes `=`, `+`, `-`, `@` cells with `'`; header row is exactly the spec's column list; evidence column uses `evidence(alert)[0]`.
- [ ] **Step 2: Implement**
  ```ts
  import { evidence, type AlertItem } from "./components/AlertFeed";

  const COLUMNS = ["last_seen", "timestamp", "severity", "attack_type", "source", "src_ip", "src_port", "dst_ip", "dst_port",
    "protocol", "count", "evidence", "acknowledged_at", "suppressed_by"] as const;

  /** A spreadsheet runs a cell starting with = + - @ as a formula; packet-derived text must not. */
  function cell(value: unknown): string {
    let s = value === null || value === undefined ? "" : String(value);
    if (/^[=+\-@]/.test(s)) s = `'${s}`;
    return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  }

  export function toCsv(alerts: AlertItem[]): string {
    const rows = alerts.map((a) => COLUMNS.map((c) => cell(c === "evidence" ? evidence(a)[0] : a[c])).join(","));
    return [COLUMNS.join(","), ...rows].join("\r\n") + "\r\n";
  }
  ```
  The Alerts header gets an **Export CSV** button. It exports `matching` (all filtered alerts, not only the 200 shown) through a `Blob`, an object URL and a temporary `<a download>`, named `sentinelstream-<live|upload-N>-<YYYYMMDD-HHMMSS>.csv`.
- [ ] **Step 3:** tests pass. **Commit:** "Dashboard: CSV export of the current view"

### Task 8: Verify, PR, merge

- [ ] **Step 1:** pytest, ruff, vitest, build; `impeccable detect --json frontend/src`; `scripts/e2e-demo.sh` passes; live check in the browser against the Docker backend: acknowledge, mute + unmute, Needs attention, Show muted, CSV opens with correct rows, reload restores an upload tab.
- [ ] **Step 2:** push `analyst-features`, open the PR, six checks green; ask the human; merge.

### Task 9: Live false-positive measurement and evidence

- [ ] **Step 1:** In a terminal tab (human types the sudo password): `sudo setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups --inh-caps=+net_raw --ambient-caps=+net_raw .venv/bin/python -m backend.pipeline --iface wlp6s0 --duration 3600`, then the same with `--iface lo`; normal use, no simulator.
- [ ] **Step 2:** Record the two `summary` lines' `alerts_per_hour` per detector in `docs/LIMITATIONS.md` and `docs/EVALUATION.md` (counts only, no IPs), the full summary lines in PROGRESS.md under "Post-v1 sub-project 3: analyst features" with the feature evidence; README unchanged.
- [ ] **Step 3:** Evidence PR through the required checks; merge.
