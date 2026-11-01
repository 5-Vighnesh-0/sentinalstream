# Sub-project 3: Analyst features — design

Roadmap: [2026-10-29-security-hardening-design.md](2026-10-29-security-hardening-design.md), row 3. Approved by the human on 2026-11-01, including the SQLite schema change (frozen since Phase 3).

## Goal

The analyst can mark alerts as handled, mute known-benign patterns without losing evidence, find past uploads after a reload, export what they see, and know the detectors' real live false-positive rate.

## Decisions (human-approved)

| Question | Decision |
|---|---|
| Scope | Acknowledge, suppress, upload history + CSV, live FP measurement (moved here from sub-project 4 at the human's choice) |
| Schema change | Approved: `alerts.acknowledged_at`, new `suppressions` table |
| Mute scope | One click mutes the exact pattern of an alert; an optional edit widens any field to "any"; an all-"any" rule is refused |
| Where muting applies | Read and broadcast time (alerts are always stored; deleting a rule unmutes) |
| FP capture | Two 1-hour runs back to back: `wlp6s0` (real interface), then `lo` |

## Part 1: database and API

1. **`alerts.acknowledged_at TEXT NULL`**, added at startup with an idempotent `ALTER TABLE alerts ADD COLUMN acknowledged_at TEXT` when the column is missing (existing databases keep their rows). An aggregated repeat (D4) that updates an acknowledged alert sets `acknowledged_at` back to NULL: new activity needs a new look.
2. **`suppressions`** table: `id INTEGER PRIMARY KEY AUTOINCREMENT`, `src_ip TEXT`, `dst_ip TEXT`, `dst_port INTEGER`, `attack_type TEXT`, `created_at TEXT NOT NULL`; NULL means "any"; `CHECK (src_ip IS NOT NULL OR dst_ip IS NOT NULL OR dst_port IS NOT NULL OR attack_type IS NOT NULL)`.
3. **Matching:** an alert is suppressed by the lowest-id rule whose non-NULL fields all equal the alert's fields. The API keeps the rules in memory (loaded at startup, updated on create/delete) and attaches `suppressed_by` (rule id or `null`) to every alert it returns or broadcasts.
4. **Endpoints** (all behind the dashboard token; the Bearer header forces a CORS preflight only the dashboard origins pass, so no extra CSRF header):
   - `PUT /alerts/{id}/ack` body `{"acknowledged": bool}` → the updated alert; 404 for an unknown id.
   - `GET /suppressions` → list; `POST /suppressions` body `{src_ip?, dst_ip?, dst_port?, attack_type?}` → 201 with the rule (422 if every field is null; fields validated: IPs parse with `ipaddress`, port 0–65535, attack_type ≤ 64 chars); `DELETE /suppressions/{id}` → 204, 404 if unknown.
   - `GET /uploads` → `[{id, filename, uploaded_at, status}]`, newest first.
5. Alert objects (REST and WebSocket) gain `acknowledged_at` (ISO string or null) and `suppressed_by` (int or null).
6. `docs/API_SPEC.md` and `docs/DATA_MODEL.md` change in the same PR.

## Part 2: dashboard (inside the existing warning-bulletin system; DESIGN.md applies)

1. **Alert details** gain actions: **Acknowledge** / **Undo acknowledge** (shows "Acknowledged HH:MM:SS"), and **Mute alerts like this**, which opens an inline editor: four rows (Source IP, Destination IP, Destination port, Attack type), each a choice of "this value" (default) or "any". Save is disabled when all are "any"; a warning shows when Attack type is "any".
2. **Feed:** acknowledged rows are de-emphasised and labelled "Acknowledged"; a **Needs attention** filter shows only unacknowledged alerts; muted alerts are hidden by default behind "**N muted · Show**".
3. **Strip** counts exclude muted alerts. The **tab title** counts unacknowledged, unmuted live High alerts (in effect or not): a High stays in the title until someone acknowledges it.
4. **Muted patterns** panel below the upload card: each rule in words ("anomaly from 127.0.0.1 to 127.0.0.1:42361") with **Delete**.
5. **Upload tabs** are restored on load from `GET /uploads` (done batches become tabs; others show their status in the upload card).
6. **Export CSV** in the Alerts header: every alert matching the current view and filters (not only the 200 rendered), columns `last_seen, timestamp, severity, attack_type, source, src_ip, src_port, dst_ip, dst_port, protocol, count, evidence, acknowledged_at, suppressed_by`; RFC 4180 quoting; a cell starting with `=`, `+`, `-` or `@` gets a leading `'` (spreadsheet formula injection); filename `sentinelstream-<live|upload-N>-<YYYYMMDD-HHMMSS>.csv`; built in the browser, no new endpoint.

## Part 3: live false-positive measurement (after the feature PR merges)

1. Run `python -m backend.pipeline --iface wlp6s0 --duration 3600`, then the same with `--iface lo`, under `sudo setpriv --reuid … --inh-caps=+net_raw --ambient-caps=+net_raw` (as docs/DEMO.md); normal desktop use, no simulator.
2. Report the summary's alerts per hour by detector (raw: mutes do not apply in the pipeline). Every alert counts as a false positive, with the caveat that real traffic is not guaranteed benign.
3. Record per-detector counts in `docs/LIMITATIONS.md` and `docs/EVALUATION.md`, the summary lines in PROGRESS.md. No IP addresses from the real network in committed files. README unchanged (AGENTS rule 4).

## Testing

- pytest: column migration on an existing database; ack set/clear and clear-on-repeat; suppression create/validate/delete, matching (exact, wildcard, lowest id wins), all-null refused; `suppressed_by` on REST and WebSocket; `GET /uploads`; token required on every new endpoint.
- Vitest: CSV quoting and formula escaping; mute editor disables Save when all "any"; Needs attention and muted toggles; tab title counts unacknowledged High.
- CI: the six required checks; `e2e` unchanged.

## Out of scope

Multi-user attribution of acknowledgements, rule expiry, CIDR or port-range rules, server-side CSV, applying mutes inside the capture pipeline.
