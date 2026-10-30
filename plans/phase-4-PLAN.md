# Phase 4 Plan — Dashboard

## Tasks

1. Scaffold `frontend/`: React 18.3.1, Vite (port 3000 set in `vite.config.js`), Tailwind v4 via `@tailwindcss/vite`, Recharts, Vitest + jsdom + Testing Library. No TypeScript type-checking (human decision): `.tsx` is transpiled only.
2. `src/config.ts` — API at `http://localhost:8000`, WebSocket at `ws://localhost:8000/ws/alerts`.
3. `src/useWebSocket.ts` — connect, parse JSON messages, reconnect with exponential backoff (1 s, 2 s, 4 s … capped at 30 s, reset after a successful open), `onOpen` callback so the app re-fetches `GET /alerts`.
4. `src/App.tsx` — state: alerts by id (aggregated updates replace by id), latest 200 kept; stats history (last 60 s); `/health` (`model_loaded`); filters. Live view shows only live alerts; picking an upload batch shows that batch's alerts, labelled "capture time".
5. Components: `AlertFeed` (latest 200, severity bar + label, severity/type/batch filters), `TrafficChart` (packets/s line, last 60 s, tooltip), `AttackDistribution` (horizontal bars, values at tips, tooltip), `PCAPUpload` (sends `X-Sentinel-Upload: 1`, shows batch status from `batch` messages and plain-language errors for 400/403/413/429), banners (Demo mode when `iface` is `lo`, "no model loaded", connection lost/reconnecting).
6. Tests: `useWebSocket.test.tsx` (message parsing, backoff sequence and cap, reset after open, cleanup on unmount), `AlertFeed.test.tsx` (≤ 200 rows from 1,000 alerts, severity label text, severity filter).
7. Gate in the built-in browser with the backend running (`sudo uvicorn`) and a loopback scan: alert visible ≤ 2 s, chart ticking every second, 1,000 alerts pushed through the hub without the UI stalling.

## Design (frontend-design + dataviz skills)

- Light only (project rule: no dark mode). System fonts only (offline rule).
- Palette: page `#f3f5f7`, surface `#ffffff`, ink `#16232d`, muted `#5d6c78`, hairline `#dde3e8`, traffic line `#2a78d6`; severity = dataviz status palette with text: high `#d03b3b`, medium `#ec835a`, low `#fab219`.
- One bold element: the severity bar on each alert row. One motion: a short highlight on a new or updated row (off under `prefers-reduced-motion`).

```
+--------------------------------------------------------------------+
| SentinelStream          Live on lo   ·   connection: connected     |
| [Demo mode: capturing loopback traffic only]  [No model loaded]    |
+-----------------------------------------+--------------------------+
| Alerts  [severity v] [type v] [view v]  | Packets per second (60 s)|
| ▌high  12:00:03  PortScan  a:p → b:p ×3 |  ~~~~~~~~~~~~~~~~~~~~~   |
| ▌low   12:00:01  anomaly   a:p → b:p ×1 | Attack types             |
| ...                                     |  PortScan ███████ 3      |
|                                         | Analyse a capture file   |
+-----------------------------------------+--------------------------+
```

## Files

| Action | Path |
|---|---|
| create | frontend/package.json, frontend/package-lock.json, frontend/vite.config.js, frontend/index.html |
| create | frontend/src/main.tsx, App.tsx, config.ts, index.css, useWebSocket.ts, components/{AlertFeed,TrafficChart,AttackDistribution,PCAPUpload,Banners}.tsx |
| create | frontend/src/useWebSocket.test.tsx, frontend/src/components/AlertFeed.test.tsx |
| modify | .gitignore (frontend/node_modules, frontend/dist already covered), AGENTS.md (approved deps) |

## Acceptance gate (from docs/PHASES.md)

> With the backend and a simulated attack running, new alerts appear within 2 seconds, the traffic chart updates every second, and the UI stays responsive after 1,000 alerts.
>
> Hardening: "no model loaded" banner from `/health`; uploaded-batch alerts shown under their batch filter and labelled "capture time"; no `dangerouslySetInnerHTML`.
