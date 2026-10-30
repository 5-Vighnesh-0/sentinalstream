// The backend binds 127.0.0.1:8000 only; see docs/API_SPEC.md. Not "localhost": browsers may try ::1 first,
// which the backend refuses, and the WebSocket then waits out a backoff before connecting (Phase 7 gate).
export const API_URL = "http://127.0.0.1:8000";
export const WS_URL = "ws://127.0.0.1:8000/ws/alerts";
export const FEED_LIMIT = 200;
export const TRAFFIC_WINDOW_S = 60;
// A repeat within 30 s of last_seen updates the same alert (docs/DATA_MODEL.md, aggregation D4): that window is "in effect".
export const IN_EFFECT_MS = 30_000;
export const STALE_AFTER_MS = 5_000; // stats arrive every second

