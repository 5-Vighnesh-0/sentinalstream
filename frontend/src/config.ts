// The backend binds 127.0.0.1:8000 only; see docs/API_SPEC.md. Not "localhost": browsers may try ::1 first,
// which the backend refuses, and the WebSocket then waits out a backoff before connecting (Phase 7 gate).
export const API_URL = "http://127.0.0.1:8000";
export const WS_URL = "ws://127.0.0.1:8000/ws/alerts";
export const FEED_LIMIT = 200;
export const TRAFFIC_WINDOW_S = 60;
