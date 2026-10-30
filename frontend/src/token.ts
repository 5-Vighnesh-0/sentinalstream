const KEY = "sentinelstream.token";

// Tokens are secrets.token_urlsafe(32); anything else would also make new WebSocket(url, protocols) throw.
export const TOKEN_PATTERN = /^[A-Za-z0-9_-]+$/;

// Per-browser convenience only: if storage is unavailable the dashboard simply asks again.
export function loadToken(): string {
  try {
    const stored = localStorage.getItem(KEY) ?? "";
    return TOKEN_PATTERN.test(stored) ? stored : "";
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
