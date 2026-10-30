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
