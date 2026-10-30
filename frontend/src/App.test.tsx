import { render, screen, waitFor, act } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import App, { upsert } from "./App";
import type { AlertItem } from "./components/AlertFeed";

const alert = (id: string, batch_id: number | null, count = 1) => ({ id, batch_id, count }) as AlertItem;

test("an update replaces the old copy and moves to the top", () => {
  const list = upsert([alert("a", null), alert("b", null)], [alert("b", null, 2)]);
  expect(list.map((a) => [a.id, a.count])).toEqual([["b", 2], ["a", 1]]);
});

test("live alerts never evict an upload's alerts", () => {
  const upload = Array.from({ length: 1000 }, (_, i) => alert(`u${i}`, 1));
  const live = Array.from({ length: 1500 }, (_, i) => alert(`l${i}`, null));
  const list = upsert(upsert([], upload), live);
  expect(list.filter((a) => a.batch_id === 1)).toHaveLength(1000);
  expect(list.filter((a) => a.batch_id === null)).toHaveLength(1000);
});

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
