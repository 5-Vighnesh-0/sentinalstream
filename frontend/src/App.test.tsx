import { render, screen, waitFor, act, fireEvent } from "@testing-library/react";
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
  static count = 0;
  protocols: string[];
  onopen?: () => void;
  onmessage?: (e: { data: string }) => void;
  onclose?: () => void;
  constructor(_url: string, protocols: string[]) {
    this.protocols = protocols;
    FakeWS.last = this;
    FakeWS.count++;
  }
  close() {}
}

beforeEach(() => {
  localStorage.clear();
  FakeWS.count = 0;
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

test("a rejected token brings back the form even though the socket never opens", async () => {
  localStorage.setItem("sentinelstream.token", "old");
  vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ status: 401, ok: false, json: async () => ({}) }));
  render(<App />);
  await waitFor(() => expect(screen.getByRole("alert").textContent).toMatch(/rejected that token/));
  expect(screen.getByText("Waiting for the dashboard token")).toBeTruthy();
});

test("each failed reconnect probes /alerts again", async () => {
  localStorage.setItem("sentinelstream.token", "t0k");
  const fetchMock = vi.fn().mockResolvedValue({ status: 200, ok: true, json: async () => ({ items: [] }) });
  vi.stubGlobal("fetch", fetchMock);
  render(<App />);
  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(1));
  act(() => FakeWS.last.onclose?.());
  await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
});

test("without a token the header waits for one and no socket is opened", () => {
  vi.stubGlobal("fetch", vi.fn());
  render(<App />);
  expect(screen.getByText("Waiting for the dashboard token")).toBeTruthy();
  expect(screen.queryByText(/Lost the connection/)).toBeNull();
  expect(FakeWS.count).toBe(0);
});

test("saving a valid token stores it and opens the socket with it", async () => {
  const fetchMock = vi.fn().mockResolvedValue({ status: 200, ok: true, json: async () => ({ items: [] }) });
  vi.stubGlobal("fetch", fetchMock);
  render(<App />);
  fireEvent.change(screen.getByLabelText("Dashboard token"), { target: { value: " abc_DEF-123 " } });
  fireEvent.click(screen.getByText("Save"));
  expect(localStorage.getItem("sentinelstream.token")).toBe("abc_DEF-123");
  expect(FakeWS.last.protocols).toEqual(["sentinelstream", "abc_DEF-123"]);
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
});

test("a malformed pasted token is not saved", () => {
  vi.stubGlobal("fetch", vi.fn());
  render(<App />);
  fireEvent.change(screen.getByLabelText("Dashboard token"), { target: { value: "Bearer abc" } });
  fireEvent.click(screen.getByText("Save"));
  expect(screen.getByRole("alert").textContent).toBe("That doesn't look like a dashboard token.");
  expect(localStorage.getItem("sentinelstream.token")).toBeNull();
  expect(FakeWS.count).toBe(0);
});

test("a malformed stored token yields the form, not a crash", () => {
  localStorage.setItem("sentinelstream.token", "bad token\n");
  vi.stubGlobal("fetch", vi.fn());
  render(<App />);
  expect(screen.getByText("Paste the dashboard token")).toBeTruthy();
  expect(FakeWS.count).toBe(0);
});
