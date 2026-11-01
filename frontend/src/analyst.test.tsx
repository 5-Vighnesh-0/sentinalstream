import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import App from "./App";
import type { AlertItem } from "./components/AlertFeed";
import MuteEditor from "./components/MuteEditor";
import { describe as describeRule } from "./components/MutedPatterns";

const alert = (over: Partial<AlertItem>) =>
  ({
    id: "x1", timestamp: new Date().toISOString(), last_seen: new Date().toISOString(), src_ip: "127.0.0.1", dst_ip: "127.0.0.1",
    src_port: 40000, dst_port: 42361, protocol: "UDP", attack_type: "anomaly", confidence: 0.993, severity: "low",
    source: "isolation_forest", count: 1, batch_id: null, acknowledged_at: null, suppressed_by: null, ...over,
  }) as AlertItem;

class FakeWS {
  static last: FakeWS;
  onopen?: () => void;
  onmessage?: (e: { data: string }) => void;
  onclose?: () => void;
  constructor() {
    FakeWS.last = this;
  }
  close() {}
}

/** A backend double that records writes; GET /alerts returns `items`, rules and uploads as given. */
function backend({ items = [] as AlertItem[], rules = [] as unknown[], uploads = [] as unknown[] } = {}) {
  const calls: { method: string; path: string; body?: unknown }[] = [];
  const fetchMock = vi.fn(async (url: string, init: RequestInit = {}) => {
    const path = new URL(String(url)).pathname;
    const method = init.method ?? "GET";
    const body = init.body ? JSON.parse(String(init.body)) : undefined;
    calls.push({ method, path, body });
    const json =
      path === "/suppressions" && method === "POST" ? { id: 9, created_at: "now", src_ip: null, dst_ip: null, dst_port: null, attack_type: null, ...body }
      : path === "/suppressions" ? rules
      : path === "/uploads" ? uploads
      : path.endsWith("/ack") ? { ...items[0], acknowledged_at: body.acknowledged ? new Date().toISOString() : null }
      : { items, model_loaded: true };
    return { status: method === "DELETE" ? 204 : 200, ok: true, json: async () => json };
  });
  vi.stubGlobal("fetch", fetchMock);
  return calls;
}

beforeEach(() => {
  localStorage.clear();
  localStorage.setItem("sentinelstream.token", "t0k");
  vi.stubGlobal("WebSocket", FakeWS);
});
afterEach(() => vi.unstubAllGlobals());

test("the mute editor never saves an all-'any' rule and warns about any attack type", async () => {
  const onSave = vi.fn(async () => {});
  render(<MuteEditor alert={alert({})} onSave={onSave} onCancel={() => {}} />);
  const anyFor = (group: string) => within(screen.getByRole("radiogroup", { name: group })).getByLabelText("any");
  fireEvent.click(anyFor("Attack type"));
  expect(screen.getByText(/Any attack type can hide real attacks/)).toBeTruthy();
  for (const g of ["Source IP", "Destination IP", "Destination port"]) fireEvent.click(anyFor(g));
  expect((screen.getByRole("button", { name: "Mute" }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.click(within(screen.getByRole("radiogroup", { name: "Destination port" })).getAllByRole("radio")[0]);
  await act(async () => fireEvent.click(screen.getByRole("button", { name: "Mute" })));
  expect(onSave).toHaveBeenCalledWith({ dst_port: 42361 });
});

test("a rule reads as words, with 'anywhere' for wildcards", () => {
  expect(describeRule({ id: 1, src_ip: "127.0.0.1", dst_ip: "127.0.0.1", dst_port: 42361, attack_type: "anomaly", created_at: "" }))
    .toBe("Anomaly from 127.0.0.1 to 127.0.0.1:42361");
  expect(describeRule({ id: 2, src_ip: null, dst_ip: null, dst_port: 53, attack_type: "PortScan", created_at: "" }))
    .toBe("PortScan from anywhere to any address, port 53");
});

test("acknowledging from the details clears the High from the tab title", async () => {
  const calls = backend({ items: [alert({ severity: "high", attack_type: "PortScan", source: "rule", confidence: 1 })] });
  render(<App />);
  await waitFor(() => expect(document.title).toBe("(1 High) SentinelStream"));
  fireEvent.click(screen.getByRole("button", { name: /PortScan from .*: details/ }));
  await act(async () => fireEvent.click(screen.getByRole("button", { name: "Acknowledge" })));
  expect(calls).toContainEqual({ method: "PUT", path: "/alerts/x1/ack", body: { acknowledged: true } });
  await waitFor(() => expect(document.title).toBe("SentinelStream"));
  expect(screen.getByRole("button", { name: "Undo acknowledge" })).toBeTruthy();
});

test("muting hides matching alerts behind a count, and deleting the rule brings them back", async () => {
  const calls = backend({ items: [alert({}), alert({ id: "x2", dst_port: 80, attack_type: "DoS", source: "random_forest" })] });
  render(<App />);
  await screen.findByRole("button", { name: /Anomaly from .*: details/ });
  fireEvent.click(screen.getByRole("button", { name: /Anomaly from .*: details/ }));
  fireEvent.click(screen.getByRole("button", { name: "Mute alerts like this" }));
  await act(async () => fireEvent.click(screen.getByRole("button", { name: "Mute" })));
  expect(calls).toContainEqual({ method: "POST", path: "/suppressions", body: { src_ip: "127.0.0.1", dst_ip: "127.0.0.1", dst_port: 42361, attack_type: "anomaly" } });
  expect(screen.queryByRole("button", { name: /Anomaly from .*: details/ })).toBeNull();
  expect(screen.getByRole("button", { name: "1 muted · Show" })).toBeTruthy();
  expect(screen.getByText("Anomaly from 127.0.0.1 to 127.0.0.1:42361")).toBeTruthy();
  await act(async () => fireEvent.click(screen.getByRole("button", { name: /Delete rule/ })));
  expect(calls).toContainEqual({ method: "DELETE", path: "/suppressions/9", body: undefined });
  expect(screen.getByRole("button", { name: /Anomaly from .*: details/ })).toBeTruthy();
});

test("Needs attention shows only unacknowledged alerts", async () => {
  backend({ items: [alert({}), alert({ id: "x2", attack_type: "DoS", source: "random_forest", acknowledged_at: new Date().toISOString() })] });
  render(<App />);
  await screen.findByRole("button", { name: /DoS from .*: details/ });
  fireEvent.click(screen.getByRole("button", { name: "Needs attention" }));
  expect(screen.queryByRole("button", { name: /DoS from .*: details/ })).toBeNull();
  expect(screen.getByRole("button", { name: /Anomaly from .*: details/ })).toBeTruthy();
});

test("past uploads come back as tabs after a reload", async () => {
  backend({ uploads: [{ id: 3, filename: "office.pcap", uploaded_at: "", status: "done" }, { id: 4, filename: "bad.pcap", uploaded_at: "", status: "failed" }] });
  render(<App />);
  expect(await screen.findByRole("tab", { name: "office.pcap" })).toBeTruthy();
  expect(screen.queryByRole("tab", { name: "bad.pcap" })).toBeNull();
});
