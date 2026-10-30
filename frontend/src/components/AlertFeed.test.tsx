import { fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { expect, test } from "vitest";
import AlertFeed, { type AlertItem, endpoint, evidence } from "./AlertFeed";

const NOW = Date.parse("2026-10-29T12:00:10.000Z");

function Feed({ alerts, captureTime = false, changed = new Map() }: { alerts: AlertItem[]; captureTime?: boolean; changed?: Map<string, "new" | "updated"> }) {
  const [severity, setSeverity] = useState("all");
  const [held, setHeld] = useState(changed);
  return (
    <AlertFeed
      alerts={alerts}
      captureTime={captureTime}
      now={NOW}
      severity={severity}
      onSeverity={setSeverity}
      changed={held}
      onSeen={(id) => setHeld((m) => { const n = new Map(m); n.delete(id); return n; })}
      selectedId={null}
      onSelect={() => {}}
    />
  );
}

const severities = ["high", "medium", "low"] as const;

function makeAlerts(n: number): AlertItem[] {
  return Array.from({ length: n }, (_, i) => ({
    id: `a${i}`,
    timestamp: "2026-10-29T12:00:00.000Z",
    last_seen: "2026-10-29T12:00:00.000Z",
    src_ip: "127.0.0.1",
    dst_ip: "127.0.0.1",
    src_port: 40000 + i,
    dst_port: 80,
    protocol: "TCP",
    attack_type: i % 2 ? "anomaly" : "PortScan",
    confidence: 0.99,
    severity: severities[i % 3],
    source: i % 2 ? "isolation_forest" : "rule",
    count: 1,
    batch_id: null,
  }));
}

const bodyRows = () => within(screen.getAllByRole("rowgroup")[1]).queryAllByRole("row");

test("renders at most the latest 200 of 1,000 alerts", () => {
  render(<Feed alerts={makeAlerts(1000)} />);
  expect(bodyRows()).toHaveLength(200);
  expect(screen.getByText(/showing 200 of 1,000/i)).toBeTruthy();
});

test("severity is written out, not only a colour", () => {
  render(<Feed alerts={makeAlerts(3)} />);
  const body = screen.getAllByRole("rowgroup")[1];
  expect(within(body).getAllByText("High")).toHaveLength(1);
  expect(within(body).getAllByText("Medium")).toHaveLength(1);
});

test("severity and attack-type filters narrow the list", () => {
  render(<Feed alerts={makeAlerts(30)} />);
  fireEvent.change(screen.getByLabelText("Severity"), { target: { value: "high" } });
  expect(bodyRows()).toHaveLength(10);
  fireEvent.change(screen.getByLabelText("Attack type"), { target: { value: "PortScan" } });
  expect(bodyRows()).toHaveLength(5);
  expect(bodyRows().every((row) => within(row).queryByText("PortScan"))).toBe(true);
});

test("upload view labels the time column as capture time", () => {
  render(<Feed alerts={makeAlerts(1)} captureTime />);
  expect(screen.getByRole("columnheader", { name: "Capture time" })).toBeTruthy();
});

test("evidence never shows an unmeasured percentage", () => {
  const [a] = makeAlerts(1);
  expect(evidence({ ...a, source: "rule", confidence: 1 })[0]).toBe("rule match");
  expect(evidence({ ...a, source: "isolation_forest", confidence: 0.9969 })).toEqual(["rarer than 99.6%", "Anomaly model: score above 99.6% of normal training flows"]);
  expect(evidence({ ...a, source: "isolation_forest", confidence: 1 })[0]).toBe("rarer than all");
  expect(evidence({ ...a, source: "random_forest", confidence: 0.8 })[0]).toBe("classifier 80%");
});

test("rows are ordered by latest activity, not first seen", () => {
  const [a, b] = makeAlerts(2);
  const older = { ...a, attack_type: "Older", timestamp: "2026-10-29T12:00:00.000Z", last_seen: "2026-10-29T12:00:05.000Z" };
  const updated = { ...b, attack_type: "Updated", timestamp: "2026-10-29T11:59:00.000Z", last_seen: "2026-10-29T12:01:00.000Z" };
  render(<Feed alerts={[older, updated]} />);
  expect(bodyRows().map((row) => within(row).queryByText(/Older|Updated/)?.textContent)).toEqual(["Updated", "Older"]);
});

test("an alert is in effect for 30 s after its last activity, then expired", () => {
  const [a, b] = makeAlerts(2);
  const fresh = { ...a, last_seen: "2026-10-29T12:00:00.000Z" }; // 10 s before NOW
  const old = { ...b, last_seen: "2026-10-29T11:59:30.000Z" }; // 40 s before NOW
  render(<Feed alerts={[fresh, old]} />);
  const [first, second] = bodyRows();
  expect(within(first).getByText("in effect · 20 s")).toBeTruthy();
  expect(within(second).getByText("expired")).toBeTruthy();
});

test("a changed row stays marked until it is looked at", () => {
  const [a] = makeAlerts(1);
  render(<Feed alerts={[a]} changed={new Map([[a.id, "updated" as const]])} />);
  const row = bodyRows()[0];
  expect(within(row).getByText("Updated")).toBeTruthy();
  fireEvent.mouseEnter(row);
  expect(within(row).queryByText("Updated")).toBeNull();
});

test("IPv6 endpoints are bracketed", () => {
  expect(endpoint("::1", 52362)).toBe("[::1]:52362");
  expect(endpoint("10.0.0.1", 80)).toBe("10.0.0.1:80");
});
