import { expect, test } from "vitest";
import type { AlertItem } from "./components/AlertFeed";
import { COLUMNS, toCsv } from "./csv";

const alert = (over: Partial<AlertItem>) =>
  ({
    id: "a", timestamp: "2026-10-29T12:00:00.000Z", last_seen: "2026-10-29T12:00:05.000Z", src_ip: "127.0.0.1", dst_ip: "127.0.0.1",
    src_port: 40000, dst_port: 20, protocol: "TCP", attack_type: "PortScan", confidence: 1, severity: "high", source: "rule",
    count: 3, batch_id: null, acknowledged_at: null, suppressed_by: null, ...over,
  }) as AlertItem;

test("the header is exactly the documented columns", () => {
  expect(toCsv([]).split("\r\n")[0]).toBe(COLUMNS.join(","));
  expect(COLUMNS).toContain("evidence");
});

test("a row uses each detector's evidence wording", () => {
  const [, row] = toCsv([alert({})]).split("\r\n");
  expect(row.split(",")).toEqual(["2026-10-29T12:00:05.000Z", "2026-10-29T12:00:00.000Z", "high", "PortScan", "rule", "127.0.0.1", "40000",
    "127.0.0.1", "20", "TCP", "3", "rule match", "", ""]);
});

test("commas, quotes and newlines are quoted (RFC 4180)", () => {
  expect(toCsv([alert({ attack_type: 'Web, "attack"' })])).toContain(',"Web, ""attack""",');
  expect(toCsv([alert({ attack_type: "two\nlines" })])).toContain(',"two\nlines",');
});

test("a cell that a spreadsheet would run as a formula is neutralised", () => {
  for (const evil of ["=HYPERLINK(1)", "+1", "-1+2", "@SUM(A1)"]) {
    expect(toCsv([alert({ attack_type: evil })])).toContain(`'${evil}`);
  }
});
