import { evidence, type AlertItem } from "./components/AlertFeed";

export const COLUMNS = ["last_seen", "timestamp", "severity", "attack_type", "source", "src_ip", "src_port", "dst_ip", "dst_port",
  "protocol", "count", "evidence", "acknowledged_at", "suppressed_by"] as const;

/** RFC 4180 quoting. A spreadsheet runs a cell starting with = + - @ as a formula, and packet-derived text must not. */
function cell(value: unknown): string {
  let s = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@]/.test(s)) s = `'${s}`;
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCsv(alerts: AlertItem[]): string {
  const rows = alerts.map((a) => COLUMNS.map((c) => cell(c === "evidence" ? evidence(a)[0] : a[c])).join(","));
  return [COLUMNS.join(","), ...rows].join("\r\n") + "\r\n";
}

/** Builds the file in the browser: no endpoint, and the export is exactly what the analyst filtered. */
export function downloadCsv(alerts: AlertItem[], view: string) {
  const stamp = new Date().toISOString().slice(0, 19).replace(/[-:]/g, "").replace("T", "-");
  const url = URL.createObjectURL(new Blob([toCsv(alerts)], { type: "text/csv" }));
  const link = Object.assign(document.createElement("a"), { href: url, download: `sentinelstream-${view}-${stamp}.csv` });
  link.click();
  URL.revokeObjectURL(url);
}
