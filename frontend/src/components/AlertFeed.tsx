import { memo, useMemo, useState } from "react";
import { FEED_LIMIT } from "../config";

export type AlertItem = {
  id: string;
  timestamp: string;
  last_seen: string;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  attack_type: string;
  confidence: number;
  severity: "low" | "medium" | "high";
  source: string;
  count: number;
  batch_id: number | null;
};

const SEVERITY = {
  high: { label: "High", bar: "bg-sev-high" },
  medium: { label: "Medium", bar: "bg-sev-medium" },
  low: { label: "Low", bar: "bg-sev-low" },
} as const;

const SOURCE = { rule: "Port-scan rule", random_forest: "Classifier", isolation_forest: "Anomaly model" } as Record<string, string>;

/** The score means something different per source (docs/ARCHITECTURE.md#detection-logic), so it is never one bare %.
 *  Returns [short cell text, full explanation]. */
export function evidence(alert: AlertItem): [string, string] {
  if (alert.source === "rule") return ["rule match", "Port-scan rule fired; no score is measured"]; // stored as 1.0
  if (alert.source === "isolation_forest") {
    // percentile among benign training scores; round down so it never claims 100%
    const pct = alert.confidence >= 1 ? "100" : String(Math.floor(alert.confidence * 1000 + 1e-9) / 10);
    const rarer = alert.confidence >= 1 ? "rarer than all" : `rarer than ${pct}%`;
    return [rarer, `Anomaly score ${alert.confidence >= 1 ? "above every" : `above ${pct}% of`} normal training flow${alert.confidence >= 1 ? "" : "s"}`];
  }
  const p = `${Math.round(alert.confidence * 100)}%`;
  return [`${p} probability`, `Classifier's probability for ${alert.attack_type}: ${p}`];
}

function formatTime(iso: string, withDate: boolean) {
  const d = new Date(iso);
  return withDate ? d.toLocaleString() : d.toLocaleTimeString();
}

const AlertRow = memo(function AlertRow({ alert, captureTime }: { alert: AlertItem; captureTime: boolean }) {
  const sev = SEVERITY[alert.severity];
  const [text, why] = evidence(alert);
  return (
    <tr className="row-arrived border-t border-hairline">
      <td className="py-2 pr-3">
        <span className="flex items-center gap-2">
          <span aria-hidden className={`h-6 w-1.5 rounded-sm ${sev.bar}`} />
          <span className="font-medium">{sev.label}</span>
        </span>
      </td>
      <td className="py-2 pr-3 whitespace-nowrap text-muted">{formatTime(alert.last_seen, captureTime)}</td>
      <td className="py-2 pr-3">
        <div className="font-medium">{alert.attack_type}</div>
        <div className="text-xs text-muted">{SOURCE[alert.source] ?? alert.source}</div>
      </td>
      <td className="py-2 pr-3 font-mono text-sm whitespace-nowrap">
        {alert.src_ip}:{alert.src_port} → {alert.dst_ip}:{alert.dst_port}
      </td>
      <td className="py-2 pr-3 text-right">{alert.count > 1 ? `×${alert.count}` : ""}</td>
      <td className="py-2 text-right whitespace-nowrap text-muted" title={why}>{text}</td>
    </tr>
  );
});

type Props = { alerts: AlertItem[]; captureTime: boolean };

/** Alerts by latest activity (last_seen) first; filters apply before the 200-row cap so a filter never hides matches beyond it. */
export default function AlertFeed({ alerts, captureTime }: Props) {
  const [severity, setSeverity] = useState("all");
  const [attackType, setAttackType] = useState("all");
  const attackTypes = useMemo(() => [...new Set(alerts.map((a) => a.attack_type))].sort(), [alerts]);
  const matching = useMemo(
    () =>
      alerts
        .filter((a) => (severity === "all" || a.severity === severity) && (attackType === "all" || a.attack_type === attackType))
        // The API pages by first-seen timestamp, but the Time column shows last_seen: order by what is shown.
        .sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen)),
    [alerts, severity, attackType],
  );
  const shown = matching.slice(0, FEED_LIMIT);

  return (
    <section className="rounded-lg border border-hairline bg-surface p-4">
      <div className="mb-3 flex flex-wrap items-end gap-3">
        <h2 className="mr-auto text-lg font-semibold">Alerts</h2>
        <label className="flex flex-col text-sm text-muted">
          Severity
          <select className="mt-1 rounded border border-hairline px-2 py-1 text-ink" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="all">All</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </label>
        <label className="flex flex-col text-sm text-muted">
          Attack type
          <select className="mt-1 rounded border border-hairline px-2 py-1 text-ink" value={attackType} onChange={(e) => setAttackType(e.target.value)}>
            <option value="all">All</option>
            {attackTypes.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </label>
      </div>
      <p className="mb-2 text-sm text-muted">
        Showing {shown.length.toLocaleString("en-US")} of {matching.length.toLocaleString("en-US")}
      </p>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <thead className="text-muted">
            <tr>
              <th className="pb-2 font-normal">Severity</th>
              <th className="pb-2 font-normal">{captureTime ? "Capture time" : "Time"}</th>
              <th className="pb-2 font-normal">Type</th>
              <th className="pb-2 font-normal">Source → destination</th>
              <th className="pb-2 text-right font-normal">Repeats</th>
              <th className="pb-2 text-right font-normal">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((a) => (
              // Remount when the count grows so the arrival highlight plays for updates too.
              <AlertRow key={`${a.id}:${a.count}`} alert={a} captureTime={captureTime} />
            ))}
          </tbody>
        </table>
        {shown.length === 0 && (
          <p className="py-6 text-center text-muted">
            {alerts.length ? "No alerts match these filters." : "No alerts yet. New detections appear here as they happen."}
          </p>
        )}
      </div>
    </section>
  );
}
