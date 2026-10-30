import { useMemo, useState } from "react";
import { FEED_LIMIT, IN_EFFECT_MS } from "../config";
import { LEVEL, LevelChip, inEffect, type Level } from "./Level";

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
  severity: Level;
  source: string;
  count: number;
  batch_id: number | null;
};

export const DETECTOR = { rule: "Port-scan rule", random_forest: "Classifier", isolation_forest: "Anomaly model" } as Record<string, string>;

/** The score means something different per source (docs/ARCHITECTURE.md#detection-logic), so it is never one bare %.
 *  Returns [short cell text, full explanation]. The text names its detector, so the detector is labelled once. */
export function evidence(alert: AlertItem): [string, string] {
  if (alert.source === "rule") return ["rule match", "Port-scan rule fired; no score is measured"]; // stored as 1.0
  if (alert.source === "isolation_forest") {
    // percentile among benign training scores; round down so it never claims 100%
    const pct = alert.confidence >= 1 ? "100" : String(Math.floor(alert.confidence * 1000 + 1e-9) / 10);
    const rarer = alert.confidence >= 1 ? "rarer than all" : `rarer than ${pct}%`;
    return [rarer, `Anomaly model: score ${alert.confidence >= 1 ? "above every" : `above ${pct}% of`} normal training flow${alert.confidence >= 1 ? "" : "s"}`];
  }
  const p = `${Math.round(alert.confidence * 100)}%`;
  return [`classifier ${p}`, `Classifier's probability for ${alert.attack_type}: ${p}`];
}

/** IPv6 needs brackets before the port, or "::1:52362" is ambiguous. */
export function endpoint(ip: string, port: number) {
  return ip.includes(":") ? `[${ip}]:${port}` : `${ip}:${port}`;
}

function formatTime(iso: string, withDate: boolean) {
  const d = new Date(iso);
  return withDate ? d.toLocaleString() : d.toLocaleTimeString();
}

type RowProps = {
  alert: AlertItem;
  now: number;
  captureTime: boolean;
  changed: "new" | "updated" | undefined;
  selected: boolean;
  onSelect: (id: string) => void;
  onSeen: (id: string) => void;
};

function AlertRow({ alert, now, captureTime, changed, selected, onSelect, onSeen }: RowProps) {
  const active = inEffect(alert, now);
  const [text, why] = evidence(alert);
  const left = Math.ceil((IN_EFFECT_MS - (now - Date.parse(alert.last_seen))) / 1000);
  const seen = () => changed && onSeen(alert.id);
  return (
    <tr
      className={`border-t border-hairline ${changed ? "bg-changed" : selected ? "bg-sunk" : ""} ${!active && !captureTime ? "text-muted" : ""}`}
      aria-selected={selected}
      onMouseEnter={seen}
      onFocus={seen}
    >
      <td className="py-2 pr-3 pl-3">
        <LevelChip level={alert.severity} state={captureTime ? "history" : active ? "active" : "expired"} />
      </td>
      <td className="py-2 pr-3">
        <button
          type="button"
          onClick={() => onSelect(alert.id)}
          aria-label={`${alert.attack_type}, ${LEVEL[alert.severity].label}: show details`}
          className={`-my-1 min-h-7 rounded py-1 font-medium hover:underline ${active || captureTime ? "text-ink" : ""}`}
        >
          {alert.attack_type}
        </button>
      </td>
      <td className="py-2 pr-3 font-mono text-[13px] whitespace-nowrap">
        {endpoint(alert.src_ip, alert.src_port)} <span aria-hidden>→</span>
        <span className="sr-only">to</span> {endpoint(alert.dst_ip, alert.dst_port)}
      </td>
      <td className="py-2 pr-3 text-right font-mono text-[13px]">{alert.count > 1 ? `×${alert.count}` : ""}</td>
      <td className="py-2 pr-3 text-right whitespace-nowrap" title={why}>{text}</td>
      <td className="py-2 pr-3 whitespace-nowrap">
        <span className="font-mono text-[13px]">{formatTime(alert.last_seen, captureTime)}</span>
        {!captureTime && (
          <span className="ml-2 text-xs">{active ? `in effect · ${left} s` : "expired"}</span>
        )}
        {changed && (
          <span className="ml-2 rounded bg-surface px-1.5 py-0.5 text-xs font-semibold text-ink ring-1 ring-hairline">
            {changed === "new" ? "New" : "Updated"}
          </span>
        )}
      </td>
    </tr>
  );
}

type Props = {
  alerts: AlertItem[];
  captureTime: boolean;
  now: number;
  severity: string;
  onSeverity: (severity: string) => void;
  changed: Map<string, "new" | "updated">;
  onSeen: (id: string) => void;
  selectedId: string | null;
  onSelect: (id: string) => void;
};

/** Alerts by latest activity (last_seen) first; filters apply before the 200-row cap so a filter never hides matches beyond it. */
export default function AlertFeed({ alerts, captureTime, now, severity, onSeverity, changed, onSeen, selectedId, onSelect }: Props) {
  const [attackType, setAttackType] = useState("all");
  const attackTypes = useMemo(() => [...new Set(alerts.map((a) => a.attack_type))].sort(), [alerts]);
  const matching = useMemo(
    () =>
      alerts
        .filter((a) => (severity === "all" || a.severity === severity) && (attackType === "all" || a.attack_type === attackType))
        // The API pages by first-seen timestamp, but the feed shows last_seen: order by what is shown.
        .sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen)),
    [alerts, severity, attackType],
  );
  const shown = matching.slice(0, FEED_LIMIT);
  const filtered = severity !== "all" || attackType !== "all";
  const select = "mt-1 min-h-9 rounded border border-edge bg-surface px-2 text-sm text-ink";

  return (
    <section className="rounded-lg border border-hairline bg-surface" aria-labelledby="alerts-heading">
      <div className="flex flex-wrap items-end gap-3 px-4 pt-4 pb-3">
        <div className="mr-auto">
          <h2 id="alerts-heading" className="text-base font-semibold">Alerts</h2>
          <p className="text-sm text-muted">
            Showing {shown.length.toLocaleString("en-US")} of {matching.length.toLocaleString("en-US")}, latest activity first
          </p>
        </div>
        <label className="flex flex-col text-xs font-medium text-muted">
          Severity
          <select className={select} value={severity} onChange={(e) => onSeverity(e.target.value)}>
            <option value="all">All</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </label>
        <label className="flex flex-col text-xs font-medium text-muted">
          Attack type
          <select className={select} value={attackType} onChange={(e) => setAttackType(e.target.value)}>
            <option value="all">All</option>
            {attackTypes.map((t) => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>
        </label>
        {filtered && (
          <button
            type="button"
            className="rounded px-2 py-1.5 text-sm font-medium text-accent hover:bg-accent-tint"
            onClick={() => {
              onSeverity("all");
              setAttackType("all");
            }}
          >
            Clear filters
          </button>
        )}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Alerts, latest activity first</caption>
          <thead className="bg-sunk text-xs text-muted">
            <tr>
              <th className="py-2 pr-3 pl-3 font-medium">Level</th>
              <th className="py-2 pr-3 font-medium">Attack</th>
              <th className="py-2 pr-3 font-medium">Source → destination</th>
              <th className="py-2 pr-3 text-right font-medium">Repeats</th>
              <th className="py-2 pr-3 text-right font-medium">Evidence</th>
              <th className="py-2 pr-3 font-medium">{captureTime ? "Capture time" : "Last activity"}</th>
            </tr>
          </thead>
          <tbody>
            {shown.map((a) => (
              <AlertRow
                key={a.id}
                alert={a}
                now={now}
                captureTime={captureTime}
                changed={changed.get(a.id)}
                selected={a.id === selectedId}
                onSelect={onSelect}
                onSeen={onSeen}
              />
            ))}
          </tbody>
        </table>
        {shown.length === 0 && (
          <p className="px-4 py-8 text-center text-sm text-muted">
            {alerts.length
              ? "No alerts match these filters."
              : captureTime
                ? "This capture produced no alerts."
                : "No alerts yet. New detections appear here as they happen; run the simulator to see one."}
          </p>
        )}
      </div>
    </section>
  );
}
