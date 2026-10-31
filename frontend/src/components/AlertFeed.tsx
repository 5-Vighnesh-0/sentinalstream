import { ChevronDown, ChevronRight } from "lucide-react";
import { Fragment, memo, useCallback, useMemo, useRef, useState } from "react";
import { FEED_LIMIT, IN_EFFECT_MS } from "../config";
import AlertDetail from "./AlertDetail";
import { LEVEL, LevelChip, inEffect, typeLabel, type Level } from "./Level";

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

// One formatter for every row: building an Intl formatter per call cost ~3 ms, and 200 rows re-render every second.
const TIME = new Intl.DateTimeFormat([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const DATE_TIME = new Intl.DateTimeFormat([], { dateStyle: "short", timeStyle: "medium" });

export function clockTime(iso: string | number, withDate = false) {
  return (withDate ? DATE_TIME : TIME).format(new Date(iso));
}

const SEEN_AFTER_MS = 700; // a pointer passing over a row is not reading it

type RowProps = {
  alert: AlertItem;
  active: boolean;
  secondsLeft: number; // 0 unless active, so expired rows keep equal props and skip re-rendering every second
  frozen: boolean;
  captureTime: boolean;
  changed: "new" | "updated" | undefined;
  open: boolean;
  onToggle: (id: string) => void;
  onSeen: (id: string) => void;
};

/** Below 1280 px a row becomes two lines (level, attack, time / endpoints, evidence), so nothing time-critical is cut off. */
const AlertRow = memo(function AlertRow({ alert, active, secondsLeft, frozen, captureTime, changed, open, onToggle, onSeen }: RowProps) {
  const [text, why] = evidence(alert);
  const dwell = useRef<ReturnType<typeof setTimeout>>();
  const seen = () => changed && onSeen(alert.id);
  const Chevron = open ? ChevronDown : ChevronRight;
  const cell = "max-xl:p-0 xl:py-2 xl:pr-3";
  return (
    <tr
      className={`border-t border-hairline max-xl:grid max-xl:grid-cols-[auto_minmax(0,1fr)_auto] max-xl:items-center max-xl:gap-x-3 max-xl:gap-y-1 max-xl:px-3 max-xl:py-2.5 ${changed ? "bg-changed" : open ? "bg-sunk" : ""}`}
      onMouseEnter={() => (dwell.current = setTimeout(seen, SEEN_AFTER_MS))}
      onMouseLeave={() => clearTimeout(dwell.current)}
      onFocus={seen}
    >
      <td className={`${cell} xl:pl-3`}>
        <LevelChip level={alert.severity} state={captureTime ? "history" : active ? "active" : "expired"} />
      </td>
      <td className={cell}>
        <button
          type="button"
          data-alert={alert.id}
          onClick={() => {
            seen();
            onToggle(alert.id);
          }}
          aria-expanded={open}
          aria-label={`${LEVEL[alert.severity].label} ${typeLabel(alert.attack_type)} from ${endpoint(alert.src_ip, alert.src_port)} at ${clockTime(alert.last_seen, captureTime)}: details`}
          className={`-my-1 inline-flex min-h-7 items-center gap-1 rounded py-1 underline decoration-hairline underline-offset-4 hover:decoration-ink ${active || captureTime ? "font-semibold text-ink" : "text-muted"}`}
        >
          {typeLabel(alert.attack_type)}
          <Chevron aria-hidden size={14} className="text-muted" />
        </button>
      </td>
      <td className={`${cell} font-mono text-[13px] max-xl:order-4 max-xl:col-span-2 xl:whitespace-nowrap ${active || captureTime ? "" : "text-muted"}`}>
        {/* each endpoint stays whole; a narrow row wraps only at the arrow */}
        <span className="whitespace-nowrap">{endpoint(alert.src_ip, alert.src_port)} <span aria-hidden>→</span></span>
        <span className="sr-only">to</span> <span className="whitespace-nowrap">{endpoint(alert.dst_ip, alert.dst_port)}</span>
        {alert.count > 1 && <span className="ml-2 text-muted xl:hidden">×{alert.count}</span>}
      </td>
      <td className={`${cell} text-right font-mono text-[13px] max-xl:hidden`}>{alert.count > 1 ? `×${alert.count}` : ""}</td>
      <td className={`${cell} whitespace-nowrap max-xl:order-5 max-xl:text-right max-xl:text-xs xl:text-right ${active || captureTime ? "" : "text-muted"}`} title={why}>
        {text}
      </td>
      <td className={`${cell} whitespace-nowrap max-xl:order-3 max-xl:text-right ${active || captureTime ? "" : "text-muted"}`}>
        <span className="font-mono text-[13px]">{clockTime(alert.last_seen, captureTime)}</span>
        {changed && (
          <span className="ml-2 rounded bg-surface px-1.5 py-0.5 text-xs font-semibold text-ink ring-1 ring-hairline">
            {changed === "new" ? "New" : "Updated"}
          </span>
        )}
        {!captureTime && active && (
          // the in-effect window as a draining rail; the text says the same for anyone who can't see it
          <span className="mt-1 flex items-center gap-2 text-xs text-muted max-xl:justify-end">
            <span aria-hidden className="h-0.5 w-12 overflow-hidden rounded-full bg-hairline">
              <span className={`block h-full ${frozen ? "bg-edge" : alert.severity === "high" ? "bg-sev-high" : alert.severity === "medium" ? "bg-sev-medium" : "bg-sev-low"}`} style={{ width: `${Math.min(100, ((secondsLeft * 1000) / IN_EFFECT_MS) * 100)}%` }} />
            </span>
            {frozen ? "held" : `${secondsLeft} s left`}
          </span>
        )}
      </td>
    </tr>
  );
});

type Props = {
  alerts: AlertItem[];
  captureTime: boolean;
  clock: number;
  frozen: boolean;
  severity: string;
  activeOnly: boolean;
  onFilter: (severity: string, activeOnly: boolean) => void;
  changed: Map<string, "new" | "updated">;
  onSeen: (id: string) => void;
};

/** Alerts by latest activity (last_seen) first; filters apply before the 200-row cap so a filter never hides matches beyond it.
 *  In effect alerts are always the newest, so one divider separates them from history. */
export default function AlertFeed({ alerts, captureTime, clock, frozen, severity, activeOnly, onFilter, changed, onSeen }: Props) {
  const [attackType, setAttackType] = useState("all");
  const [openId, setOpenId] = useState<string | null>(null);
  const attackTypes = useMemo(() => [...new Set(alerts.map((a) => a.attack_type))].sort(), [alerts]);
  const matching = useMemo(
    () =>
      alerts
        .filter(
          (a) =>
            (severity === "all" || a.severity === severity) &&
            (attackType === "all" || a.attack_type === attackType) &&
            (!activeOnly || inEffect(a, clock)),
        )
        // The API pages by first-seen timestamp, but the feed shows last_seen: order by what is shown.
        .sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen)),
    [alerts, severity, attackType, activeOnly, clock],
  );
  const shown = matching.slice(0, FEED_LIMIT);
  const firstExpired = captureTime ? -1 : shown.findIndex((a) => !inEffect(a, clock));
  const filtered = severity !== "all" || attackType !== "all" || activeOnly;
  const select = "mt-1 min-h-9 rounded border border-edge bg-surface px-2 text-sm text-ink";

  const toggle = useCallback((id: string) => setOpenId((cur) => (cur === id ? null : id)), []);

  function close() {
    // the row's button stays mounted, so hand focus back before the details unmount
    document.querySelector<HTMLElement>(`[data-alert="${openId}"]`)?.focus();
    setOpenId(null);
  }

  return (
    <section className="rounded-lg border border-hairline bg-surface" aria-labelledby="alerts-heading">
      <div className="flex flex-wrap items-end gap-3 px-4 pt-4 pb-3">
        <div className="mr-auto">
          <h2 id="alerts-heading" className="text-lg font-semibold">Alerts</h2>
          <p className="text-sm text-muted">
            Showing {shown.length.toLocaleString("en-US")} of {matching.length.toLocaleString("en-US")}
            {activeOnly ? ", in effect only" : ", latest activity first"}
          </p>
        </div>
        <label className="flex flex-col text-xs font-medium text-muted">
          Severity
          <select className={select} value={severity} onChange={(e) => onFilter(e.target.value, activeOnly)}>
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
              <option key={t} value={t}>{typeLabel(t)}</option>
            ))}
          </select>
        </label>
        {filtered && (
          <button
            type="button"
            className="min-h-9 rounded px-2 text-sm font-medium text-accent hover:bg-accent-tint"
            onClick={() => {
              onFilter("all", false);
              setAttackType("all");
            }}
          >
            Clear filters
          </button>
        )}
      </div>
      <div className="feed-scroll overflow-x-auto">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Alerts, latest activity first. Each attack name opens the alert's details.</caption>
          <thead className="bg-sunk text-xs text-muted max-xl:sr-only">
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
            {shown.map((a, i) => (
              <Fragment key={a.id}>
                {i === firstExpired && (
                  <tr className="max-xl:block">
                    <td colSpan={6} className="border-t border-hairline bg-page px-3 py-1.5 text-xs font-medium text-muted max-xl:block">
                      Expired: no activity for 30 s
                    </td>
                  </tr>
                )}
                <AlertRow
                  alert={a}
                  active={inEffect(a, clock)}
                  secondsLeft={inEffect(a, clock) ? Math.ceil((IN_EFFECT_MS - (clock - Date.parse(a.last_seen))) / 1000) : 0}
                  frozen={frozen}
                  captureTime={captureTime}
                  changed={changed.get(a.id)}
                  open={a.id === openId}
                  onToggle={toggle}
                  onSeen={onSeen}
                />
                {a.id === openId && (
                  <tr className="max-xl:block">
                    <td colSpan={6} className="border-t border-hairline bg-sunk p-3 max-xl:block">
                      <AlertDetail alert={a} clock={clock} onClose={close} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
        {shown.length === 0 && (
          <p className="px-4 py-8 text-center text-sm text-muted">
            {alerts.length
              ? activeOnly
                ? "Nothing at this level is in effect. Clear the filter to see its history."
                : "No alerts match these filters."
              : captureTime
                ? "This capture produced no alerts."
                : "No alerts yet. New detections appear here as they happen; run the simulator to see one."}
          </p>
        )}
      </div>
    </section>
  );
}
