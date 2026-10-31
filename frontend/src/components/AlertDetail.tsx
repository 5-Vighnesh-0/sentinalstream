import { X } from "lucide-react";
import { useEffect, useRef } from "react";
import { DETECTOR, clockTime, endpoint, evidence, type AlertItem } from "./AlertFeed";
import { LevelChip, inEffect, typeLabel } from "./Level";

type Props = { alert: AlertItem; clock: number; onClose: () => void };

/** One alert's facts in labelled segments, opened in place under its row; the evidence segment spells out its number.
 *  Focus moves to the heading on open; Escape or the close button returns it to the row. */
export default function AlertDetail({ alert, clock, onClose }: Props) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => heading.current?.focus(), [alert.id]);
  const capture = alert.batch_id !== null;
  const segments: [string, React.ReactNode, boolean?][] = [
    ["Level", <LevelChip level={alert.severity} state={capture ? "history" : inEffect(alert, clock) ? "active" : "expired"} />],
    ["Detector", DETECTOR[alert.source] ?? alert.source],
    ["Protocol", alert.protocol],
    ["Source", <span className="font-mono break-all">{endpoint(alert.src_ip, alert.src_port)}</span>],
    ["Destination", <span className="font-mono break-all">{endpoint(alert.dst_ip, alert.dst_port)}</span>],
    ["Repeats", <span className="font-mono">{alert.count.toLocaleString("en-US")}</span>],
    ["First seen", <span className="font-mono">{clockTime(alert.timestamp, capture)}</span>],
    ["Last seen", <span className="font-mono">{clockTime(alert.last_seen, capture)}</span>],
    ["Evidence", evidence(alert)[1], true],
  ];
  return (
    <section
      aria-labelledby={`detail-${alert.id}`}
      className="rounded-md border border-hairline bg-surface"
      onKeyDown={(e) => e.key === "Escape" && onClose()}
    >
      <div className="flex items-center justify-between border-b border-hairline px-4 py-2">
        <h3 id={`detail-${alert.id}`} ref={heading} tabIndex={-1} className="text-sm font-semibold">
          {typeLabel(alert.attack_type)} details
        </h3>
        <button type="button" onClick={onClose} className="inline-flex size-8 items-center justify-center rounded text-muted hover:bg-sunk hover:text-ink" aria-label="Close details">
          <X aria-hidden size={16} />
        </button>
      </div>
      <dl className="grid grid-cols-2 sm:grid-cols-3">
        {segments.map(([label, value, wide]) => (
          <div key={label} className={`border-t border-hairline px-4 py-3 first:border-t-0 sm:[&:nth-child(-n+3)]:border-t-0 max-sm:[&:nth-child(2)]:border-t-0 ${wide ? "col-span-2 sm:col-span-3" : ""}`}>
            <dt className="text-xs font-medium text-muted">{label}</dt>
            <dd className="mt-1 text-sm">{value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
