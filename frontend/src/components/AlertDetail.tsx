import { X } from "lucide-react";
import { DETECTOR, endpoint, evidence, type AlertItem } from "./AlertFeed";
import { LevelChip, inEffect } from "./Level";

type Props = { alert: AlertItem; now: number; onClose: () => void };

/** One alert's facts in labelled segments, read left to right; the evidence segment spells out what its number means. */
export default function AlertDetail({ alert, now, onClose }: Props) {
  const capture = alert.batch_id !== null;
  const time = (iso: string) => (capture ? new Date(iso).toLocaleString() : new Date(iso).toLocaleTimeString());
  const segments: [string, React.ReactNode][] = [
    ["Level", <LevelChip level={alert.severity} state={capture ? "history" : inEffect(alert, now) ? "active" : "expired"} />],
    ["Attack", alert.attack_type],
    ["Source", <span className="font-mono">{endpoint(alert.src_ip, alert.src_port)}</span>],
    ["Destination", <span className="font-mono">{endpoint(alert.dst_ip, alert.dst_port)}</span>],
    ["Protocol", alert.protocol],
    ["Detector", DETECTOR[alert.source] ?? alert.source],
    ["Evidence", evidence(alert)[1]],
    ["First seen", <span className="font-mono">{time(alert.timestamp)}</span>],
    ["Last seen", <span className="font-mono">{time(alert.last_seen)}</span>],
    ["Repeats", <span className="font-mono">{alert.count.toLocaleString("en-US")}</span>],
  ];
  return (
    <section aria-label={`Details: ${alert.attack_type}`} className="rounded-lg border border-hairline bg-surface">
      <div className="flex items-center justify-between border-b border-hairline px-4 py-2">
        <h2 className="text-sm font-semibold">Alert details</h2>
        <button type="button" onClick={onClose} className="inline-flex size-8 items-center justify-center rounded text-muted hover:bg-sunk hover:text-ink" aria-label="Close details">
          <X aria-hidden size={16} />
        </button>
      </div>
      <dl className="grid grid-cols-2 sm:grid-cols-5">
        {segments.map(([label, value]) => (
          <div key={label} className="border-b border-hairline px-4 py-3 sm:border-r sm:[&:nth-child(5n)]:border-r-0">
            <dt className="text-xs font-medium text-muted">{label}</dt>
            <dd className="mt-1 text-sm">{value}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
