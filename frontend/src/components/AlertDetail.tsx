import { BellOff, Check, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { RuleIn } from "../api";
import { DETECTOR, clockTime, endpoint, evidence, type AlertItem } from "./AlertFeed";
import { LevelChip, inEffect, typeLabel } from "./Level";
import MuteEditor from "./MuteEditor";

type Props = {
  alert: AlertItem;
  clock: number;
  onClose: () => void;
  onAck: (id: string, acknowledged: boolean) => Promise<void>;
  onMute: (rule: RuleIn) => Promise<void>;
};

/** One alert's facts in labelled segments, opened in place under its row; the evidence segment spells out its number.
 *  Focus moves to the heading on open; Escape or the close button returns it to the row. */
export default function AlertDetail({ alert, clock, onClose, onAck, onMute }: Props) {
  const heading = useRef<HTMLHeadingElement>(null);
  const [muting, setMuting] = useState(false);
  const [result, setResult] = useState("");
  useEffect(() => heading.current?.focus(), [alert.id]);
  const capture = alert.batch_id !== null;
  const segments: [string, React.ReactNode, string?][] = [ // third item: column span, so no row ends in an empty cell
    ["Level", <LevelChip level={alert.severity} state={capture ? "history" : inEffect(alert, clock) ? "active" : "expired"} />],
    ["Detector", DETECTOR[alert.source] ?? alert.source],
    ["Protocol", alert.protocol],
    ["Source", <span className="font-mono break-all">{endpoint(alert.src_ip, alert.src_port)}</span>],
    ["Destination", <span className="font-mono break-all">{endpoint(alert.dst_ip, alert.dst_port)}</span>],
    ["Repeats", <span className="font-mono">{alert.count.toLocaleString("en-US")}</span>],
    ["First seen", <span className="font-mono">{clockTime(alert.timestamp, capture)}</span>],
    ["Last seen", <span className="font-mono">{clockTime(alert.last_seen, capture)}</span>, "sm:col-span-2"],
    ["Evidence", evidence(alert)[1], "col-span-2 sm:col-span-3"],
  ];
  const acked = alert.acknowledged_at !== null;

  async function ack() {
    try {
      await onAck(alert.id, !acked);
      setResult(acked ? "Acknowledgement removed" : "Acknowledged");
    } catch {
      setResult("The backend refused the change. Try again.");
    }
  }
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
          <div key={label} className={`border-t border-hairline px-4 py-3 first:border-t-0 sm:[&:nth-child(-n+3)]:border-t-0 max-sm:[&:nth-child(2)]:border-t-0 ${wide ?? ""}`}>
            <dt className="text-xs font-medium text-muted">{label}</dt>
            <dd className="mt-1 text-sm">{value}</dd>
          </div>
        ))}
      </dl>
      <div className="space-y-3 border-t border-hairline px-4 py-3">
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" onClick={ack} className="inline-flex items-center gap-1.5 rounded bg-accent px-3 py-1.5 text-sm font-semibold text-white hover:bg-accent/90">
            <Check aria-hidden size={15} /> {acked ? "Undo acknowledge" : "Acknowledge"}
          </button>
          <button type="button" aria-expanded={muting} onClick={() => setMuting(!muting)} className="inline-flex items-center gap-1.5 rounded px-3 py-1.5 text-sm font-medium text-accent ring-1 ring-edge hover:bg-accent-tint">
            <BellOff aria-hidden size={15} /> Mute alerts like this
          </button>
          {acked && <span className="text-sm text-muted">Acknowledged <span className="font-mono">{clockTime(alert.acknowledged_at!)}</span></span>}
          {alert.suppressed_by !== null && <span className="text-sm text-muted">Muted by rule {alert.suppressed_by}</span>}
        </div>
        {muting && (
          <MuteEditor
            alert={alert}
            onCancel={() => setMuting(false)}
            onSave={async (rule) => {
              await onMute(rule);
              setMuting(false);
              setResult("Muted: matching alerts are hidden and counted in the feed");
            }}
          />
        )}
        <p aria-live="polite" className="sr-only">{result}</p>
      </div>
    </section>
  );
}
