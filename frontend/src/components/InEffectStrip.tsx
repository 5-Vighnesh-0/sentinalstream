import type { AlertItem } from "./AlertFeed";
import { LEVEL, LEVELS, inEffect } from "./Level";

type Props = {
  alerts: AlertItem[];
  now: number;
  capture: boolean; // an uploaded capture: counts are history, nothing is in effect
  severity: string;
  onSeverity: (severity: string) => void;
};

/** One block per level, like the header of a warning bulletin. A level with something in effect is filled;
 *  pressing a block filters the feed to that level, pressing it again clears the filter. */
export default function InEffectStrip({ alerts, now, capture, severity, onSeverity }: Props) {
  const counted = capture ? alerts : alerts.filter((a) => inEffect(a, now));
  const expired = alerts.length - counted.length;
  return (
    <section aria-labelledby="in-effect-heading" className="flex flex-wrap items-center gap-2">
      <h2 id="in-effect-heading" className="mr-1 text-sm font-semibold">
        {capture ? "In this capture" : "In effect now"}
      </h2>
      {LEVELS.map((level) => {
        const n = counted.filter((a) => a.severity === level).length;
        const { label, Icon, solid, tint, line } = LEVEL[level];
        const look = n === 0 ? `border bg-surface ${line}` : capture || level !== "high" ? tint : solid;
        return (
          <button
            key={level}
            type="button"
            aria-pressed={severity === level}
            aria-label={`${label} ${n} ${capture ? "alerts" : "in effect"}`}
            onClick={() => onSeverity(severity === level ? "all" : level)}
            className={`inline-flex min-h-10 items-center gap-2 rounded-md px-3 text-sm font-semibold ${look} ${severity === level ? "ring-2 ring-accent ring-offset-2 ring-offset-page" : ""}`}
          >
            <Icon aria-hidden size={16} strokeWidth={2.25} />
            {label}
            <span className="font-mono">{n}</span>
          </button>
        );
      })}
      {!capture && (
        <p className="ml-1 text-sm text-muted">
          {expired === 0 ? "Nothing expired yet" : `${expired.toLocaleString("en-US")} earlier ${expired === 1 ? "alert has" : "alerts have"} expired`}
        </p>
      )}
    </section>
  );
}
