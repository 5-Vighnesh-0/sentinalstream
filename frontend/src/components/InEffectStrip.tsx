import type { AlertItem } from "./AlertFeed";
import { LEVEL, LEVELS, inEffect } from "./Level";

type Props = {
  alerts: AlertItem[];
  clock: number;
  frozen: boolean; // no data arriving: the counts are as of `clock`, not now
  capture: boolean; // an uploaded capture: counts are history, nothing is in effect
  severity: string;
  activeOnly: boolean;
  onFilter: (severity: string, activeOnly: boolean) => void;
};

/** One block per level, like the header of a warning bulletin: the count is the headline. Only an in-effect High is
 *  filled; an empty level is grey. Pressing a block shows exactly what it counts; pressing it again clears the filter. */
export default function InEffectStrip({ alerts, clock, frozen, capture, severity, activeOnly, onFilter }: Props) {
  const counted = capture ? alerts : alerts.filter((a) => inEffect(a, clock));
  const expired = alerts.length - counted.length;
  const asOf = new Date(clock).toLocaleTimeString();
  return (
    <section aria-labelledby="in-effect-heading" className="space-y-2">
      <div className="flex flex-wrap items-baseline gap-x-3">
        <h2 id="in-effect-heading" className="text-lg font-semibold">
          {capture ? "In this capture" : frozen ? `In effect as of ${asOf}` : "In effect now"}
        </h2>
        {!capture && (
          <p className={`text-sm ${frozen ? "font-medium text-stale" : "text-muted"}`}>
            {frozen
              ? "No new data: counts are held until the connection is back"
              : expired === 0
                ? "Nothing has expired yet"
                : `${expired.toLocaleString("en-US")} earlier ${expired === 1 ? "alert has" : "alerts have"} expired`}
          </p>
        )}
      </div>
      <div className="grid grid-cols-3 gap-2 sm:flex">
        {LEVELS.map((level) => {
          const n = counted.filter((a) => a.severity === level).length;
          const { label, Icon, solid, tint, icon } = LEVEL[level];
          const pressed = severity === level && activeOnly === !capture;
          const look =
            n === 0 || frozen ? "bg-surface text-muted ring-1 ring-hairline" : level === "high" && !capture ? solid : tint;
          return (
            <button
              key={level}
              type="button"
              aria-pressed={pressed}
              aria-label={`${label} ${n} ${capture ? "alerts" : "in effect"}`}
              onClick={() => onFilter(pressed ? "all" : level, !capture && !pressed)}
              className={`flex min-h-16 flex-col justify-between rounded-md px-3 py-2 text-left sm:w-44 ${look} ${pressed ? "ring-2 ring-accent ring-offset-2 ring-offset-page" : ""}`}
            >
              <span className="flex items-center gap-1.5 text-sm font-semibold">
                <Icon aria-hidden size={15} strokeWidth={2.25} className={n === 0 || frozen ? icon : undefined} />
                {label}
              </span>
              <span className="font-mono text-2xl leading-none font-semibold">{n}</span>
            </button>
          );
        })}
      </div>
    </section>
  );
}
