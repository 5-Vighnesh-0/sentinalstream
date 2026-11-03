import gsap from "gsap";
import { useLayoutEffect, useRef } from "react";
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

/** The ink band: a full-bleed charcoal wash where the in-effect counts are the headline, set huge like a bulletin.
 *  While a High is in effect the vermilion seal floods across it (the page's one authored motion: a wipe from the left,
 *  a cross-fade with reduced motion). Pressing a level filters the feed to exactly what it counts. */
export default function InEffectStrip({ alerts, clock, frozen, capture, severity, activeOnly, onFilter }: Props) {
  const counted = capture ? alerts : alerts.filter((a) => inEffect(a, clock));
  const expired = alerts.length - counted.length;
  const asOf = new Date(clock).toLocaleTimeString();
  const highs = counted.filter((a) => a.severity === "high").length;
  const raised = !capture && !frozen && highs > 0;
  const flood = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    const el = flood.current;
    if (!el) return;
    const mm = gsap.matchMedia();
    mm.add({ full: "(prefers-reduced-motion: no-preference)", reduced: "(prefers-reduced-motion: reduce)" }, (ctx) => {
      if (ctx.conditions?.full) {
        if (raised) {
          // always from the left edge, like ink spreading across the band
          gsap.fromTo(el, { clipPath: "inset(0% 100% 0% 0%)", opacity: 1 }, { clipPath: "inset(0% 0% 0% 0%)", duration: 0.7, ease: "expo.out" });
        } else {
          gsap.to(el, { clipPath: "inset(0% 0% 0% 100%)", duration: 0.35, ease: "power2.in" }); // exits faster than it arrives
        }
      } else {
        gsap.to(el, { clipPath: "inset(0% 0% 0% 0%)", opacity: raised ? 1 : 0, duration: 0.2 });
      }
    });
    return () => mm.revert();
  }, [raised]);

  const quiet = raised ? "text-white" : "text-band-muted"; // grey on vermilion would fall below 4.5:1
  return (
    <section aria-labelledby="in-effect-heading" className="relative overflow-hidden bg-band text-band-text">
      <div ref={flood} aria-hidden className="absolute inset-0 bg-sev-high" style={{ clipPath: "inset(0% 100% 0% 0%)" }} />
      <svg aria-hidden className="pointer-events-none absolute inset-0 h-full w-full">
        <rect width="100%" height="100%" filter="url(#ink-grain)" />
      </svg>
      <div className="relative mx-auto max-w-[1440px] px-4 pt-6 pb-9 sm:px-6">
        <div className="flex flex-wrap items-baseline gap-x-4 gap-y-1">
          <h2 id="in-effect-heading" className="font-display text-sm font-bold tracking-[0.18em] uppercase">
            {capture ? "In this capture" : frozen ? `In effect as of ${asOf}` : raised ? "High in effect" : "In effect now"}
          </h2>
          {!capture && (
            <p className={`text-sm ${quiet}`}>
              {frozen
                ? "No new data: counts are held until the connection is back"
                : expired === 0
                  ? "Nothing has expired yet"
                  : `${expired.toLocaleString("en-US")} earlier ${expired === 1 ? "alert has" : "alerts have"} expired`}
            </p>
          )}
        </div>
        <div className="mt-4 grid grid-cols-3 divide-x divide-white/15">
          {LEVELS.map((level) => {
            const n = counted.filter((a) => a.severity === level).length;
            const { label, Icon } = LEVEL[level];
            const pressed = severity === level && activeOnly === !capture;
            const empty = n === 0 || frozen;
            return (
              <button
                key={level}
                type="button"
                aria-pressed={pressed}
                aria-label={`${label} ${n} ${capture ? "alerts" : "in effect"}`}
                onClick={() => onFilter(pressed ? "all" : level, !capture && !pressed)}
                className={`group flex flex-col gap-2 px-4 py-2 text-left first:pl-0 hover:bg-white/5 ${pressed ? "underline decoration-2 underline-offset-8" : ""}`}
              >
                <span className={`flex items-center gap-1.5 text-xs font-semibold tracking-[0.16em] uppercase ${empty ? quiet : ""}`}>
                  <Icon aria-hidden size={14} strokeWidth={2.25} />
                  {label}
                </span>
                <span
                  key={n}
                  className={`count-tick font-display text-5xl leading-none font-extrabold sm:text-7xl ${empty ? `${quiet} opacity-70` : "text-white"}`}
                >
                  {n}
                </span>
              </button>
            );
          })}
        </div>
      </div>
      {/* torn brush edge where the band meets the paper */}
      <svg aria-hidden viewBox="0 0 1200 14" preserveAspectRatio="none" className="absolute bottom-0 left-0 h-3.5 w-full fill-page">
        <path d="M0 14V9c40-3 70 2 120-1s90-5 140-2 60 4 110 1 80-6 130-3 70 5 120 2 90-4 140-1 70 3 120 0 80-5 130-2 60 3 90 1 50-2 100 1V14z" />
      </svg>
    </section>
  );
}
