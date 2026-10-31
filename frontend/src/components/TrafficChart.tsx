import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export type TrafficPoint = { time: string; pps: number };

const INK = "#141b24", MUTED = "#4a5666", HAIRLINE = "#d3dae3"; // index.css tokens; Recharts needs literal colours

/** Packets per second over the last 60 s. One series, so no legend: the title names it and the latest value is shown.
 *  When stats stop arriving the chart dims and says when its data ends, instead of looking live. */
export default function TrafficChart({ points, stale }: { points: TrafficPoint[]; stale: boolean }) {
  const latest = points.length ? points[points.length - 1] : null;
  const label = latest === null ? "waiting for data" : stale ? `stopped at ${latest.time}` : `${Math.round(latest.pps).toLocaleString()} now`;
  return (
    <section className="rounded-lg border border-hairline bg-surface p-4" aria-labelledby="traffic-heading">
      <div className="mb-2 flex flex-wrap items-baseline justify-between gap-x-3">
        <h2 id="traffic-heading" className="text-lg font-semibold">Packets per second</h2>
        <span className={`font-mono text-[13px] ${stale ? "text-stale" : "text-muted"}`}>{label}</span>
      </div>
      <div className={`h-40 rounded bg-sunk/60 py-2 pr-1 ${stale ? "opacity-50" : ""}`} role="img" aria-label={`Packets per second over the last minute, ${label}`}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: 0 }} accessibilityLayer={false}>
            <CartesianGrid vertical={false} stroke={HAIRLINE} />
            <XAxis dataKey="time" tick={{ fill: MUTED, fontSize: 12, fontFamily: "JetBrains Mono Variable, monospace" }} tickLine={false} axisLine={{ stroke: HAIRLINE }} minTickGap={48} />
            <YAxis tick={{ fill: MUTED, fontSize: 12, fontFamily: "JetBrains Mono Variable, monospace" }} tickLine={false} axisLine={false} width={44} allowDecimals={false} />
            <Tooltip formatter={(v) => [Math.round(Number(v)).toLocaleString(), "packets/s"]} cursor={{ stroke: HAIRLINE }} />
            {/* No animation: the chart updates every second and should not wobble. */}
            <Line type="monotone" dataKey="pps" stroke={INK} strokeWidth={1.75} dot={false} isAnimationActive={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
