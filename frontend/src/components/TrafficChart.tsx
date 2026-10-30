import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export type TrafficPoint = { time: string; pps: number };

/** Packets per second over the last 60 s. One series, so no legend: the title names it and the latest value is shown. */
export default function TrafficChart({ points }: { points: TrafficPoint[] }) {
  const latest = points.length ? points[points.length - 1].pps : null;
  return (
    <section className="rounded-lg border border-hairline bg-surface p-4">
      <div className="mb-2 flex items-baseline justify-between">
        <h2 className="text-lg font-semibold">Packets per second</h2>
        <span className="text-sm text-muted">{latest === null ? "waiting for data" : `${Math.round(latest).toLocaleString()} now`}</span>
      </div>
      <div className="h-44">
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
            <CartesianGrid vertical={false} stroke="#dde3e8" />
            <XAxis dataKey="time" tick={{ fill: "#5d6c78", fontSize: 11 }} tickLine={false} axisLine={{ stroke: "#c3c2b7" }} minTickGap={40} />
            <YAxis tick={{ fill: "#5d6c78", fontSize: 11 }} tickLine={false} axisLine={false} width={44} allowDecimals={false} />
            <Tooltip formatter={(v) => [Math.round(Number(v)).toLocaleString(), "packets/s"]} cursor={{ stroke: "#c3c2b7" }} />
            {/* No animation: the chart updates every second and should not wobble. */}
            <Line type="monotone" dataKey="pps" stroke="#2a78d6" strokeWidth={2} dot={false} isAnimationActive={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}
