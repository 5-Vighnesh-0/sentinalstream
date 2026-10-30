import { Bar, BarChart, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { AlertItem } from "./AlertFeed";

/** Detections per attack type in the current view. Bars encode magnitude, so one hue; the type is on the axis. */
export default function AttackDistribution({ alerts }: { alerts: AlertItem[] }) {
  const totals = new Map<string, number>();
  for (const a of alerts) totals.set(a.attack_type, (totals.get(a.attack_type) ?? 0) + a.count);
  const data = [...totals].map(([type, detections]) => ({ type, detections })).sort((a, b) => b.detections - a.detections);

  return (
    <section className="rounded-lg border border-hairline bg-surface p-4">
      <h2 className="mb-2 text-lg font-semibold">Attack types</h2>
      {data.length === 0 ? (
        <p className="py-4 text-sm text-muted">No detections in this view yet.</p>
      ) : (
        <div style={{ height: Math.max(80, data.length * 34) }}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ top: 0, right: 40, bottom: 0, left: 0 }}>
              <XAxis type="number" hide />
              <YAxis type="category" dataKey="type" width={96} tick={{ fill: "#16232d", fontSize: 12 }} tickLine={false} axisLine={{ stroke: "#c3c2b7" }} />
              <Tooltip cursor={{ fill: "#f3f5f7" }} formatter={(v) => [Number(v).toLocaleString(), "detections"]} />
              <Bar dataKey="detections" fill="#2a78d6" barSize={18} radius={[0, 4, 4, 0]} isAnimationActive={false}>
                <LabelList dataKey="detections" position="right" fill="#16232d" fontSize={12} />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </section>
  );
}
