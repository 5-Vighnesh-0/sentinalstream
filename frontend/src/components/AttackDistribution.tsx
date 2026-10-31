import { memo } from "react";
import { Bar, BarChart, CartesianGrid, LabelList, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { typeLabel } from "./Level";
import type { AlertItem } from "./AlertFeed";

const INK = "#141b24", MUTED = "#4a5666", HAIRLINE = "#d3dae3", SUNK = "#e9edf2"; // index.css tokens; same as TrafficChart

/** Detections per attack type in the current view. Bars encode magnitude, so one neutral hue; the type is on the axis.
 *  A detection is one flow; an aggregated alert counts each of its repeats. */
export default memo(function AttackDistribution({ alerts }: { alerts: AlertItem[] }) {
  const totals = new Map<string, number>();
  for (const a of alerts) totals.set(a.attack_type, (totals.get(a.attack_type) ?? 0) + a.count);
  const data = [...totals].map(([type, detections]) => ({ type: typeLabel(type), detections })).sort((a, b) => b.detections - a.detections);
  const n = alerts.length;

  return (
    <section className="rounded-lg border border-hairline bg-surface p-4" aria-labelledby="types-heading">
      <h2 id="types-heading" className="text-lg font-semibold">Attack types</h2>
      <p className="mb-2 text-sm text-muted">
        Detections, counting repeats, across the {n.toLocaleString("en-US")} {n === 1 ? "alert" : "alerts"} in this view.
      </p>
      {data.length === 0 ? (
        <p className="py-4 text-sm text-muted">No detections in this view yet.</p>
      ) : (
        <div style={{ height: Math.max(72, data.length * 32) + 16 }} className="rounded bg-sunk/60 py-2" role="img" aria-label={data.map((d) => `${d.type} ${d.detections}`).join(", ")}>
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ top: 0, right: 44, bottom: 0, left: 0 }} accessibilityLayer={false}>
              <CartesianGrid horizontal={false} stroke={HAIRLINE} />
              <XAxis type="number" hide />
              <YAxis type="category" dataKey="type" width={96} tick={{ fill: MUTED, fontSize: 12 }} tickLine={false} axisLine={{ stroke: HAIRLINE }} />
              <Tooltip cursor={{ fill: SUNK }} formatter={(v) => [Number(v).toLocaleString(), "detections"]} />
              <Bar dataKey="detections" fill={INK} barSize={16} radius={[0, 3, 3, 0]} isAnimationActive={false}>
                <LabelList dataKey="detections" position="right" fill={INK} fontSize={12} fontFamily="JetBrains Mono Variable, monospace" />
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </section>
  );
});
