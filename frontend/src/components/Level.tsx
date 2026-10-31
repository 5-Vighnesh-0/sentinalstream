import { Info, ShieldAlert, TriangleAlert } from "lucide-react";
import { IN_EFFECT_MS } from "../config";
import type { AlertItem } from "./AlertFeed";

export const LEVELS = ["high", "medium", "low"] as const;
export type Level = (typeof LEVELS)[number];

export const LEVEL = {
  high: { label: "High", Icon: ShieldAlert, solid: "bg-sev-high text-white", tint: "bg-sev-high-tint text-sev-high-ink", icon: "text-sev-high" },
  medium: { label: "Medium", Icon: TriangleAlert, solid: "bg-sev-medium text-white", tint: "bg-sev-medium-tint text-sev-medium-ink", icon: "text-sev-medium" },
  low: { label: "Low", Icon: Info, solid: "bg-sev-low text-white", tint: "bg-sev-low-tint text-sev-low-ink", icon: "text-sev-low" },
} as const;

/** Live alerts only: an uploaded capture's alerts are history, never "in effect". `clock` stops while data is not
 *  arriving, so a dropped connection never makes alerts look like they expired. */
export function inEffect(alert: AlertItem, clock: number): boolean {
  return alert.batch_id === null && clock - Date.parse(alert.last_seen) < IN_EFFECT_MS;
}

/** The backend's attack names, as people write them. */
export function typeLabel(type: string) {
  return type === "anomaly" ? "Anomaly" : type;
}

export type ChipState = "active" | "expired" | "history";

/** The level as a word plus an icon whose shape differs per level. Loudness follows what needs attention:
 *  only an in-effect High is solid; other in-effect levels and uploaded history are tinted; expired is a neutral outline. */
export function LevelChip({ level, state }: { level: Level; state: ChipState }) {
  const { label, Icon, solid, tint, icon } = LEVEL[level];
  const look = state === "expired" ? "border border-hairline bg-surface text-muted" : state === "active" && level === "high" ? solid : tint;
  return (
    <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold whitespace-nowrap ${look}`}>
      <Icon aria-hidden size={13} strokeWidth={2.25} className={state === "expired" ? icon : undefined} />
      {label}
    </span>
  );
}
