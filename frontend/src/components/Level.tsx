import { Info, ShieldAlert, TriangleAlert } from "lucide-react";
import { IN_EFFECT_MS } from "../config";
import type { AlertItem } from "./AlertFeed";

export const LEVELS = ["high", "medium", "low"] as const;
export type Level = (typeof LEVELS)[number];

export const LEVEL = {
  high: { label: "High", Icon: ShieldAlert, solid: "bg-sev-high text-white", tint: "bg-sev-high-tint text-sev-high-ink", line: "border-sev-high text-sev-high-ink" },
  medium: { label: "Medium", Icon: TriangleAlert, solid: "bg-sev-medium text-white", tint: "bg-sev-medium-tint text-sev-medium-ink", line: "border-sev-medium text-sev-medium-ink" },
  low: { label: "Low", Icon: Info, solid: "bg-sev-low text-white", tint: "bg-sev-low-tint text-sev-low-ink", line: "border-sev-low text-sev-low-ink" },
} as const;

/** Live alerts only: an uploaded capture's alerts are history, never "in effect". */
export function inEffect(alert: AlertItem, now: number): boolean {
  return alert.batch_id === null && now - Date.parse(alert.last_seen) < IN_EFFECT_MS;
}

export type ChipState = "active" | "expired" | "history";

/** The level as a word plus an icon whose shape differs per level. Form carries state as well as colour:
 *  solid while in effect, outlined once expired, tinted for an uploaded capture (history, never in effect). */
export function LevelChip({ level, state }: { level: Level; state: ChipState }) {
  const { label, Icon, solid, tint, line } = LEVEL[level];
  const look = state === "active" ? solid : state === "history" ? tint : `border bg-surface ${line}`;
  return (
    <span className={`inline-flex items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold whitespace-nowrap ${look}`}>
      <Icon aria-hidden size={13} strokeWidth={2.25} />
      {label}
    </span>
  );
}
