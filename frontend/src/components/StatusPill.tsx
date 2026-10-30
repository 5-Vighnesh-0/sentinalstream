import { CircleDot, KeyRound, PauseCircle, WifiOff } from "lucide-react";
import type { SocketStatus } from "../useWebSocket";

type Props = { status: SocketStatus; iface: string | null; pps: number | null; lastStatAt: number | null; now: number; stale: boolean };

function ago(ms: number) {
  const s = Math.max(0, Math.round(ms / 1000));
  return s < 60 ? `${s} s ago` : `${Math.round(s / 60)} min ago`;
}

/** Live, stale or offline, said in words and an icon, never colour alone. Announced politely when it changes. */
export default function StatusPill({ status, iface, pps, lastStatAt, now, stale }: Props) {
  let look = "bg-surface text-muted ring-1 ring-hairline";
  let icon = <KeyRound aria-hidden size={14} />;
  let text = "Waiting for the dashboard token";
  let state = ""; // the live region gets only the state word: the visible text changes every second
  if (status === "connecting") {
    text = "Connecting…";
    state = "Connecting";
    icon = <CircleDot aria-hidden size={14} />;
  } else if (status === "reconnecting") {
    look = "bg-sunk text-ink ring-1 ring-edge";
    icon = <WifiOff aria-hidden size={14} />;
    text = "Offline · reconnecting";
    state = "Offline, reconnecting";
  } else if (status === "open" && stale) {
    look = "bg-stale-tint text-stale";
    icon = <PauseCircle aria-hidden size={14} />;
    text = lastStatAt ? `Stale · last data ${ago(now - lastStatAt)}` : "Connected · no data yet";
    state = "Stale: no new data";
  } else if (status === "open") {
    look = "bg-live-tint text-live";
    icon = <span aria-hidden className="dot-live inline-block size-2 rounded-full bg-live" />;
    state = "Live";
    text = ["Live", iface && `capturing on ${iface}`, pps !== null && `${Math.round(pps).toLocaleString()} packets/s`].filter(Boolean).join(" · ");
  }
  return (
    <p className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-sm font-medium ${look}`}>
      {icon}
      <span>{text}</span>
      <span role="status" className="sr-only">{state}</span>
    </p>
  );
}
