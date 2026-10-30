import { CircleAlert, WifiOff } from "lucide-react";
import type { SocketStatus } from "../useWebSocket";

type Props = { status: SocketStatus; modelLoaded: boolean | null };

/** Problems that change what the screen means. Demo mode is a fact, not a problem: it lives in the header. */
export default function Banners({ status, modelLoaded }: Props) {
  return (
    <div className="space-y-2">
      {status === "reconnecting" && (
        <p role="status" className="flex items-center gap-2 rounded-md bg-sunk px-3 py-2 text-sm ring-1 ring-edge">
          <WifiOff aria-hidden size={16} className="shrink-0" />
          Lost the connection to the backend at localhost:8000. Reconnecting automatically; the feed and chart are paused.
        </p>
      )}
      {modelLoaded === false && (
        <p role="status" className="flex items-center gap-2 rounded-md bg-sev-medium-tint px-3 py-2 text-sm text-sev-medium-ink">
          <CircleAlert aria-hidden size={16} className="shrink-0" />
          No detection model is loaded, so live detection is off. Check the backend log for the model path.
        </p>
      )}
    </div>
  );
}
