import type { SocketStatus } from "../useWebSocket";

type Props = { status: SocketStatus; iface: string | null; modelLoaded: boolean | null };

export default function Banners({ status, iface, modelLoaded }: Props) {
  return (
    <div className="space-y-2">
      {status === "reconnecting" && (
        <p role="status" className="rounded border border-sev-high/40 bg-sev-high/10 px-3 py-2 text-sm">
          Lost the connection to the backend at localhost:8000. Reconnecting automatically.
        </p>
      )}
      {modelLoaded === false && (
        <p role="status" className="rounded border border-sev-medium/50 bg-sev-medium/10 px-3 py-2 text-sm">
          No detection model is loaded, so live detection is off. Check the backend log for the model path.
        </p>
      )}
      {iface === "lo" && (
        <p className="rounded border border-hairline bg-surface px-3 py-2 text-sm">
          Demo mode: capturing loopback traffic only, so alerts come from programs on this computer.
        </p>
      )}
    </div>
  );
}
