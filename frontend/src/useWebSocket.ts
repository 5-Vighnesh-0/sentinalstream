import { useEffect, useRef, useState } from "react";

export type SocketStatus = "connecting" | "open" | "reconnecting";

const BACKOFF_START_MS = 1000;
const BACKOFF_MAX_MS = 30_000;

export function nextDelay(attempt: number): number {
  return Math.min(BACKOFF_START_MS * 2 ** attempt, BACKOFF_MAX_MS);
}

type Handlers = { onMessage: (message: any) => void; onOpen?: () => void };

/** One WebSocket that reconnects with exponential backoff (1 s, 2 s, 4 s ... 30 s), reset after each good open. */
export function useWebSocket(url: string, handlers: Handlers): SocketStatus {
  const [status, setStatus] = useState<SocketStatus>("connecting");
  const latest = useRef(handlers);
  latest.current = handlers; // callers may pass new closures each render without reconnecting

  useEffect(() => {
    let socket: WebSocket;
    let timer: ReturnType<typeof setTimeout>;
    let attempt = 0;
    let stopped = false;

    const connect = () => {
      socket = new WebSocket(url);
      socket.onopen = () => {
        attempt = 0;
        setStatus("open");
        latest.current.onOpen?.();
      };
      socket.onmessage = (event) => {
        let message;
        try {
          message = JSON.parse(event.data);
        } catch {
          return; // not ours; the server only sends JSON
        }
        latest.current.onMessage(message);
      };
      socket.onclose = () => {
        if (stopped) return;
        setStatus("reconnecting");
        timer = setTimeout(connect, nextDelay(attempt++));
      };
    };

    connect();
    return () => {
      stopped = true;
      clearTimeout(timer);
      socket.close();
    };
  }, [url]);

  return status;
}
