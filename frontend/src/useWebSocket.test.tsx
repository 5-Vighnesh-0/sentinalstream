import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, expect, test, vi } from "vitest";
import { nextDelay, useWebSocket } from "./useWebSocket";

class FakeSocket {
  static instances: FakeSocket[] = [];
  url: string;
  closedByClient = false;
  onopen?: () => void;
  onmessage?: (event: { data: string }) => void;
  onclose?: () => void;

  constructor(url: string) {
    this.url = url;
    FakeSocket.instances.push(this);
  }
  close() {
    this.closedByClient = true;
  }
}

const latest = () => FakeSocket.instances[FakeSocket.instances.length - 1];

beforeEach(() => {
  FakeSocket.instances = [];
  vi.stubGlobal("WebSocket", FakeSocket);
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

test("backoff doubles from 1 s and caps at 30 s", () => {
  expect([0, 1, 2, 3, 4, 5, 6].map(nextDelay)).toEqual([1000, 2000, 4000, 8000, 16000, 30000, 30000]);
});

test("parses messages, reports status and calls onOpen", () => {
  const onMessage = vi.fn();
  const onOpen = vi.fn();
  const { result } = renderHook(() => useWebSocket("ws://test", { onMessage, onOpen }));
  expect(result.current).toBe("connecting");

  act(() => latest().onopen?.());
  act(() => latest().onmessage?.({ data: '{"type":"alert","data":{"id":"a"}}' }));
  act(() => latest().onmessage?.({ data: "not json" }));

  expect(result.current).toBe("open");
  expect(onOpen).toHaveBeenCalledTimes(1);
  expect(onMessage).toHaveBeenCalledTimes(1);
  expect(onMessage).toHaveBeenCalledWith({ type: "alert", data: { id: "a" } });
});

test("reconnects with backoff and resets it after a successful open", () => {
  const { result } = renderHook(() => useWebSocket("ws://test", { onMessage: () => {} }));

  act(() => latest().onclose?.());
  expect(result.current).toBe("reconnecting");
  act(() => vi.advanceTimersByTime(999));
  expect(FakeSocket.instances).toHaveLength(1);
  act(() => vi.advanceTimersByTime(1));
  expect(FakeSocket.instances).toHaveLength(2);

  act(() => latest().onclose?.());
  act(() => vi.advanceTimersByTime(1999));
  expect(FakeSocket.instances).toHaveLength(2);
  act(() => vi.advanceTimersByTime(1));
  expect(FakeSocket.instances).toHaveLength(3);

  act(() => latest().onopen?.());
  act(() => latest().onclose?.());
  act(() => vi.advanceTimersByTime(1000));
  expect(FakeSocket.instances).toHaveLength(4); // back to 1 s after a good connection
});

test("unmount closes the socket and stops reconnecting", () => {
  const { unmount } = renderHook(() => useWebSocket("ws://test", { onMessage: () => {} }));
  const socket = latest();
  unmount();
  act(() => socket.onclose?.());
  act(() => vi.advanceTimersByTime(60_000));
  expect(socket.closedByClient).toBe(true);
  expect(FakeSocket.instances).toHaveLength(1);
});
