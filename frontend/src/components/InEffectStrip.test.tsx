import { fireEvent, render, screen } from "@testing-library/react";
import { useState } from "react";
import { expect, test } from "vitest";
import type { AlertItem } from "./AlertFeed";
import InEffectStrip from "./InEffectStrip";
import { checkFile } from "./PCAPUpload";

const NOW = Date.parse("2026-10-29T12:00:30.000Z");
const alert = (id: string, severity: AlertItem["severity"], last_seen: string, batch_id: number | null = null) =>
  ({ id, severity, last_seen, batch_id, count: 1 }) as AlertItem;

function Strip({ alerts, capture = false }: { alerts: AlertItem[]; capture?: boolean }) {
  const [severity, setSeverity] = useState("all");
  return (
    <>
      <InEffectStrip alerts={alerts} now={NOW} capture={capture} severity={severity} onSeverity={setSeverity} />
      <output data-testid="filter">{severity}</output>
    </>
  );
}

const live = [
  alert("a", "high", "2026-10-29T12:00:20.000Z"), // 10 s ago: in effect
  alert("b", "low", "2026-10-29T12:00:25.000Z"), // in effect
  alert("c", "high", "2026-10-29T11:59:00.000Z"), // 90 s ago: expired
];

test("counts only alerts still in effect, and says how many expired", () => {
  render(<Strip alerts={live} />);
  expect(screen.getByRole("button", { name: /High 1 in effect/ })).toBeTruthy();
  expect(screen.getByRole("button", { name: /Medium 0 in effect/ })).toBeTruthy();
  expect(screen.getByText("1 earlier alert has expired")).toBeTruthy();
});

test("a level block filters the feed and pressing it again clears the filter", () => {
  render(<Strip alerts={live} />);
  const high = screen.getByRole("button", { name: /High 1/ });
  fireEvent.click(high);
  expect(screen.getByTestId("filter").textContent).toBe("high");
  expect(high.getAttribute("aria-pressed")).toBe("true");
  fireEvent.click(high);
  expect(screen.getByTestId("filter").textContent).toBe("all");
});

test("an uploaded capture counts every alert and never claims anything is in effect", () => {
  render(<Strip alerts={[alert("u", "high", "2020-01-01T00:00:00.000Z", 7)]} capture />);
  expect(screen.getByText("In this capture")).toBeTruthy();
  expect(screen.getByRole("button", { name: /High 1 alerts/ })).toBeTruthy();
});

test("a wrong file is refused before upload", () => {
  expect(checkFile(new File(["x"], "notes.txt"))).toBe("Choose a .pcap or .pcapng file.");
  const big = new File(["x"], "big.pcap");
  Object.defineProperty(big, "size", { value: 51 * 1024 * 1024 });
  expect(checkFile(big)).toBe("That file is larger than 50 MB.");
  expect(checkFile(new File(["x"], "ok.PCAPNG"))).toBe("");
});
