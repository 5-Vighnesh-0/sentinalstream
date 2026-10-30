import { expect, test } from "vitest";
import { upsert } from "./App";
import type { AlertItem } from "./components/AlertFeed";

const alert = (id: string, batch_id: number | null, count = 1) => ({ id, batch_id, count }) as AlertItem;

test("an update replaces the old copy and moves to the top", () => {
  const list = upsert([alert("a", null), alert("b", null)], [alert("b", null, 2)]);
  expect(list.map((a) => [a.id, a.count])).toEqual([["b", 2], ["a", 1]]);
});

test("live alerts never evict an upload's alerts", () => {
  const upload = Array.from({ length: 1000 }, (_, i) => alert(`u${i}`, 1));
  const live = Array.from({ length: 1500 }, (_, i) => alert(`l${i}`, null));
  const list = upsert(upsert([], upload), live);
  expect(list.filter((a) => a.batch_id === 1)).toHaveLength(1000);
  expect(list.filter((a) => a.batch_id === null)).toHaveLength(1000);
});
