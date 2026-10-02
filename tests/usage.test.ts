import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  FileLedgerStore,
  MemoryLedgerStore,
  UsageLedger,
  UsageLedgerError,
  UsageLimitError,
  type LedgerStore,
} from "../src/index.js";
import { at, claims, NOW } from "./helpers.js";

const LIMITS = { exports: 10, seats: 3 };

/** A ledger over a store the test can tamper with, at a "now" it controls. */
function ledger(store: LedgerStore = new MemoryLedgerStore(), over: Parameters<typeof claims>[0] = {}) {
  let t = NOW;
  const usage = new UsageLedger({
    store,
    claims: claims({ limits: LIMITS, ...over }),
    now: () => t,
  });
  return { usage, store, set: (seconds: number) => (t = seconds) };
}

/** Rewrite the stored JSON the way someone with an editor would. */
async function edit(store: LedgerStore, change: (ledger: Record<string, unknown>) => void): Promise<void> {
  const parsed = JSON.parse((await store.read()) ?? "") as Record<string, unknown>;
  change(parsed);
  await store.write(JSON.stringify(parsed));
}

describe("counting against limits", () => {
  it("starts empty when nothing was ever recorded", async () => {
    const { usage } = ledger();
    await usage.load();
    expect(usage.entries).toEqual([]);
    expect(usage.used("exports")).toBe(0);
    expect(usage.remaining("exports")).toBe(10);
    expect(usage.head).toBeNull();
  });

  it("adds up what it recorded, and says what is left", async () => {
    const { usage, set } = ledger();
    await usage.record("exports", 3);
    set(NOW + 60);
    await usage.record("exports", 2);
    await usage.record("seats");

    expect(usage.used("exports")).toBe(5);
    expect(usage.remaining("exports")).toBe(5);
    expect(usage.used("seats")).toBe(1);
    expect(usage.entries).toEqual([
      { key: "exports", amount: 3, at: NOW, mac: expect.any(String) },
      { key: "exports", amount: 2, at: NOW + 60, mac: expect.any(String) },
      { key: "seats", amount: 1, at: NOW + 60, mac: expect.any(String) },
    ]);
  });

  it("refuses the consumption that would pass the cap, and records nothing", async () => {
    const { usage } = ledger();
    await usage.record("exports", 9);
    await expect(usage.record("exports", 2)).rejects.toThrow(UsageLimitError);
    await expect(usage.record("exports", 2)).rejects.toMatchObject({
      key: "exports",
      cap: 10,
      used: 9,
      requested: 2,
    });
    expect(usage.used("exports")).toBe(9);
    expect(usage.entries).toHaveLength(1);
  });

  it("lets consumption reach the cap exactly, the way the guard's withinLimit does", async () => {
    const { usage } = ledger();
    await usage.record("exports", 10);
    expect(usage.used("exports")).toBe(10);
    expect(usage.remaining("exports")).toBe(0);
    expect(usage.withinLimit("exports")).toBe(false);
    await expect(usage.record("exports")).rejects.toThrow(UsageLimitError);
  });

  it("allows everything for a key the license caps nowhere", async () => {
    const { usage } = ledger();
    await usage.record("api_calls", 1_000_000);
    expect(usage.limit("api_calls")).toBeNull();
    // Uncapped is not "nothing left": null says the license sets no cap at all.
    expect(usage.remaining("api_calls")).toBeNull();
    expect(usage.withinLimit("api_calls", 1_000_000)).toBe(true);
  });

  it("takes only a positive whole amount, so a total cannot drift or run backwards", async () => {
    const { usage } = ledger();
    for (const amount of [0, -1, 1.5, NaN, Infinity]) {
      await expect(usage.record("exports", amount), `amount ${amount}`).rejects.toThrow(TypeError);
    }
  });

  it("refuses to answer before load(), rather than answering zero", () => {
    const { usage } = ledger();
    expect(() => usage.used("exports")).toThrow(/load\(\)/);
    expect(() => usage.entries).toThrow(/load\(\)/);
    expect(() => usage.head).toThrow(/load\(\)/);
  });

  it("re-reads the store before appending, so a second window's entries survive", async () => {
    const store = new MemoryLedgerStore();
    const { usage: first } = ledger(store);
    const { usage: second } = ledger(store);
    await first.load();
    await second.load();

    await first.record("exports", 4);
    await second.record("exports", 3); // loaded when the ledger was empty

    expect(second.used("exports")).toBe(7);
    await first.load();
    expect(first.used("exports")).toBe(7);
  });

  it("counts a second window's entries towards the cap it checks", async () => {
    const store = new MemoryLedgerStore();
    const { usage: first } = ledger(store);
    const { usage: second } = ledger(store);
    await first.record("exports", 8);
    await expect(second.record("exports", 5)).rejects.toMatchObject({ used: 8 });
  });
});

describe("the chain", () => {
  it("notices an amount someone edited", async () => {
    const { usage, store } = ledger();
    await usage.record("exports", 2);
    await edit(store, (l) => {
      (l.entries as { amount: number }[])[0]!.amount = 1;
    });

    const { usage: reopened } = ledger(store);
    await expect(reopened.load()).rejects.toThrow(UsageLedgerError);
    await expect(reopened.load()).rejects.toMatchObject({ reason: "broken_chain" });
  });

  it("notices an entry dropped from the middle, and a pair swapped", async () => {
    const { usage, store } = ledger();
    await usage.record("exports", 1);
    await usage.record("exports", 2);
    await usage.record("exports", 3);
    const original = (await store.read()) ?? "";

    await edit(store, (l) => {
      (l.entries as unknown[]).splice(1, 1);
    });
    await expect(ledger(store).usage.load()).rejects.toMatchObject({ reason: "broken_chain" });

    await store.write(original);
    await edit(store, (l) => {
      const entries = l.entries as unknown[];
      [entries[0], entries[1]] = [entries[1]!, entries[0]!];
    });
    await expect(ledger(store).usage.load()).rejects.toMatchObject({ reason: "broken_chain" });
  });

  it("notices an entry invented out of another one's mac", async () => {
    const { usage, store } = ledger();
    await usage.record("exports", 1);
    // Copying a mac that verified once is the cheapest forgery there is: the
    // message it covers includes the mac before it, so a copy lands out of place.
    await edit(store, (l) => {
      const entries = l.entries as Record<string, unknown>[];
      entries.push({ ...entries[0]! });
    });
    await expect(ledger(store).usage.load()).rejects.toMatchObject({ reason: "broken_chain" });
  });

  it("notices a ledger moved from another license, by the field and by the macs", async () => {
    const { usage, store } = ledger();
    await usage.record("exports", 1);

    const { usage: other } = ledger(store, { id: "lic_other" });
    await expect(other.load()).rejects.toMatchObject({ reason: "wrong_license" });

    // Relabelled, so only the key the chain is built from is left to catch it.
    await edit(store, (l) => {
      l.license = "lic_other";
    });
    await expect(other.load()).rejects.toMatchObject({ reason: "broken_chain" });
  });

  it("moves the head with every entry, so one string stands for the history", async () => {
    const { usage } = ledger();
    await usage.record("exports", 1);
    const first = usage.head;
    await usage.record("exports", 1);
    expect(usage.head).not.toBe(first);
    expect(usage.head).toBe(usage.entries.at(-1)?.mac);
  });

  it("accepts a ledger it wrote itself, reopened", async () => {
    const { usage, store } = ledger();
    await usage.record("exports", 4);
    await usage.record("seats", 2);

    const { usage: reopened } = ledger(store);
    await reopened.load();
    expect(reopened.used("exports")).toBe(4);
    expect(reopened.used("seats")).toBe(2);
    expect(reopened.head).toBe(usage.head);
  });
});

describe("the stored form", () => {
  it("refuses a version it does not know rather than reading the fields as if they still meant this", async () => {
    const store = new MemoryLedgerStore();
    await store.write(JSON.stringify({ version: 2, license: "lic_test_1", entries: [] }));
    await expect(ledger(store).usage.load()).rejects.toMatchObject({ reason: "malformed" });
  });

  it("refuses an unknown field, because ignoring one would erase it on the next write", async () => {
    const store = new MemoryLedgerStore();
    await store.write(JSON.stringify({ version: 1, license: "lic_test_1", entries: [], note: "hi" }));
    await expect(ledger(store).usage.load()).rejects.toThrow(/unknown field: note/);
  });

  it("refuses an entry that is not one", async () => {
    const shapes = [
      { amount: 1, at: NOW, mac: "m" },
      { key: "exports", amount: 0, at: NOW, mac: "m" },
      { key: "exports", amount: 1.5, at: NOW, mac: "m" },
      { key: "exports", amount: 1, at: "soon", mac: "m" },
      { key: "exports", amount: 1, at: NOW },
      { key: "exports", amount: 1, at: NOW, mac: "m", extra: true },
    ];
    for (const entry of shapes) {
      const store = new MemoryLedgerStore();
      await store.write(JSON.stringify({ version: 1, license: "lic_test_1", entries: [entry] }));
      await expect(ledger(store).usage.load(), JSON.stringify(entry)).rejects.toMatchObject({ reason: "malformed" });
    }
  });

  it("writes one line per entry, so a consumption is one line in a diff", async () => {
    const { usage, store } = ledger();
    await usage.record("exports", 1);
    await usage.record("exports", 2);
    const lines = ((await store.read()) ?? "").trimEnd().split("\n");
    expect(lines).toHaveLength(8); // {, version, license, entries [, two entries, ], }
    expect(lines[4]).toContain('"amount":1');
    expect(lines[5]).toContain('"amount":2');
  });
});

describe("FileLedgerStore", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "offline-license-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("treats a ledger that was never written as a first run", async () => {
    const { usage } = ledger(new FileLedgerStore(join(dir, "usage.json")));
    await usage.load();
    expect(usage.used("exports")).toBe(0);
  });

  it("round-trips through a file and leaves no temp files behind", async () => {
    const path = join(dir, "nested", "usage.json");
    const { usage } = ledger(new FileLedgerStore(path));
    await usage.record("exports", 6);
    await usage.record("seats", 1);

    expect(await readdir(join(dir, "nested"))).toEqual(["usage.json"]);
    const { usage: reopened } = ledger(new FileLedgerStore(path));
    await reopened.load();
    expect(reopened.used("exports")).toBe(6);
    expect(reopened.remaining("exports")).toBe(4);
    expect(JSON.parse(await readFile(path, "utf8"))).toMatchObject({ version: 1, license: "lic_test_1" });
  });

  it("reports a file edited on disk as a broken chain, not as a count it can trust", async () => {
    const path = join(dir, "usage.json");
    const { usage } = ledger(new FileLedgerStore(path));
    await usage.record("exports", 9);

    const text = await readFile(path, "utf8");
    await writeFile(path, text.replace('"amount":9', '"amount":1'));

    const { usage: reopened } = ledger(new FileLedgerStore(path));
    await expect(reopened.load()).rejects.toMatchObject({ reason: "broken_chain" });
  });

  it("reports a truncated file as unusable rather than as an empty quota", async () => {
    const path = join(dir, "usage.json");
    const { usage } = ledger(new FileLedgerStore(path));
    await usage.record("exports", 9);
    const text = await readFile(path, "utf8");
    await writeFile(path, text.slice(0, text.length / 2));

    await expect(ledger(new FileLedgerStore(path)).usage.load()).rejects.toMatchObject({ reason: "malformed" });
  });
});
