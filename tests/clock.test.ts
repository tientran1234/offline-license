import { mkdtemp, readdir, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FileStore, issue, MemoryStore, MonotonicClock, verify } from "../src/index.js";
import { claims, keys, NOW } from "./helpers.js";

/** A clock whose "now" the test controls. */
function controlled(store = new MemoryStore(), opts: { flush?: number; tolerance?: number } = {}) {
  let t = NOW;
  const clock = new MonotonicClock({
    store,
    now: () => t,
    ...(opts.flush !== undefined ? { flushIntervalSeconds: opts.flush } : {}),
    ...(opts.tolerance !== undefined ? { toleranceSeconds: opts.tolerance } : {}),
  });
  return { clock, store, set: (seconds: number) => (t = seconds) };
}

describe("MonotonicClock", () => {
  it("starts from now on first run and persists that immediately", async () => {
    const { clock, store } = controlled();
    await clock.load();
    expect(clock.mark).toBe(NOW);
    expect(await store.read()).toBe(NOW);
  });

  it("resumes from the persisted mark, even if the wall clock is now earlier", async () => {
    const store = new MemoryStore();
    await store.write(NOW + 10_000);
    const { clock } = controlled(store);
    await clock.load();
    expect(clock.mark).toBe(NOW + 10_000);
  });

  it("refuses to observe before load()", () => {
    const { clock } = controlled();
    expect(() => clock.observe()).toThrow(/load\(\)/);
  });

  it("flags a rollback past the tolerance, and only past it", async () => {
    const { clock, set } = controlled(undefined, { tolerance: 300 });
    await clock.load();
    set(NOW + 5_000);
    expect(clock.observe().rollback).toBe(false);

    set(NOW + 5_000 - 299); // inside tolerance: ordinary NTP jitter
    expect(clock.observe().rollback).toBe(false);

    set(NOW + 5_000 - 301); // past it: someone moved the clock
    expect(clock.observe().rollback).toBe(true);
  });

  it("never lowers the mark, so a rollback stays detected on every later call", async () => {
    const { clock, set } = controlled(undefined, { tolerance: 0 });
    await clock.load();
    set(NOW + 1000);
    clock.observe();
    set(NOW);
    expect(clock.observe().rollback).toBe(true);
    expect(clock.observe().rollback).toBe(true);
    expect(clock.mark).toBe(NOW + 1000);
  });

  it("does not touch the store on the hot path until the flush interval elapses", async () => {
    let writes = 0;
    const store: MemoryStore = new (class extends MemoryStore {
      override async write(v: number) {
        writes++;
        return super.write(v);
      }
    })();
    const { clock, set } = controlled(store, { flush: 3600 });
    await clock.load();
    expect(writes).toBe(1); // the first-run persist

    for (let i = 1; i <= 100; i++) {
      set(NOW + i);
      clock.observe();
    }
    expect(writes).toBe(1);

    set(NOW + 3600);
    clock.observe();
    await clock.flush();
    expect(writes).toBe(2);
    expect(await store.read()).toBe(NOW + 3600);
  });

  it("collapses concurrent flushes into one write", async () => {
    let writes = 0;
    const store: MemoryStore = new (class extends MemoryStore {
      override async write(v: number) {
        writes++;
        await new Promise((r) => setTimeout(r, 5));
        return super.write(v);
      }
    })();
    const { clock } = controlled(store);
    await clock.load();
    writes = 0;
    await Promise.all([clock.flush(), clock.flush(), clock.flush()]);
    expect(writes).toBe(1);
  });

  it("makes verify() fail with clock_rollback", async () => {
    const { clock, set } = controlled(undefined, { tolerance: 0 });
    await clock.load();
    set(NOW + 1000);
    clock.observe();
    set(NOW);
    const token = issue(keys.privateKey, claims());
    expect(verify(keys.publicKey, token, { now: () => NOW, clock })).toMatchObject({
      ok: false,
      reason: "clock_rollback",
    });
  });
});

describe("FileStore", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "offline-license-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("reads null when nothing was written yet", async () => {
    expect(await new FileStore(join(dir, "clock")).read()).toBeNull();
  });

  it("round-trips a value and leaves no temp files behind", async () => {
    const store = new FileStore(join(dir, "nested", "clock"));
    await store.write(NOW);
    expect(await store.read()).toBe(NOW);
    expect(await readdir(join(dir, "nested"))).toEqual(["clock"]);
    expect((await readFile(join(dir, "nested", "clock"), "utf8")).trim()).toBe(String(NOW));
  });

  it("treats a corrupted file as absent rather than as time zero", async () => {
    const store = new FileStore(join(dir, "clock"));
    await store.write(NOW);
    const { writeFile } = await import("node:fs/promises");
    await writeFile(join(dir, "clock"), "not a number");
    expect(await store.read()).toBeNull();
  });
});
