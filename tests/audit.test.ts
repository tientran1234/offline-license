import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  CheckLog,
  CHECK_LOG_VERSION,
  FileCheckLogStore,
  MemoryCheckLogStore,
  type CheckLogStore,
  type VerifyResult,
} from "../src/index.js";
import { claims, NOW } from "./helpers.js";

const passed: VerifyResult = { ok: true, claims: claims() };
const onGrace: VerifyResult = { ok: true, claims: claims(), status: "expired_in_grace" };
const expired: VerifyResult = { ok: false, reason: "expired", claims: claims() };
const junk: VerifyResult = { ok: false, reason: "malformed" };

/** A store that keeps every text written to it, in order. */
function countingStore() {
  const writes: string[] = [];
  const store: CheckLogStore = {
    async read() {
      return writes.at(-1) ?? null;
    },
    async write(text) {
      writes.push(text);
    },
  };
  return { store, writes };
}

/** A log over a store the test can tamper with, at a "now" it controls. */
function logging(store: CheckLogStore = new MemoryCheckLogStore(), options: { max?: number; flush?: number } = {}) {
  let t = NOW;
  const log = new CheckLog({
    store,
    now: () => t,
    ...(options.max !== undefined ? { maxFailures: options.max } : {}),
    ...(options.flush !== undefined ? { flushIntervalSeconds: options.flush } : {}),
  });
  return { log, store, set: (seconds: number) => (t = seconds) };
}

describe("CheckLog", () => {
  it("starts with no history at all, which is not the same as a failure", async () => {
    const { log } = logging();
    await log.load();
    expect(log.lastVerifiedAt).toBeNull();
    expect(log.lastOk).toBeNull();
    expect(log.failures).toEqual([]);
  });

  it("remembers when the license last verified, and which one it was", async () => {
    const { log, set } = logging();
    await log.load();
    log.record(passed);
    set(NOW + 3600);
    log.record(passed);

    expect(log.lastVerifiedAt).toBe(NOW + 3600);
    expect(log.lastOk).toEqual({ at: NOW + 3600, license: "lic_test_1" });
    expect(log.failures).toEqual([]);
  });

  it("keeps the status of a license alive on grace alone, so the page can warn", async () => {
    const { log } = logging();
    await log.load();
    log.record(onGrace);
    expect(log.lastOk).toEqual({ at: NOW, license: "lic_test_1", status: "expired_in_grace" });
  });

  it("records what went wrong, with the license when the failure read that far", async () => {
    const { log, set } = logging();
    await log.load();
    log.record(expired);
    set(NOW + 60);
    log.record(junk);

    expect(log.failures).toEqual([
      { reason: "expired", firstAt: NOW, at: NOW, count: 1, license: "lic_test_1" },
      { reason: "malformed", firstAt: NOW + 60, at: NOW + 60, count: 1 },
    ]);
  });

  it("collapses a run of the same failure into one entry with a count", async () => {
    // The guard re-verifies on every question, so one expired license fails
    // again on every render. Without the run, a small log holds a few
    // milliseconds of one failure and nothing else that ever went wrong.
    const { log, set } = logging(undefined, { max: 20 });
    await log.load();
    log.record(junk);
    for (let i = 1; i <= 500; i++) {
      set(NOW + i);
      log.record(expired);
    }

    expect(log.failures).toHaveLength(2);
    expect(log.failures.at(-1)).toEqual({
      reason: "expired",
      firstAt: NOW + 1,
      at: NOW + 500,
      count: 500,
      license: "lic_test_1",
    });
  });

  it("starts a new run when the reason changes, or when another license fails", async () => {
    const { log } = logging();
    await log.load();
    log.record(expired);
    log.record({ ok: false, reason: "expired", claims: claims({ id: "lic_other" }) });
    log.record(expired);

    expect(log.failures.map((run) => [run.reason, run.license, run.count])).toEqual([
      ["expired", "lic_test_1", 1],
      ["expired", "lic_other", 1],
      ["expired", "lic_test_1", 1],
    ]);
  });

  it("rotates past the limit, dropping the oldest run", async () => {
    const { log } = logging(undefined, { max: 2 });
    await log.load();
    for (const reason of ["malformed", "invalid_signature", "expired"] as const) {
      log.record({ ok: false, reason });
    }
    expect(log.failures.map((run) => run.reason)).toEqual(["invalid_signature", "expired"]);
  });

  it("does not erase the failures when the license starts verifying again", async () => {
    // "It works now" is the state the screen is already in. What the operator
    // came to the page for is what it was doing an hour ago.
    const { log, set } = logging();
    await log.load();
    log.record(expired);
    set(NOW + 3600);
    log.record(passed);

    expect(log.lastVerifiedAt).toBe(NOW + 3600);
    expect(log.failures).toHaveLength(1);
  });

  it("refuses to be read before load(), rather than claiming nothing ever verified", async () => {
    const { log } = logging();
    expect(() => log.failures).toThrow(/load\(\)/);
    expect(() => log.lastOk).toThrow(/load\(\)/);
    await log.load();
    expect(log.failures).toEqual([]);
  });
});

describe("keeping the log across restarts", () => {
  it("round-trips what it stored", async () => {
    const { log, store, set } = logging();
    await log.load();
    log.record(expired);
    set(NOW + 3600);
    log.record(passed);
    await log.flush();

    const next = new CheckLog({ store });
    await next.load();
    expect(next.lastOk).toEqual({ at: NOW + 3600, license: "lic_test_1" });
    expect(next.failures).toEqual([{ reason: "expired", firstAt: NOW, at: NOW, count: 1, license: "lic_test_1" }]);
  });

  it("writes the first check at once, then only on the throttle", async () => {
    const { store, writes } = countingStore();
    const { log, set } = logging(store, { flush: 3600 });
    await log.load();

    // A product that is started and stopped again would otherwise never record
    // that it verified at all.
    log.record(passed);
    expect(writes).toHaveLength(1);
    await log.flush();

    // The guard verifies on every question, and a write per question would put
    // the log on the product's render path.
    for (let i = 1; i <= 100; i++) {
      set(NOW + i);
      log.record(passed);
    }
    expect(writes).toHaveLength(1);

    set(NOW + 3600);
    log.record(passed);
    expect(writes).toHaveLength(2);
  });

  it("writes a new failure the moment it happens, throttle or no throttle", async () => {
    // A crash is exactly when someone is about to open the admin page, and a
    // failure nobody wrote down cannot be reconstructed afterwards.
    const { store, writes } = countingStore();
    const { log, set } = logging(store, { flush: 86_400 });
    await log.load();
    log.record(passed);
    await log.flush();

    set(NOW + 60);
    log.record(expired);
    expect(writes).toHaveLength(2);
    expect(JSON.parse(writes[1] ?? "")).toMatchObject({
      failures: [{ reason: "expired", at: NOW + 60, count: 1 }],
    });

    // A second failure in the same run is not news, so it rides the throttle.
    set(NOW + 120);
    log.record(expired);
    expect(writes).toHaveLength(2);
  });

  it("merges rather than overwrites when a check happened before load() resolved", async () => {
    // The guard is handed the listener in its constructor, so it can answer a
    // question while the file is still being read. Flushing an empty log over
    // the stored one would erase the history the page exists to show.
    const store = new MemoryCheckLogStore();
    const first = logging(store);
    await first.log.load();
    first.log.record(expired);
    await first.log.flush();

    const { log, set } = logging(store);
    set(NOW + 3600);
    log.record({ ok: false, reason: "machine_mismatch", claims: claims() });
    await log.load();
    await log.flush();

    expect(log.failures.map((run) => run.reason)).toEqual(["expired", "machine_mismatch"]);
    const reloaded = logging(store);
    await reloaded.log.load();
    expect(reloaded.log.failures).toHaveLength(2);
  });

  it("keeps the later success when load() finds an older one stored", async () => {
    const store = new MemoryCheckLogStore();
    const first = logging(store);
    await first.log.load();
    first.log.record(passed);
    await first.log.flush();

    const { log, set } = logging(store);
    set(NOW + 86_400);
    log.record(passed);
    await log.load();
    expect(log.lastVerifiedAt).toBe(NOW + 86_400);
  });

  it("collapses concurrent flushes into one write", async () => {
    let writes = 0;
    const store: MemoryCheckLogStore = new (class extends MemoryCheckLogStore {
      override async write(text: string) {
        writes++;
        await new Promise((resolve) => setTimeout(resolve, 5));
        return super.write(text);
      }
    })();
    const { log } = logging(store);
    await log.load();
    await Promise.all([log.flush(), log.flush(), log.flush()]);
    expect(writes).toBe(1);
  });

  it("survives a store that cannot be written, because a log is not a check", async () => {
    const store: CheckLogStore = {
      async read() {
        return null;
      },
      async write() {
        throw new Error("disk full");
      },
    };
    const { log } = logging(store);
    await log.load();
    expect(() => log.record(expired)).not.toThrow();
    expect(log.failures).toHaveLength(1);
  });
});

describe("a stored log this release cannot read", () => {
  const starts = async (stored: string) => {
    const store = new MemoryCheckLogStore();
    await store.write(stored);
    const { log } = logging(store);
    await log.load();
    return log;
  };

  it("is discarded rather than refused — nothing is decided from it", async () => {
    for (const stored of [
      "",
      "   ",
      "not json",
      "[]",
      '{"version":2,"lastOk":null,"failures":[]}',
      '{"version":1,"lastOk":null,"failures":[],"note":"hand-edited"}',
      '{"version":1,"failures":[]}',
      '{"version":1,"lastOk":null,"failures":{}}',
      '{"version":1,"lastOk":{"at":1,"license":"lic","extra":true},"failures":[]}',
      '{"version":1,"lastOk":{"at":1},"failures":[]}',
      '{"version":1,"lastOk":{"at":1,"license":"lic","status":"fine"},"failures":[]}',
      '{"version":1,"lastOk":null,"failures":[{"reason":"nonsense","firstAt":1,"at":1,"count":1}]}',
      '{"version":1,"lastOk":null,"failures":[{"reason":"expired","firstAt":1,"at":1,"count":0}]}',
      '{"version":1,"lastOk":null,"failures":[{"reason":"expired","firstAt":1,"at":1}]}',
    ]) {
      const log = await starts(stored);
      expect(log.lastOk, stored).toBeNull();
      expect(log.failures, stored).toEqual([]);
    }
  });

  it("reads back a log it wrote itself, field for field", async () => {
    const { log, store } = logging();
    await log.load();
    log.record(onGrace);
    log.record(expired);
    await log.flush();
    const written = (await store.read()) ?? "";

    expect(JSON.parse(written)).toEqual({
      version: CHECK_LOG_VERSION,
      lastOk: { at: NOW, license: "lic_test_1", status: "expired_in_grace" },
      failures: [{ reason: "expired", firstAt: NOW, at: NOW, count: 1, license: "lic_test_1" }],
    });

    const reloaded = logging(store);
    await reloaded.log.load();
    await reloaded.log.flush();
    expect(await store.read()).toBe(written);
  });
});

describe("FileCheckLogStore", () => {
  let dir: string;
  beforeEach(async () => {
    dir = await mkdtemp(join(tmpdir(), "offline-license-"));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it("reads null when nothing was ever written", async () => {
    expect(await new FileCheckLogStore(join(dir, "checks.json")).read()).toBeNull();
  });

  it("round-trips a log and leaves no temp files behind", async () => {
    const store = new FileCheckLogStore(join(dir, "nested", "checks.json"));
    const { log } = logging(store);
    await log.load();
    log.record(expired);
    await log.flush();

    expect(await readdir(join(dir, "nested"))).toEqual(["checks.json"]);
    expect(await readFile(join(dir, "nested", "checks.json"), "utf8")).toContain('"reason":"expired"');

    const reloaded = logging(store);
    await reloaded.log.load();
    expect(reloaded.log.failures).toHaveLength(1);
  });

  it("starts the history again when the file was truncated", async () => {
    const path = join(dir, "checks.json");
    const store = new FileCheckLogStore(path);
    const { log } = logging(store);
    await log.load();
    log.record(expired);
    await log.flush();

    await writeFile(path, (await readFile(path, "utf8")).slice(0, 40));
    const reloaded = logging(store);
    await reloaded.log.load();
    expect(reloaded.log.failures).toEqual([]);
  });
});
