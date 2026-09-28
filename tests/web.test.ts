import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { bindMachine, issue, LicenseError, MonotonicClock, verify as nodeVerify } from "../src/index.js";
import {
  bindMachine as webBindMachine,
  CLOCK_STORAGE_KEY,
  importPublicKey,
  LicenseGuard,
  LocalStorageStore,
  verify,
  verifyOrThrow,
  type WebStorage,
} from "../src/web.js";
import { at, claims, keys, NOW } from "./helpers.js";
import { FINGERPRINT, vectors } from "./vectors.js";

/**
 * Vitest runs on Node, but the web build only ever touches globalThis.crypto —
 * the same WebCrypto a browser hands it. The imports guard that: nothing here
 * reaches the browser build through ../src/index.js.
 */
describe("the shared vectors, on WebCrypto", () => {
  for (const vector of vectors) {
    it(vector.name, async () => {
      expect(await verify(vector.publicKey, vector.token, vector.options)).toEqual(vector.expected);
      // Both builds against the same table: a verdict that moves on one
      // platform and not the other has to fail somewhere, and it fails here.
      expect(await verify(vector.publicKey, vector.token, vector.options)).toEqual(
        nodeVerify(vector.publicKey, vector.token, vector.options),
      );
    });
  }
});

describe("the browser build stands alone", () => {
  it("pulls in no Node builtin, anywhere in what it imports", async () => {
    // The whole promise of this entry point is that a bundler can take it. One
    // `import { x } from "node:crypto"` three modules down breaks that, and a
    // browser only finds out at runtime — so walk the graph here instead.
    const reached = await runtimeImports("web.ts");
    expect([...reached].sort()).toEqual(["claims.ts", "clock.ts", "core.ts", "localstorage.ts", "web.ts"]);
    for (const file of reached) {
      const source = await readFile(new URL(`../src/${file}`, import.meta.url), "utf8");
      expect(source, `${file} imports a Node builtin`).not.toMatch(/from "node:/);
      expect(source, `${file} uses Buffer`).not.toMatch(/\bBuffer\s*[.(]/);
    }
  });

  it("binds a machine byte-for-byte the way the Node build does", async () => {
    expect(await webBindMachine("lic_7f3a", FINGERPRINT)).toBe(bindMachine("lic_7f3a", FINGERPRINT));
    expect(await webBindMachine("lic_other", FINGERPRINT)).not.toBe(bindMachine("lic_7f3a", FINGERPRINT));
  });

  it("takes an already-imported CryptoKey, so a render loop need not re-parse the PEM", async () => {
    const key = await importPublicKey(keys.publicKey);
    const token = issue(keys.privateKey, claims());
    expect(await verify(key, token, { now: at(NOW) })).toEqual({ ok: true, claims: claims() });
    expect(await verify({ "2026": key }, issue(keys.privateKey, claims({ kid: "2026" })), { now: at(NOW) })).toEqual({
      ok: true,
      claims: claims({ kid: "2026" }),
    });
  });

  it("refuses a PEM it cannot parse rather than calling the license invalid", async () => {
    await expect(importPublicKey("-----BEGIN PUBLIC KEY-----\nnot-a-key\n-----END PUBLIC KEY-----")).rejects.toThrow(
      /could not parse a public key/,
    );
  });

  it("fails a rolled-back clock, sharing the check with the Node build", async () => {
    const clock = new MonotonicClock({ store: new MemoryClockStore(), now: at(NOW) });
    await clock.load();
    const token = issue(keys.privateKey, claims());
    expect(await verify(keys.publicKey, token, { now: at(NOW), clock })).toEqual({ ok: true, claims: claims() });
    expect(await verify(keys.publicKey, token, { now: at(NOW - 86_400), clock })).toEqual({
      ok: false,
      reason: "clock_rollback",
      claims: claims(),
    });
  });

  it("throws the same LicenseError as the Node build", async () => {
    const token = issue(keys.privateKey, claims({ expiresAt: NOW - 86_400 }));
    await expect(verifyOrThrow(keys.publicKey, token, { now: at(NOW) })).rejects.toThrow(LicenseError);
    await expect(verifyOrThrow(keys.publicKey, token, { now: at(NOW) })).rejects.toMatchObject({ reason: "expired" });
  });
});

describe("the browser guard", () => {
  const guard = (over: Parameters<typeof claims>[0] = {}, options = {}) =>
    new LicenseGuard({
      publicKey: keys.publicKey,
      token: issue(keys.privateKey, claims(over)),
      now: at(NOW),
      ...options,
    });

  it("answers entitlement questions", async () => {
    const license = guard();
    expect(await license.hasFeature("sso")).toBe(true);
    expect(await license.hasFeature("billing")).toBe(false);
    expect(await license.limit("seats")).toBe(10);
    expect(await license.withinLimit("seats", 9)).toBe(true);
    expect(await license.withinLimit("seats", 10)).toBe(false);
    expect(await license.withinLimit("projects", 1_000)).toBe(true);
  });

  it("says no to everything once the license is expired", async () => {
    const expired = guard({ expiresAt: NOW - 86_400 });
    expect(await expired.hasFeature("sso")).toBe(false);
    expect(await expired.claims()).toBeNull();
    await expect(expired.assertFeature("sso")).rejects.toMatchObject({ reason: "expired" });
  });

  it("keeps answering inside the grace window, and says it is in grace", async () => {
    const late = guard({ expiresAt: NOW - 86_400 }, { graceSeconds: 7 * 86_400 });
    expect(await late.inGrace()).toBe(true);
    expect(await late.hasFeature("sso")).toBe(true);
    expect(await guard().inGrace()).toBe(false);
  });

  it("separates an invalid license from a missing feature", async () => {
    await expect(guard().assertFeature("billing")).rejects.toMatchObject({ reason: "invalid_claims" });
  });
});

describe("LocalStorageStore", () => {
  it("reads null when nothing was written yet", async () => {
    expect(await new LocalStorageStore({ storage: new FakeStorage() }).read()).toBeNull();
  });

  it("round-trips a value under the key it documents", async () => {
    const storage = new FakeStorage();
    await new LocalStorageStore({ storage }).write(NOW);
    expect(storage.items.get(CLOCK_STORAGE_KEY)).toBe(String(NOW));
    expect(await new LocalStorageStore({ storage }).read()).toBe(NOW);
  });

  it("keeps two guards on one origin apart by key", async () => {
    const storage = new FakeStorage();
    await new LocalStorageStore({ storage, key: "other" }).write(NOW);
    expect(await new LocalStorageStore({ storage }).read()).toBeNull();
    expect(await new LocalStorageStore({ storage, key: "other" }).read()).toBe(NOW);
  });

  it("treats a cleared or corrupted entry as absent rather than as time zero", async () => {
    const storage = new FakeStorage();
    const store = new LocalStorageStore({ storage });
    for (const junk of ["", "   ", "not a number", "NaN", "Infinity"]) {
      storage.items.set(CLOCK_STORAGE_KEY, junk);
      // Zero would be a mark every later clock beats, so it must not be one.
      expect(await store.read(), `read ${JSON.stringify(junk)}`).toBeNull();
    }
  });

  it("never lowers the stored mark, so a stale tab cannot undo a rollback", async () => {
    const storage = new FakeStorage();
    const store = new LocalStorageStore({ storage });
    await store.write(NOW + 1000);
    await store.write(NOW); // a second tab, flushing the mark it loaded yesterday
    expect(await store.read()).toBe(NOW + 1000);
  });

  it("reaches for globalThis.localStorage when given no storage", async () => {
    const storage = new FakeStorage();
    await withAmbientStorage(storage, async () => {
      await new LocalStorageStore().write(NOW);
    });
    expect(storage.items.get(CLOCK_STORAGE_KEY)).toBe(String(NOW));
  });

  it("names the missing API instead of failing on a property of undefined", async () => {
    // Constructing has to be safe: a guard built while a page renders on a
    // server is only unusable once something asks it for the mark.
    const store = new LocalStorageStore();
    await withAmbientStorage(undefined, async () => {
      await expect(store.read()).rejects.toThrow(/localStorage is unavailable/);
    });
  });

  it("carries the high-water mark across page loads, rollback and all", async () => {
    const storage = new FakeStorage();
    let t = NOW;
    const clock = () => new MonotonicClock({ store: new LocalStorageStore({ storage }), now: () => t });

    const first = clock();
    await first.load(); // first run: the mark starts at now and is persisted at once
    t = NOW + 10_000;
    first.observe();
    await first.flush();

    t = NOW; // the page is reloaded with the clock wound back
    const reloaded = clock();
    await reloaded.load();
    expect(reloaded.mark).toBe(NOW + 10_000);
    expect(reloaded.observe().rollback).toBe(true);

    const token = issue(keys.privateKey, claims());
    expect(await verify(keys.publicKey, token, { now: at(NOW), clock: reloaded })).toEqual({
      ok: false,
      reason: "clock_rollback",
      claims: claims(),
    });
  });
});

/** The two methods the store uses, over a Map: localStorage without a browser. */
class FakeStorage implements WebStorage {
  readonly items = new Map<string, string>();
  getItem(key: string): string | null {
    return this.items.get(key) ?? null;
  }
  setItem(key: string, value: string): void {
    this.items.set(key, value);
  }
}

/** Swap globalThis.localStorage for the duration of one check, then put it back. */
async function withAmbientStorage(storage: WebStorage | undefined, fn: () => Promise<void>): Promise<void> {
  const original = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  Object.defineProperty(globalThis, "localStorage", { value: storage, configurable: true, writable: true });
  try {
    await fn();
  } finally {
    if (original) Object.defineProperty(globalThis, "localStorage", original);
    else delete (globalThis as { localStorage?: unknown }).localStorage;
  }
}

/** The modules a bundler would actually pull in: type-only edges are erased. */
async function runtimeImports(entry: string, seen = new Set<string>()): Promise<Set<string>> {
  if (seen.has(entry)) return seen;
  seen.add(entry);
  const source = await readFile(new URL(`../src/${entry}`, import.meta.url), "utf8");
  const runtime = source.replace(/^(?:import|export) type .*$/gm, "");
  for (const match of runtime.matchAll(/from "\.\/([^"]+)\.js"/g)) {
    await runtimeImports(`${match[1]}.ts`, seen);
  }
  return seen;
}

/** A store with nothing behind it, for the checks that are not about storage. */
class MemoryClockStore {
  private value: number | null = null;
  async read() {
    return this.value;
  }
  async write(seconds: number) {
    this.value = seconds;
  }
}
