import type { LedgerStore } from "./ledger.js";
import type { ClockStore } from "./stores.js";

/**
 * The slice of the Web Storage API these stores need. `localStorage` and
 * `sessionStorage` both satisfy it, and so does anything else that keeps a
 * string under a key — which is what makes this testable without a browser.
 */
export interface WebStorage {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/** Namespaced, because the origin's storage belongs to the whole app. */
export const CLOCK_STORAGE_KEY = "offline-license:clock";

/** Where a usage ledger sits, under the same namespace. */
export const USAGE_STORAGE_KEY = "offline-license:usage";

export interface LocalStorageStoreOptions {
  /** Default: `CLOCK_STORAGE_KEY`. */
  key?: string;
  /** Default: `globalThis.localStorage`. Pass `sessionStorage` to forget on close. */
  storage?: WebStorage;
}

/**
 * The browser counterpart to `FileStore`: one string under one key, read back
 * as a number and treated as absent whenever it is not one. A cleared or
 * garbled entry has to look like a first run, never like time zero — time zero
 * is a mark every later clock beats, which switches rollback detection off
 * without saying so.
 *
 * Nothing here mimics the temp-file-then-rename. `setItem` either replaces a
 * key's value or leaves it as it was, so there is no half-written string to
 * read back and no torn write to defend against.
 *
 * The one place this goes further than `FileStore`: a write never lowers what
 * is stored. A file has a single process behind it, while an origin has every
 * tab, each holding its own in-memory mark — and a tab left open since
 * yesterday would otherwise flush its older mark over a newer one, handing back
 * exactly the rollback the mark exists to catch.
 */
export class LocalStorageStore implements ClockStore {
  private readonly key: string;
  private readonly storage: WebStorage | undefined;

  constructor(options: LocalStorageStoreOptions = {}) {
    this.key = options.key ?? CLOCK_STORAGE_KEY;
    this.storage = options.storage;
  }

  async read(): Promise<number | null> {
    return parseMark(resolveStorage(this.storage).getItem(this.key));
  }

  async write(seconds: number): Promise<void> {
    const storage = resolveStorage(this.storage);
    const stored = parseMark(storage.getItem(this.key));
    if (stored !== null && stored >= seconds) return;
    storage.setItem(this.key, String(seconds));
  }
}

export interface LocalStorageLedgerStoreOptions {
  /** Default: `USAGE_STORAGE_KEY`. Give a second license its own. */
  key?: string;
  /** Default: `globalThis.localStorage`. */
  storage?: WebStorage;
}

/**
 * The browser counterpart to `FileLedgerStore`: the ledger as one string under
 * one key.
 *
 * A write replaces what is there, with none of the clock store's refusal to go
 * backwards. It needs none: a ledger is appended to by `record()`, which
 * re-reads the store first, so a tab that loaded an older ledger picks up the
 * other tab's entries before it writes rather than flushing a shorter history
 * over a longer one.
 *
 * An absent key is a first run, the same as a file that was never written. A
 * ledger that is there and does not chain is the broken one, and that verdict
 * belongs to the ledger, not to its storage — so nothing is parsed here.
 */
export class LocalStorageLedgerStore implements LedgerStore {
  private readonly key: string;
  private readonly storage: WebStorage | undefined;

  constructor(options: LocalStorageLedgerStoreOptions = {}) {
    this.key = options.key ?? USAGE_STORAGE_KEY;
    this.storage = options.storage;
  }

  async read(): Promise<string | null> {
    return resolveStorage(this.storage).getItem(this.key);
  }

  async write(text: string): Promise<void> {
    resolveStorage(this.storage).setItem(this.key, text);
  }
}

/**
 * Resolved per call rather than in a constructor: a store built while a page
 * renders on a server must not throw there, and a browser that has withheld
 * storage should be named as such instead of surfacing as a property read on
 * undefined.
 */
function resolveStorage(given: WebStorage | undefined): WebStorage {
  if (given !== undefined) return given;
  let ambient: WebStorage | undefined;
  try {
    // The property access is what throws when site data is blocked, so it is
    // inside the try and not just its result.
    ambient = globalThis.localStorage;
  } catch {
    ambient = undefined;
  }
  if (!ambient) {
    throw new Error(
      "localStorage is unavailable: a browser withholds it when site data is blocked, and a server has none — pass { storage }",
    );
  }
  return ambient;
}

/** Absent, empty and unparsable all mean "no mark", the way a missing file does. */
function parseMark(text: string | null): number | null {
  const trimmed = text?.trim();
  if (!trimmed) return null;
  const seconds = Number(trimmed);
  return Number.isFinite(seconds) ? seconds : null;
}
