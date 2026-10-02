import type { LicenseClaims } from "./claims.js";

/**
 * Metered limits: what a license has actually been consumed for, counted
 * locally against `limits` and chained so that editing the record shows up.
 *
 * Everything here is platform-free. The chain's HMAC is not — it is the same
 * primitive that binds a machine, keyed by the license id — so each build
 * passes its own `bindMachine` in and exports the `UsageLedger` that results.
 * The format, the chaining and the cap arithmetic live here, once, so a ledger
 * written by an Electron main process reads back in its renderer.
 */

/** The only ledger format that exists. Bumped when this shape changes. */
export const USAGE_LEDGER_VERSION = 1;

/** One consumption, as it sits in the ledger. */
export interface UsageEntry {
  /** Which cap it counts against — a key of the license's `limits`. */
  key: string;
  /** How much was consumed. A positive integer. */
  amount: number;
  /** When, in unix seconds. */
  at: number;
  /** HMAC over this entry and the mac before it, keyed by the license id. */
  mac: string;
}

/** A ledger as it is stored: the entries, plus whose license they belong to. */
export interface Ledger {
  version: number;
  /** The license id the entries were chained under. */
  license: string;
  entries: UsageEntry[];
}

/** Where a ledger is kept. One string, read back whole — the chain needs all of it. */
export interface LedgerStore {
  read(): Promise<string | null>;
  write(text: string): Promise<void>;
}

/**
 * The HMAC the chain is built from: `bindMachine`, in whichever build. Node's
 * is synchronous and the browser's is not, so the signature covers both and
 * the ledger awaits either.
 */
export type LedgerMac = (licenseId: string, message: string) => string | Promise<string>;

/** A stored ledger this license cannot use. `reason` is there because the UIs differ. */
export class UsageLedgerError extends Error {
  override readonly name = "UsageLedgerError";
  constructor(
    readonly reason: "malformed" | "wrong_license" | "broken_chain",
    message: string,
  ) {
    super(message);
  }
}

/** A consumption the cap refuses. Carries the arithmetic, so a UI can explain it. */
export class UsageLimitError extends Error {
  override readonly name = "UsageLimitError";
  constructor(
    readonly key: string,
    readonly cap: number,
    readonly used: number,
    readonly requested: number,
  ) {
    super(`usage limit reached: ${key} allows ${cap}, ${used} already used, ${requested} requested`);
  }
}

export interface ChainedLedgerOptions {
  store: LedgerStore;
  /** The verified claims: their `id` keys the chain and their `limits` are the caps. */
  claims: Pick<LicenseClaims, "id" | "limits">;
  /** The build's HMAC. Supplied by the `UsageLedger` each entry point exports. */
  mac: LedgerMac;
  /** Unix seconds for new entries. Injected for tests; defaults to the wall clock. */
  now?: () => number;
}

/**
 * The ledger itself, less the HMAC.
 *
 * Reads are synchronous off the loaded entries — a product asks "how many left"
 * on a render path — so `load()` has to resolve first, the way the clock's does.
 * Writes are not: `record()` re-reads the store before it appends, because two
 * windows of the same app share one file or one origin, and appending to a copy
 * loaded minutes ago would drop whatever the other one recorded since.
 */
export class ChainedLedger {
  private readonly store: LedgerStore;
  private readonly licenseId: string;
  private readonly limits: Readonly<Record<string, number>>;
  private readonly mac: LedgerMac;
  private readonly now: () => number;

  private current: UsageEntry[] = [];
  private loaded = false;

  constructor(options: ChainedLedgerOptions) {
    this.store = options.store;
    this.licenseId = options.claims.id;
    this.limits = options.claims.limits ?? {};
    this.mac = options.mac;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /**
   * Read the stored ledger and check every link. Call once at startup.
   *
   * Nothing stored is a first run, not an error: a product that has never
   * metered anything has no ledger, and so does one whose file was deleted —
   * see the note on truncation in the README. A ledger that *is* there and does
   * not chain is refused, because that is the case the chain exists to catch.
   */
  async load(): Promise<void> {
    this.current = await this.read();
    this.loaded = true;
  }

  /** Every entry, oldest first. */
  get entries(): readonly UsageEntry[] {
    this.assertLoaded("entries");
    return this.current;
  }

  /**
   * The last mac in the chain, or null for an empty ledger.
   *
   * One short string that stands for the whole history: a product with
   * somewhere else to keep it — a server it syncs with, an MDM profile — can
   * pin it there and notice a ledger that has been rolled back to an earlier
   * head, which the file alone cannot tell it.
   */
  get head(): string | null {
    this.assertLoaded("head");
    return this.current.at(-1)?.mac ?? null;
  }

  /** How much of `key` has been consumed. */
  used(key: string): number {
    this.assertLoaded("used()");
    return total(this.current, key);
  }

  /** The cap for `key`, or null when the license sets none. */
  limit(key: string): number | null {
    return this.limits[key] ?? null;
  }

  /** What is left of `key`, or null when it is uncapped — which is not zero left. */
  remaining(key: string): number | null {
    const cap = this.limit(key);
    return cap === null ? null : Math.max(0, cap - this.used(key));
  }

  /**
   * Whether consuming `amount` more of `key` would stay inside the cap.
   *
   * An uncapped key allows everything, exactly as `LicenseGuard.withinLimit`
   * does, and the arithmetic is the guard's too: consumption may reach the cap
   * and not pass it.
   */
  withinLimit(key: string, amount = 1): boolean {
    const cap = this.limit(key);
    return cap === null || this.used(key) + amount <= cap;
  }

  /**
   * Record a consumption, or refuse it.
   *
   * The store is re-read first, so the cap is checked against what every other
   * window has recorded and not only against what this one loaded. Past the cap
   * nothing is written and `UsageLimitError` carries the numbers.
   */
  async record(key: string, amount = 1): Promise<UsageEntry> {
    if (!Number.isInteger(amount) || amount <= 0) {
      throw new TypeError(`amount must be a positive integer, got ${amount}`);
    }
    const entries = await this.read();
    this.current = entries;
    this.loaded = true;

    const cap = this.limit(key);
    const used = total(entries, key);
    if (cap !== null && used + amount > cap) throw new UsageLimitError(key, cap, used, amount);

    const at = this.now();
    const entry: UsageEntry = { key, amount, at, mac: await this.chain(entries.at(-1)?.mac ?? null, key, amount, at) };
    const next = [...entries, entry];
    await this.store.write(serializeLedger({ version: USAGE_LEDGER_VERSION, license: this.licenseId, entries: next }));
    this.current = next;
    return entry;
  }

  /** Read, parse and verify. Shared by load() and every record(). */
  private async read(): Promise<UsageEntry[]> {
    const text = await this.store.read();
    if (text === null || text.trim() === "") return [];

    const ledger = parseLedger(text);
    if (ledger.license !== this.licenseId) {
      throw new UsageLedgerError(
        "wrong_license",
        `ledger belongs to license ${JSON.stringify(ledger.license)}, not ${JSON.stringify(this.licenseId)}`,
      );
    }
    let previous: string | null = null;
    for (const [index, entry] of ledger.entries.entries()) {
      const expected = await this.chain(previous, entry.key, entry.amount, entry.at);
      if (expected !== entry.mac) {
        throw new UsageLedgerError("broken_chain", `ledger entry ${index} does not match its mac`);
      }
      previous = entry.mac;
    }
    return ledger.entries;
  }

  /**
   * One link: the mac before it, then the entry's own fields.
   *
   * The previous mac is in the message, so an entry cannot be moved, dropped
   * from the middle or inserted without every mac after it going wrong. The
   * fields go in as a JSON array rather than joined by a separator, because a
   * limit key is the caller's string and could otherwise be written to look
   * like two fields. The `usage.` tag keeps these macs from meaning anything
   * where a machine binding is expected, since both are HMACs under the same key.
   */
  private async chain(previous: string | null, key: string, amount: number, at: number): Promise<string> {
    return this.mac(this.licenseId, `usage.${previous ?? ""}.${JSON.stringify([key, amount, at])}`);
  }

  private assertLoaded(what: string): void {
    if (!this.loaded) throw new Error(`UsageLedger.load() must resolve before ${what}`);
  }
}

function total(entries: readonly UsageEntry[], key: string): number {
  let sum = 0;
  for (const entry of entries) if (entry.key === key) sum += entry.amount;
  return sum;
}

/**
 * The stored form: the envelope indented, one entry per line.
 *
 * A ledger only ever grows, so an entry to a line means one consumption is one
 * line in a diff, however many are already there.
 */
export function serializeLedger(ledger: Ledger): string {
  const entries = ledger.entries.map(
    (e) => `    {"key":${JSON.stringify(e.key)},"amount":${e.amount},"at":${e.at},"mac":${JSON.stringify(e.mac)}}`,
  );
  const lines = [
    "{",
    `  "version": ${ledger.version},`,
    `  "license": ${JSON.stringify(ledger.license)},`,
    '  "entries": [',
    ...(entries.length > 0 ? [entries.join(",\n")] : []),
    "  ]",
    "}",
  ];
  return `${lines.join("\n")}\n`;
}

/**
 * Parse a stored ledger, refusing anything this version does not understand.
 *
 * The shape is closed like the license envelope's: an unknown field is a typo
 * or a later format, and reading past it would drop it on the next write — in a
 * file whose whole job is to be complete.
 */
export function parseLedger(text: string): Ledger {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new UsageLedgerError("malformed", `ledger is not JSON (${(err as Error).message})`);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new UsageLedgerError("malformed", "ledger must be a JSON object");
  }
  const l = parsed as Record<string, unknown>;
  if (l.version !== USAGE_LEDGER_VERSION) {
    throw new UsageLedgerError(
      "malformed",
      `unsupported ledger version ${JSON.stringify(l.version)}, expected ${USAGE_LEDGER_VERSION}`,
    );
  }
  const stray = Object.keys(l).filter((k) => !["version", "license", "entries"].includes(k));
  if (stray.length > 0) {
    throw new UsageLedgerError("malformed", `unknown field${stray.length > 1 ? "s" : ""}: ${stray.join(", ")}`);
  }
  if (typeof l.license !== "string" || l.license === "") {
    throw new UsageLedgerError("malformed", "license must be a non-empty string");
  }
  if (!Array.isArray(l.entries)) throw new UsageLedgerError("malformed", "entries must be an array");

  return { version: USAGE_LEDGER_VERSION, license: l.license, entries: l.entries.map(assertEntry) };
}

function assertEntry(value: unknown, index: number): UsageEntry {
  const bad = (message: string) => new UsageLedgerError("malformed", `entry ${index}: ${message}`);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw bad("expected an object");
  const e = value as Record<string, unknown>;

  const stray = Object.keys(e).filter((k) => !["key", "amount", "at", "mac"].includes(k));
  if (stray.length > 0) throw bad(`unknown field${stray.length > 1 ? "s" : ""}: ${stray.join(", ")}`);
  if (typeof e.key !== "string" || e.key === "") throw bad("key must be a non-empty string");
  if (typeof e.mac !== "string" || e.mac === "") throw bad("mac must be a non-empty string");
  if (!Number.isInteger(e.amount) || (e.amount as number) <= 0) throw bad("amount must be a positive integer");
  if (typeof e.at !== "number" || !Number.isFinite(e.at)) throw bad("at must be a number");

  return { key: e.key, amount: e.amount as number, at: e.at, mac: e.mac };
}
