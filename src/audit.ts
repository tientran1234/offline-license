import { VERIFY_FAILURES, type VerifyFailure, type VerifyResult } from "./core.js";

/**
 * What the product's license checks have looked like, for the screen that has
 * to explain them.
 *
 * A self-hosted install has nobody to phone when it stops letting people in, so
 * its admin page needs two things of its own: when the license last verified,
 * and what went wrong the last few times it did not. `LicenseGuard({ onCheck })`
 * reports every verdict it reaches, and `CheckLog` is the listener that keeps
 * the little of it worth showing.
 *
 * Nothing here is evidence. The log sits on the customer's disk under no
 * signature, and chaining it the way the usage ledger is chained would claim a
 * guarantee it cannot have: the ledger is chained because a count decides what
 * the product allows, while nothing is ever decided from this file. It is a
 * display — which is also why a log that cannot be read is discarded rather
 * than refused. An unreadable history costs an admin page its history; refusing
 * would cost a paying customer their product.
 */

/** The stored format. Bumped when the shape below changes. */
export const CHECK_LOG_VERSION = 1;

/** What `LicenseGuard({ onCheck })` takes: told the verdict, told nothing else. */
export type CheckListener = (result: VerifyResult) => void;

/** The last check that passed, which is the whole of "last verified at". */
export interface CheckSuccess {
  /** When, in unix seconds. */
  at: number;
  /** The id of the license that passed, so a page can say which one it read. */
  license: string;
  /** Present only when the license was alive on grace alone. */
  status?: "expired_in_grace";
}

/**
 * A run of consecutive checks that failed the same way.
 *
 * A run and not one entry per check: the guard re-verifies on every question it
 * is asked, so an expired license fails again on every render. What an admin
 * page can use is the kind of failure, when it started and when it last
 * happened; keeping each check separately would push every other kind of
 * failure out of a small log within one screen's worth of questions.
 */
export interface CheckFailure {
  reason: VerifyFailure;
  /** When this run started, unix seconds. */
  firstAt: number;
  /** When it last failed this way. */
  at: number;
  /** Checks in the run. One question may be more than one check. */
  count: number;
  /** The license the claims named, when the failure got far enough to read them. */
  license?: string;
}

/** A log as it is stored. */
export interface CheckLogState {
  version: number;
  lastOk: CheckSuccess | null;
  failures: CheckFailure[];
}

/** Where the log is kept. One string, read and written whole, like the ledger's. */
export interface CheckLogStore {
  read(): Promise<string | null>;
  write(text: string): Promise<void>;
}

export interface CheckLogOptions {
  store: CheckLogStore;
  /** How many failure runs to keep. Default: 20. */
  maxFailures?: number;
  /** Persist a repeat failure or a success at most this often. Default: 60 seconds. */
  flushIntervalSeconds?: number;
  /** Unix seconds for new entries. Injected for tests; defaults to the wall clock. */
  now?: () => number;
}

/**
 * The log itself: a rotating list of failure runs, and the one success that
 * "last verified at" is.
 *
 * Successes are not a list. The guard verifies on every question, so a product
 * asking three of them per render produces successes faster than any small log
 * could hold — and a ring filled with them would push out the failures the page
 * exists to show. One timestamp is also all the question needs answering.
 */
export class CheckLog {
  private readonly store: CheckLogStore;
  private readonly maxFailures: number;
  private readonly flushInterval: number;
  private readonly now: () => number;

  private success: CheckSuccess | null = null;
  private runs: CheckFailure[] = [];
  private loaded = false;
  private lastFlushed = 0;
  /** Bumped by anything that changes the log, so a flush can tell it has work. */
  private revision = 0;
  /** The revision the last completed write put in the store. */
  private stored = -1;
  private inFlight: Promise<void> | null = null;
  private queued: Promise<void> | null = null;

  constructor(options: CheckLogOptions) {
    this.store = options.store;
    this.maxFailures = options.maxFailures ?? 20;
    this.flushInterval = options.flushIntervalSeconds ?? 60;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /**
   * Read the stored log, merged with anything recorded already. Call once at
   * startup; safe to call again.
   *
   * Merged, because a guard may be answering questions before this resolves —
   * it is handed the listener in its constructor, and nothing should have to be
   * sequenced around a display. Whatever was stored goes underneath, so a check
   * that happened while the file was being read lands after the history rather
   * than replacing it.
   */
  async load(): Promise<void> {
    const stored = parse(await this.store.read());
    const pending = this.runs;
    this.runs = stored?.failures ?? [];
    for (const run of pending) this.append(run);
    // The later success wins: a log that has already seen a check pass must not
    // report an older "last verified at" than the one it watched happen.
    const wasStored = stored?.lastOk ?? null;
    if (wasStored !== null && (this.success === null || wasStored.at > this.success.at)) this.success = wasStored;
    this.revision++;
    this.loaded = true;
  }

  /**
   * Record one check.
   *
   * A property rather than a method so that it can be handed straight to
   * `LicenseGuard({ onCheck: log.record })` — the one call site that matters —
   * without a wrapper to keep `this`.
   */
  readonly record = (result: VerifyResult, at = this.now()): void => {
    this.revision++;
    let startedRun = false;
    if (result.ok) {
      this.success =
        result.status === undefined
          ? { at, license: result.claims.id }
          : { at, license: result.claims.id, status: result.status };
    } else {
      const license = result.claims?.id;
      startedRun = this.append(
        license === undefined
          ? { reason: result.reason, firstAt: at, at, count: 1 }
          : { reason: result.reason, firstAt: at, at, count: 1, license },
      );
    }

    // Nothing is written before load() has handed over the stored history: an
    // empty log flushed over a full one would erase the failures the page
    // exists to show, which is the opposite of what recording them is for.
    if (!this.loaded) return;

    // A failure is persisted the moment the run starts. It is rare, and it is
    // the one thing an admin page cannot reconstruct after a crash. A success
    // only moves a timestamp, so it rides the throttle — a write per question
    // would put this on the render path. The first check after startup still
    // persists at once, or a product that is started and stopped would never
    // record that it verified at all.
    if (startedRun || at - this.lastFlushed >= this.flushInterval) {
      void this.flush().catch(() => {
        /* A failed background write must not take down the check it is logging.
           The next record past the interval tries again. */
      });
    }
  };

  /** When the license last verified here, or null if it never has. */
  get lastVerifiedAt(): number | null {
    return this.lastOk?.at ?? null;
  }

  /** The last check that passed, with the license it passed for. */
  get lastOk(): CheckSuccess | null {
    this.assertLoaded("lastOk");
    return this.success;
  }

  /** The failure runs, oldest first. */
  get failures(): readonly CheckFailure[] {
    this.assertLoaded("failures");
    return this.runs;
  }

  /**
   * Persist the log now, resolving once what is in memory has been stored.
   *
   * A write already on its way carries an older snapshot, so a caller is not
   * handed it: one more write is queued behind it instead. Handing back the
   * in-flight promise would resolve before the entry the caller is flushing had
   * ever reached the store — which is exactly the case a new failure is flushed
   * for. The queue is one deep because a write stores everything in memory, and
   * a flush with nothing new to store is not a write at all.
   */
  flush(): Promise<void> {
    if (this.inFlight !== null) {
      this.queued ??= this.inFlight
        .catch(() => {
          /* Whether the write before this one failed is its caller's business. */
        })
        .then(() => {
          this.queued = null;
          return this.flush();
        });
      return this.queued;
    }
    if (this.revision === this.stored) return Promise.resolve();

    const snapshot = this.revision;
    const text = serialize({ version: CHECK_LOG_VERSION, lastOk: this.success, failures: this.runs });
    this.inFlight = this.store
      .write(text)
      .then(() => {
        this.stored = snapshot;
        this.lastFlushed = this.now();
      })
      .finally(() => {
        this.inFlight = null;
      });
    return this.inFlight;
  }

  /** Fold a failure onto the run in progress, or start a new one. True if it started one. */
  private append(failure: CheckFailure): boolean {
    const newest = this.runs.at(-1);
    if (newest !== undefined && newest.reason === failure.reason && newest.license === failure.license) {
      newest.firstAt = Math.min(newest.firstAt, failure.firstAt);
      newest.at = Math.max(newest.at, failure.at);
      newest.count += failure.count;
      return false;
    }
    this.runs.push(failure);
    if (this.runs.length > this.maxFailures) this.runs = this.runs.slice(-this.maxFailures);
    return true;
  }

  /**
   * Reading an unloaded log would say "never verified" about an install that
   * has been verifying for a year, and a page that quietly says that is worse
   * than one that fails. Recording to it is never refused, though — see record.
   */
  private assertLoaded(what: string): void {
    if (!this.loaded) throw new Error(`CheckLog.load() must resolve before ${what}`);
  }
}

/**
 * Hand a verdict to a listener, swallowing whatever it throws.
 *
 * An observer watches a check; it does not take part in one. A log whose
 * storage has gone missing, or a listener with a bug in it, must not be able to
 * turn a valid license into an exception on the product's own render path —
 * that would make keeping an audit worse than not keeping one.
 */
export function reportCheck(listener: CheckListener | undefined, result: VerifyResult): void {
  if (listener === undefined) return;
  try {
    listener(result);
  } catch {
    /* The verdict is already decided, and nothing above asked to watch it. */
  }
}

/** The stored form: the envelope indented, one failure run to a line. */
function serialize(state: CheckLogState): string {
  const failures = state.failures.map((run) => `    ${JSON.stringify(run)}`);
  const lines = [
    "{",
    `  "version": ${state.version},`,
    `  "lastOk": ${state.lastOk === null ? "null" : JSON.stringify(state.lastOk)},`,
    '  "failures": [',
    ...(failures.length > 0 ? [failures.join(",\n")] : []),
    "  ]",
    "}",
  ];
  return `${lines.join("\n")}\n`;
}

/**
 * The stored log, or null for anything this release cannot read whole: absent,
 * empty, a later version, a stray field, one run that does not hold together.
 *
 * Half a log is not worth having. Nothing is decided from this file, so there
 * is nothing to be gained by interpreting the readable part — and whatever was
 * not understood would be dropped on the next write anyway, in a file whose
 * whole job is to say what happened.
 */
function parse(text: string | null): CheckLogState | null {
  if (text === null || text.trim() === "") return null;
  try {
    return read(JSON.parse(text));
  } catch {
    return null;
  }
}

/** Throws on anything it cannot read whole; parse() turns that into "no history". */
function read(parsed: unknown): CheckLogState {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new TypeError("expected an object");
  const log = parsed as Record<string, unknown>;
  if (log.version !== CHECK_LOG_VERSION) throw new TypeError(`unsupported version ${JSON.stringify(log.version)}`);

  const stray = Object.keys(log).filter((key) => !["version", "lastOk", "failures"].includes(key));
  if (stray.length > 0) throw new TypeError(`unknown field: ${stray.join(", ")}`);
  if (!("lastOk" in log)) throw new TypeError("lastOk is missing");
  if (!Array.isArray(log.failures)) throw new TypeError("failures must be an array");

  return {
    version: CHECK_LOG_VERSION,
    lastOk: log.lastOk === null ? null : readSuccess(log.lastOk),
    failures: log.failures.map(readFailure),
  };
}

function readSuccess(value: unknown): CheckSuccess {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new TypeError("lastOk must be an object");
  const ok = value as Record<string, unknown>;

  const stray = Object.keys(ok).filter((key) => !["at", "license", "status"].includes(key));
  if (stray.length > 0) throw new TypeError(`lastOk: unknown field: ${stray.join(", ")}`);
  if (typeof ok.at !== "number" || !Number.isFinite(ok.at)) throw new TypeError("lastOk.at must be a number");
  if (typeof ok.license !== "string" || ok.license === "") {
    throw new TypeError("lastOk.license must be a non-empty string");
  }
  if (ok.status !== undefined && ok.status !== "expired_in_grace") {
    throw new TypeError(`lastOk.status: unknown status ${JSON.stringify(ok.status)}`);
  }
  return ok.status === undefined
    ? { at: ok.at, license: ok.license }
    : { at: ok.at, license: ok.license, status: ok.status };
}

function readFailure(value: unknown, index: number): CheckFailure {
  const bad = (message: string) => new TypeError(`failure ${index}: ${message}`);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw bad("expected an object");
  const run = value as Record<string, unknown>;

  const stray = Object.keys(run).filter((key) => !["reason", "firstAt", "at", "count", "license"].includes(key));
  if (stray.length > 0) throw bad(`unknown field: ${stray.join(", ")}`);
  if (!isReason(run.reason)) throw bad(`unknown reason ${JSON.stringify(run.reason)}`);
  if (typeof run.firstAt !== "number" || !Number.isFinite(run.firstAt)) throw bad("firstAt must be a number");
  if (typeof run.at !== "number" || !Number.isFinite(run.at)) throw bad("at must be a number");
  if (!Number.isInteger(run.count) || (run.count as number) <= 0) throw bad("count must be a positive integer");
  if (run.license !== undefined && (typeof run.license !== "string" || run.license === "")) {
    throw bad("license must be a non-empty string");
  }

  const base = { reason: run.reason, firstAt: run.firstAt, at: run.at, count: run.count as number };
  return run.license === undefined ? base : { ...base, license: run.license as string };
}

/** A reason from a file, which may name one this release has never heard of. */
function isReason(value: unknown): value is VerifyFailure {
  return typeof value === "string" && (VERIFY_FAILURES as readonly string[]).includes(value);
}
