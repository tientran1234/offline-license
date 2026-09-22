import type { ClockStore } from "./stores.js";

export interface MonotonicClockOptions {
  store: ClockStore;
  /** Persist at most this often. Default: 1 hour. */
  flushIntervalSeconds?: number;
  /** How far back `now` may sit behind the high-water mark before it counts as rollback. Default: 5 minutes. */
  toleranceSeconds?: number;
  /** Unix seconds. Injected for tests. */
  now?: () => number;
}

export interface ClockObservation {
  /** True when the wall clock has moved backwards past the tolerance. */
  rollback: boolean;
  /** The highest time this clock has ever seen. */
  highWater: number;
}

/**
 * Detects the classic offline-license attack: set the system clock back and an
 * expired license looks valid again.
 *
 * The defence is a high-water mark — the latest time ever observed — kept in
 * memory and persisted only occasionally. Checking on every request costs one
 * comparison, no I/O. The mark itself only moves forward, so once a later time
 * has been seen, an earlier one is a rollback no matter how the clock is set.
 *
 * Persisting on a throttle rather than every observation is the trade-off:
 * after a crash, the mark can be up to `flushIntervalSeconds` stale, which
 * bounds how far a rollback can go undetected. Tighten the interval if that
 * window matters more than the write cost.
 */
export class MonotonicClock {
  private readonly store: ClockStore;
  private readonly flushInterval: number;
  private readonly tolerance: number;
  private readonly now: () => number;

  private highWater = 0;
  private lastFlushed = 0;
  private loaded = false;
  private inFlight: Promise<void> | null = null;

  constructor(options: MonotonicClockOptions) {
    this.store = options.store;
    this.flushInterval = options.flushIntervalSeconds ?? 3600;
    this.tolerance = options.toleranceSeconds ?? 300;
    this.now = options.now ?? (() => Math.floor(Date.now() / 1000));
  }

  /** Read the persisted mark. Call once at startup; safe to call again. */
  async load(): Promise<void> {
    const stored = await this.store.read();
    const now = this.now();
    this.highWater = Math.max(stored ?? 0, this.highWater);
    // First run, or a store that was cleared: start from now, and persist it so
    // the *next* run has something to compare against.
    if (stored === null) {
      this.highWater = Math.max(this.highWater, now);
      await this.flush();
    }
    this.lastFlushed = this.lastFlushed || now;
    this.loaded = true;
  }

  /**
   * Record the current time and report whether it went backwards. Synchronous
   * on purpose — this sits on the request path. Persistence happens in the
   * background when the throttle window has elapsed.
   */
  observe(now = this.now()): ClockObservation {
    if (!this.loaded) throw new Error("MonotonicClock.load() must resolve before observe()");

    const rollback = now < this.highWater - this.tolerance;
    if (now > this.highWater) this.highWater = now;

    if (now - this.lastFlushed >= this.flushInterval) {
      void this.flush().catch(() => {
        /* A failed background flush must not take down the request. The next
           observation past the interval will try again. */
      });
    }
    return { rollback, highWater: this.highWater };
  }

  /** Persist the mark now. Concurrent calls share one write. */
  flush(): Promise<void> {
    if (this.inFlight) return this.inFlight;
    const value = this.highWater;
    this.inFlight = this.store
      .write(value)
      .then(() => {
        this.lastFlushed = this.now();
      })
      .finally(() => {
        this.inFlight = null;
      });
    return this.inFlight;
  }

  get mark(): number {
    return this.highWater;
  }
}
