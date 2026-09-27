import type { LicenseClaims } from "./claims.js";
import type { MonotonicClock } from "./clock.js";

/**
 * Everything a verifier needs that is neither crypto nor I/O.
 *
 * The Node build and the browser build sign and hash through different APIs,
 * but they must reach the same verdict on the same token. Whatever does not
 * depend on the platform lives here, once, so the two cannot drift: the token
 * prefix, the failure vocabulary, and the order of the time checks.
 */

/** Token version prefix. Part of the signed bytes, so it cannot be swapped. */
export const TOKEN_PREFIX = "lic1";

export type VerifyFailure =
  | "malformed"
  | "invalid_signature"
  | "invalid_claims"
  | "not_yet_valid"
  | "expired"
  | "machine_mismatch"
  | "clock_rollback";

export type VerifyResult =
  /** `status` is present only when the license is inside its grace window. */
  | { ok: true; claims: LicenseClaims; status?: "expired_in_grace" }
  | { ok: false; reason: VerifyFailure; claims?: LicenseClaims };

export interface VerifyOptions {
  /** Unix seconds. Injected for tests; defaults to the wall clock. */
  now?: () => number;
  /** Required when the license carries a machine binding. */
  machineFingerprint?: string;
  /** When given, a rolled-back clock fails verification. */
  clock?: MonotonicClock;
  /** Slack for expiry and notBefore, in seconds. Default: 60. */
  skewSeconds?: number;
  /**
   * Seconds past expiresAt during which the license still verifies, reported as
   * status "expired_in_grace". Default: 0 — expiry blocks the moment it lands.
   */
  graceSeconds?: number;
}

export interface TimeCheckOptions {
  /** Unix seconds, already resolved by the caller. */
  now: number;
  clock?: MonotonicClock | undefined;
  skewSeconds?: number | undefined;
  graceSeconds?: number | undefined;
}

export type TimeCheck =
  | { ok: false; reason: "clock_rollback" | "not_yet_valid" | "expired" }
  | { ok: true; status?: "expired_in_grace" };

/**
 * The clock-dependent checks, in the order the README documents: rollback
 * first, because an expired license looks valid again on a wound-back clock,
 * then notBefore, then expiry.
 *
 * Machine binding is not here — it is a hash, so each build does its own, and
 * it runs last either way.
 */
export function checkTime(claims: LicenseClaims, options: TimeCheckOptions): TimeCheck {
  const { now } = options;
  const skew = options.skewSeconds ?? 60;

  if (options.clock && options.clock.observe(now).rollback) {
    return { ok: false, reason: "clock_rollback" };
  }
  if (claims.notBefore !== undefined && now + skew < claims.notBefore) {
    return { ok: false, reason: "not_yet_valid" };
  }
  if (claims.expiresAt !== undefined && now - skew >= claims.expiresAt) {
    // Grace keeps a just-expired license working so the product can warn about a
    // late renewal instead of locking a paying customer out on the day. The
    // window still ends: grace with no end is no expiry at all.
    if (now - skew >= claims.expiresAt + (options.graceSeconds ?? 0)) {
      return { ok: false, reason: "expired" };
    }
    return { ok: true, status: "expired_in_grace" };
  }
  return { ok: true };
}

export class LicenseError extends Error {
  override readonly name = "LicenseError";
  constructor(
    readonly reason: VerifyFailure,
    readonly claims?: LicenseClaims,
  ) {
    super(`license check failed: ${reason}`);
  }
}
