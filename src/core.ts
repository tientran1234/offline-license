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

/**
 * The failure vocabulary, as a list so that it also exists at runtime: the
 * check log reads reasons back out of a stored file and has to know which ones
 * this release understands. Two spellings of the same vocabulary would drift.
 */
export const VERIFY_FAILURES = [
  "malformed",
  "invalid_signature",
  "invalid_claims",
  "not_yet_valid",
  "expired",
  "machine_mismatch",
  "clock_rollback",
  "renewal_gap",
] as const;

export type VerifyFailure = (typeof VERIFY_FAILURES)[number];

export type VerifyResult =
  /** `status` is present only when the license is inside its grace window. */
  | { ok: true; claims: LicenseClaims; status?: "expired_in_grace" }
  | { ok: false; reason: VerifyFailure; claims?: LicenseClaims };

/**
 * The license a renewal replaces — as much of it as the chain checks read.
 *
 * `LicenseClaims` satisfies this, so a caller hands over the claims an earlier
 * verify() gave it rather than assembling anything.
 */
export interface Predecessor {
  id: string;
  expiresAt?: number | undefined;
}

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
  /**
   * The license the install is replacing, when it is checking a renewal. Given
   * one, verify() checks that the token's `renews` names it — see checkRenewal.
   */
  previous?: Predecessor;
}

export interface TimeCheckOptions {
  /** Unix seconds, already resolved by the caller. */
  now: number;
  clock?: MonotonicClock | undefined;
  skewSeconds?: number | undefined;
  graceSeconds?: number | undefined;
  /** checkRenewal's verdict: the predecessor is on grace, so notBefore is soft. */
  inheritsGrace?: boolean | undefined;
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
    // A renewal dated from the start of the next term has not begun, but the
    // license it replaces is on grace and the install has already swapped the
    // file for this one. Blocking would lock out a customer whose entitlement
    // never actually lapsed, which is the same thing grace exists to avoid; the
    // window is the predecessor's, so it still ends.
    if (options.inheritsGrace !== true) return { ok: false, reason: "not_yet_valid" };
    return { ok: true, status: "expired_in_grace" };
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

export interface RenewalCheckOptions {
  /** The license being replaced. Without it there is nothing to check against. */
  previous?: Predecessor | undefined;
  /** Unix seconds, already resolved by the caller. */
  now: number;
  skewSeconds?: number | undefined;
  graceSeconds?: number | undefined;
}

export type RenewalCheck =
  | { ok: false; reason: "renewal_gap" }
  /** inheritsGrace: the license being replaced is inside its grace window now. */
  | { ok: true; inheritsGrace: boolean };

/**
 * Where a renewal sits in the chain, given the license it is replacing.
 *
 * Two things come out of it. A renewal naming a license other than the one
 * installed is refused: each generation is issued to follow the one before it,
 * so a token that skips one — a file kept back from an earlier term, or one
 * meant for a different chain — would otherwise install as though it were the
 * next. And a renewal whose term has not begun is accepted while the license it
 * replaces is on grace, because the install has already swapped the file and
 * the entitlement has not lapsed.
 *
 * Both need the predecessor, which only the product has; with none supplied
 * nothing is checked and `renews` is just a field. A token carrying no `renews`
 * is not a renewal at all — an issuer re-issuing from scratch rather than
 * renewing says so by leaving it out — so it is left exactly as it was before
 * this check existed.
 */
export function checkRenewal(claims: LicenseClaims, options: RenewalCheckOptions): RenewalCheck {
  const { previous } = options;
  if (previous === undefined || claims.renews === undefined) return { ok: true, inheritsGrace: false };
  if (claims.renews !== previous.id) return { ok: false, reason: "renewal_gap" };

  const skew = options.skewSeconds ?? 60;
  const grace = options.graceSeconds ?? 0;
  const expiresAt = previous.expiresAt;
  // A predecessor that never expires is never on grace, so there is nothing to
  // inherit — and the same window has to be measured the way checkTime measures
  // it, or the two would disagree about the day it ends.
  const inheritsGrace =
    expiresAt !== undefined && options.now - skew >= expiresAt && options.now - skew < expiresAt + grace;
  return { ok: true, inheritsGrace };
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
