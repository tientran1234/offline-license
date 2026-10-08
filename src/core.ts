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
  "revoked",
  "revocation_stale",
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

/** Version prefix of a revocation list. Inside the signed bytes, like a token's. */
export const REVOCATION_PREFIX = "rev1";

/**
 * A license the issuer has withdrawn, and when the withdrawal takes effect.
 *
 * `revokedAt` is a date rather than a flag so a list can be published before it
 * bites — the end of a billing period, the last day of a trial — without the
 * issuer having to be at a keyboard on the day it does.
 */
export interface RevocationEntry {
  id: string;
  /** Unix seconds. Before it, the entry is a notice; after it, a refusal. */
  revokedAt: number;
  /** Free text for an admin page. No check reads it. */
  reason?: string;
}

/**
 * What a verifier checks a license against: the list readRevocationList() hands
 * back, already proved to be the issuer's.
 *
 * `expiresAt` is what gives an offline list teeth. A revoked install can simply
 * stop collecting new lists, so a list that is believed forever is only ever
 * advisory; dating one makes the install refuse to run on evidence older than
 * the issuer was willing to vouch for. Leaving it out says the opposite — this
 * list is good until another replaces it — and is the right choice when losing
 * a license to a missed update would be worse than honouring a revoked one.
 */
export interface RevocationList {
  issuedAt: number;
  /** Unix seconds. Past it the list is stale and stops being believed. */
  expiresAt?: number;
  revoked: readonly RevocationEntry[];
}

/** A list's signed claims: the list, plus the kid naming the key that signed it. */
export interface RevocationClaims extends RevocationList {
  kid?: string;
}

/** A list this release cannot read. `reason` is there because the UIs differ. */
export class RevocationError extends Error {
  override readonly name = "RevocationError";
  constructor(
    readonly reason: "malformed" | "invalid_claims" | "invalid_signature",
    message: string,
  ) {
    super(message);
  }
}

/** Runtime shape check for a decoded list — never trust the wire. */
export function assertRevocationClaims(value: unknown): asserts value is RevocationClaims {
  if (!value || typeof value !== "object") {
    throw new RevocationError("invalid_claims", "a revocation list must be an object");
  }
  const list = value as Record<string, unknown>;

  if (typeof list.issuedAt !== "number" || !Number.isFinite(list.issuedAt)) {
    throw new RevocationError("invalid_claims", "issuedAt must be a number");
  }
  if (list.expiresAt !== undefined && (typeof list.expiresAt !== "number" || !Number.isFinite(list.expiresAt))) {
    throw new RevocationError("invalid_claims", "expiresAt must be a number when present");
  }
  if (list.kid !== undefined && (typeof list.kid !== "string" || list.kid === "")) {
    throw new RevocationError("invalid_claims", "kid must be a non-empty string when present");
  }
  if (!Array.isArray(list.revoked)) {
    throw new RevocationError("invalid_claims", "revoked must be an array");
  }
  for (const entry of list.revoked as readonly unknown[]) {
    assertRevocationEntry(entry);
  }
}

function assertRevocationEntry(value: unknown): asserts value is RevocationEntry {
  if (!value || typeof value !== "object") {
    throw new RevocationError("invalid_claims", "a revoked entry must be an object");
  }
  const entry = value as Record<string, unknown>;
  if (typeof entry.id !== "string" || entry.id === "") {
    throw new RevocationError("invalid_claims", "a revoked entry needs a non-empty id");
  }
  if (typeof entry.revokedAt !== "number" || !Number.isFinite(entry.revokedAt)) {
    throw new RevocationError("invalid_claims", `revokedAt must be a number (${entry.id})`);
  }
  if (entry.reason !== undefined && typeof entry.reason !== "string") {
    throw new RevocationError("invalid_claims", `reason must be a string when present (${entry.id})`);
  }
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
  /**
   * The issuer's revocation list, as readRevocationList() returned it.
   *
   * Passing one opts into the check and into its staleness: see
   * checkRevocation. With none, revocation is not checked at all, which is what
   * every install did before lists existed.
   */
  revocations?: RevocationList;
}

export interface RevocationCheckOptions {
  /** Unix seconds, already resolved by the caller. */
  now: number;
}

export type RevocationCheck = { ok: false; reason: "revoked" | "revocation_stale" } | { ok: true };

/**
 * What the issuer's list says about this license.
 *
 * Two verdicts come out of it. A license named by an entry whose `revokedAt`
 * has passed is refused: the issuer has withdrawn it, and that is true whatever
 * the clock or the chain says, which is why this runs before both. And a list
 * that has itself expired refuses every license, revoked or not — the install
 * was told to check revocation and can no longer do it, so continuing would
 * hand a revoked box exactly what it wants for going quiet. A revocation dated
 * in the future is a notice and not yet a refusal, which is how an issuer
 * publishes one ahead of the day it bites.
 *
 * `skewSeconds` is not among the options, and that is the one place this reads
 * differently from the clock checks. Slack on an expiry keeps a paying customer
 * working through a disagreement about what time it is; slack here would only
 * postpone a refusal the issuer has already decided on, and a revocation that
 * arrives a minute late is a minute the license should not have worked.
 */
export function checkRevocation(
  claims: LicenseClaims,
  list: RevocationList | undefined,
  options: RevocationCheckOptions,
): RevocationCheck {
  if (list === undefined) return { ok: true };

  const entry = list.revoked.find((revocation) => revocation.id === claims.id);
  if (entry !== undefined && options.now >= entry.revokedAt) return { ok: false, reason: "revoked" };
  if (list.expiresAt !== undefined && options.now >= list.expiresAt) {
    return { ok: false, reason: "revocation_stale" };
  }
  return { ok: true };
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
