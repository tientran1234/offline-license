import { verify as cryptoVerify, type KeyObject } from "node:crypto";
import { assertClaims, ClaimsError, type LicenseClaims } from "./claims.js";
import { fromBase64Url } from "./encoding.js";
import { TOKEN_PREFIX } from "./issue.js";
import { isKeyRing, toPublicKey, type PublicKeyInput } from "./keys.js";
import { bindMachine } from "./machine.js";
import type { MonotonicClock } from "./clock.js";

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

/**
 * Check a token. Every check runs in order: signature before anything else, so
 * nothing below ever reasons about claims an attacker wrote. Choosing the key
 * by `kid` is not one of the checks — see selectKeys.
 */
export function verify(publicKey: PublicKeyInput, token: string, options: VerifyOptions = {}): VerifyResult {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX) return { ok: false, reason: "malformed" };
  const [prefix, payload, signature] = parts as [string, string, string];

  const signedBytes = Buffer.from(`${prefix}.${payload}`);
  const signatureBytes = fromBase64Url(signature);
  const candidates = selectKeys(publicKey, payload);
  if (!candidates.some((key) => signatureOk(key, signedBytes, signatureBytes))) {
    return { ok: false, reason: "invalid_signature" };
  }

  let claims: LicenseClaims;
  try {
    const parsed: unknown = JSON.parse(fromBase64Url(payload).toString("utf8"));
    assertClaims(parsed);
    claims = parsed;
  } catch (err) {
    if (err instanceof ClaimsError || err instanceof SyntaxError) {
      return { ok: false, reason: "invalid_claims" };
    }
    throw err;
  }

  const now = options.now?.() ?? Math.floor(Date.now() / 1000);
  const skew = options.skewSeconds ?? 60;

  if (options.clock && options.clock.observe(now).rollback) {
    return { ok: false, reason: "clock_rollback", claims };
  }
  if (claims.notBefore !== undefined && now + skew < claims.notBefore) {
    return { ok: false, reason: "not_yet_valid", claims };
  }
  if (claims.expiresAt !== undefined && now - skew >= claims.expiresAt) {
    return { ok: false, reason: "expired", claims };
  }
  if (claims.machine !== undefined) {
    const fingerprint = options.machineFingerprint;
    if (!fingerprint || bindMachine(claims.id, fingerprint) !== claims.machine) {
      return { ok: false, reason: "machine_mismatch", claims };
    }
  }

  return { ok: true, claims };
}

/**
 * The keys that may have signed this token.
 *
 * Choosing by `kid` means reading the payload before the signature is checked,
 * which is why the kid is used for nothing else: it picks a key, and the token
 * then has to survive that key like any other. Editing the kid changes the
 * signed bytes, so a forged one fails the check it was meant to escape.
 *
 * A kid naming no key in the ring yields no candidate at all rather than
 * falling back to the rest of it. Falling back would make a retired key
 * indistinguishable from a current one, which is the entire point of the ring.
 */
function selectKeys(input: PublicKeyInput, payload: string): KeyObject[] {
  if (!isKeyRing(input)) return [toPublicKey(input)];

  const kid = peekKid(payload);
  if (kid === undefined) {
    // Issued before rotation, so it names no key. Every key in the ring is one
    // the caller trusts, so try them all.
    return Object.values(input).map(toPublicKey);
  }
  const named = input[kid];
  return named === undefined ? [] : [toPublicKey(named)];
}

/**
 * The kid from an unverified payload — for key selection and nothing else, so
 * anything unreadable is simply "no kid" rather than an error of its own.
 */
function peekKid(payload: string): string | undefined {
  try {
    const parsed: unknown = JSON.parse(fromBase64Url(payload).toString("utf8"));
    const kid = (parsed as Record<string, unknown>)?.kid;
    return typeof kid === "string" && kid !== "" ? kid : undefined;
  } catch {
    return undefined;
  }
}

function signatureOk(key: KeyObject, signed: Buffer, signature: Buffer): boolean {
  try {
    return cryptoVerify(null, signed, key, signature);
  } catch {
    return false;
  }
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

/** Same as verify(), for callers who prefer exceptions. */
export function verifyOrThrow(publicKey: PublicKeyInput, token: string, options?: VerifyOptions): LicenseClaims {
  const result = verify(publicKey, token, options);
  if (!result.ok) throw new LicenseError(result.reason, result.claims);
  return result.claims;
}
