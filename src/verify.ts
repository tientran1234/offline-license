import { verify as cryptoVerify } from "node:crypto";
import { assertClaims, ClaimsError, type LicenseClaims } from "./claims.js";
import { fromBase64Url } from "./encoding.js";
import { TOKEN_PREFIX } from "./issue.js";
import { toPublicKey, type KeyInput } from "./keys.js";
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
  | { ok: true; claims: LicenseClaims }
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
}

/**
 * Check a token. Every check runs in order: signature before anything else, so
 * nothing below ever reasons about claims an attacker wrote.
 */
export function verify(publicKey: KeyInput, token: string, options: VerifyOptions = {}): VerifyResult {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX) return { ok: false, reason: "malformed" };
  const [prefix, payload, signature] = parts as [string, string, string];

  const key = toPublicKey(publicKey);
  const signedBytes = Buffer.from(`${prefix}.${payload}`);
  let signatureOk = false;
  try {
    signatureOk = cryptoVerify(null, signedBytes, key, fromBase64Url(signature));
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) return { ok: false, reason: "invalid_signature" };

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
export function verifyOrThrow(publicKey: KeyInput, token: string, options?: VerifyOptions): LicenseClaims {
  const result = verify(publicKey, token, options);
  if (!result.ok) throw new LicenseError(result.reason, result.claims);
  return result.claims;
}
