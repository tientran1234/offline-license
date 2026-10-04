import { verify as cryptoVerify, type KeyObject } from "node:crypto";
import { assertClaims, ClaimsError, type LicenseClaims } from "./claims.js";
import {
  checkRenewal,
  checkTime,
  LicenseError,
  TOKEN_PREFIX,
  type VerifyOptions,
  type VerifyResult,
} from "./core.js";
import { fromBase64Url } from "./encoding.js";
import { isKeyRing, toPublicKey, type PublicKeyInput } from "./keys.js";
import { bindMachine } from "./machine.js";

/**
 * Check a token. Every check runs in order: signature before anything else, so
 * nothing below ever reasons about claims an attacker wrote. The chain comes
 * before the clock, because a renewal from the wrong generation is the wrong
 * file whatever the time is. Choosing the key by `kid` is not one of the
 * checks — see selectKeys.
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
  const renewal = checkRenewal(claims, {
    previous: options.previous,
    now,
    skewSeconds: options.skewSeconds,
    graceSeconds: options.graceSeconds,
  });
  if (!renewal.ok) return { ok: false, reason: renewal.reason, claims };

  const timing = checkTime(claims, {
    now,
    clock: options.clock,
    skewSeconds: options.skewSeconds,
    graceSeconds: options.graceSeconds,
    inheritsGrace: renewal.inheritsGrace,
  });
  if (!timing.ok) return { ok: false, reason: timing.reason, claims };

  if (claims.machine !== undefined) {
    const fingerprint = options.machineFingerprint;
    if (!fingerprint || bindMachine(claims.id, fingerprint) !== claims.machine) {
      return { ok: false, reason: "machine_mismatch", claims };
    }
  }

  return timing.status === undefined ? { ok: true, claims } : { ok: true, claims, status: timing.status };
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

/** Same as verify(), for callers who prefer exceptions. */
export function verifyOrThrow(publicKey: PublicKeyInput, token: string, options?: VerifyOptions): LicenseClaims {
  const result = verify(publicKey, token, options);
  if (!result.ok) throw new LicenseError(result.reason, result.claims);
  return result.claims;
}
