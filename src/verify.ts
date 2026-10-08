import { assertClaims, ClaimsError, type LicenseClaims } from "./claims.js";
import {
  checkRenewal,
  checkRevocation,
  checkTime,
  LicenseError,
  TOKEN_PREFIX,
  type VerifyOptions,
  type VerifyResult,
} from "./core.js";
import { fromBase64Url } from "./encoding.js";
import { selectKeys, signedByAny, type PublicKeyInput } from "./keys.js";
import { bindMachine } from "./machine.js";

/**
 * Check a token. Every check runs in order: signature before anything else, so
 * nothing below ever reasons about claims an attacker wrote. Revocation comes
 * next, because a withdrawn license is the wrong license whatever else is true
 * of it, then the chain before the clock, because a renewal from the wrong
 * generation is the wrong file whatever the time is. Choosing the key by `kid`
 * is not one of the checks — see selectKeys.
 */
export function verify(publicKey: PublicKeyInput, token: string, options: VerifyOptions = {}): VerifyResult {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX) return { ok: false, reason: "malformed" };
  const [prefix, payload, signature] = parts as [string, string, string];

  const signedBytes = Buffer.from(`${prefix}.${payload}`);
  const signatureBytes = fromBase64Url(signature);
  if (!signedByAny(selectKeys(publicKey, payload), signedBytes, signatureBytes)) {
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
  const revocation = checkRevocation(claims, options.revocations, { now });
  if (!revocation.ok) return { ok: false, reason: revocation.reason, claims };

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

/** Same as verify(), for callers who prefer exceptions. */
export function verifyOrThrow(publicKey: PublicKeyInput, token: string, options?: VerifyOptions): LicenseClaims {
  const result = verify(publicKey, token, options);
  if (!result.ok) throw new LicenseError(result.reason, result.claims);
  return result.claims;
}
