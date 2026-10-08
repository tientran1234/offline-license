import { sign } from "node:crypto";
import {
  assertRevocationClaims,
  REVOCATION_PREFIX,
  RevocationError,
  type RevocationClaims,
  type RevocationEntry,
} from "./core.js";
import { canonicalJson, fromBase64Url, toBase64Url } from "./encoding.js";
import { selectKeys, signedByAny, toPrivateKey, type KeyInput, type PublicKeyInput } from "./keys.js";

/**
 * Revocation, for the installs a file can still reach.
 *
 * The README is blunt that offline licensing has no revocation worth the name,
 * and that stays true of the thing people mean by it: there is no list to
 * consult at check time, and an install that has gone quiet cannot be told
 * anything. What this adds is the other half — an issuer that has withdrawn a
 * license can say so in a signed artefact, and an install that does receive it
 * (an update bundle, a USB stick, the same channel the license itself arrived
 * on) will refuse that license from then on.
 *
 * Two things make it more than a courtesy. The list is signed, so nobody but
 * the issuer can revoke a competitor's customers or forge a refusal; and it can
 * be dated, so an install told to check revocation refuses to run on evidence
 * older than the issuer vouched for, which is the only answer to a revoked box
 * that simply stops taking updates. Neither closes the gap against someone who
 * deletes the list and patches the check out — nothing running on the
 * customer's machine can.
 */

/** What an issuer publishes when it withdraws licenses. */
export interface RevocationListInput {
  revoked: readonly RevocationEntry[];
  /** Unix seconds. Defaults to the wall clock. */
  issuedAt?: number;
  /**
   * Unix seconds, after which an install stops believing this list.
   *
   * Set it to the interval the product can actually refresh over and the list
   * fails closed; leave it out and the list is good until another replaces it.
   * See RevocationList.
   */
  expiresAt?: number;
  /** Names the signing key, so a verifier holding a ring knows which to try. */
  kid?: string;
}

/** Sign a revocation list: `rev1.<payload>.<signature>`. */
export function issueRevocationList(privateKey: KeyInput, input: RevocationListInput): string {
  const claims: RevocationClaims = {
    issuedAt: input.issuedAt ?? Math.floor(Date.now() / 1000),
    revoked: input.revoked,
  };
  if (input.expiresAt !== undefined) claims.expiresAt = input.expiresAt;
  if (input.kid !== undefined) claims.kid = input.kid;
  assertRevocationClaims(claims);

  const key = toPrivateKey(privateKey);
  const payload = toBase64Url(canonicalJson(claims));
  const signed = `${REVOCATION_PREFIX}.${payload}`;
  return `${signed}.${toBase64Url(sign(null, Buffer.from(signed), key))}`;
}

/**
 * Read a list, refusing one that is not the issuer's.
 *
 * Signature before shape, the same order verify() uses and for the same reason:
 * the list says which licenses to stop honouring, so nothing below may reason
 * about entries an attacker wrote. A list that does not hold together throws
 * rather than yielding an empty one — an empty list revokes nothing, which is
 * exactly the verdict an attacker who mangled the file is hoping for.
 */
export function readRevocationList(publicKey: PublicKeyInput, list: string): RevocationClaims {
  const parts = list.trim().split(".");
  if (parts.length !== 3 || parts[0] !== REVOCATION_PREFIX) {
    throw new RevocationError(
      "malformed",
      `expected a ${REVOCATION_PREFIX}.<payload>.<signature> revocation list`,
    );
  }
  const [prefix, payload, signature] = parts as [string, string, string];

  const signedBytes = Buffer.from(`${prefix}.${payload}`);
  if (!signedByAny(selectKeys(publicKey, payload), signedBytes, fromBase64Url(signature))) {
    throw new RevocationError("invalid_signature", "the revocation list is not signed by a key this verifier holds");
  }

  try {
    const parsed: unknown = JSON.parse(fromBase64Url(payload).toString("utf8"));
    assertRevocationClaims(parsed);
    return parsed;
  } catch (err) {
    if (err instanceof RevocationError) throw err;
    // Signed by the right key, but the payload is not a list — the issuer's own
    // mistake rather than an attack, and still not something to act on.
    throw new RevocationError("invalid_claims", `not a revocation list: ${(err as Error).message}`);
  }
}
