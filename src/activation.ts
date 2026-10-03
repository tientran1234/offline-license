import { createPublicKey, generateKeyPairSync, randomBytes, sign, verify as cryptoVerify } from "node:crypto";
import type { LicenseClaims } from "./claims.js";
import { canonicalJson, fromBase64Url, toBase64Url } from "./encoding.js";
import { issue } from "./issue.js";
import { toPrivateKey, type KeyInput } from "./keys.js";
import { bindMachine } from "./machine.js";

/**
 * Activation for installs that cannot reach the issuer.
 *
 * The product states what it is — a fingerprint and a nonce — the operator
 * carries that to the issuer by whatever means the air gap allows, and the
 * issuer signs a license bound to it. Two blobs, one in each direction, neither
 * of which needs a socket.
 *
 * The request is signed, and it is worth being exact about what that buys. The
 * product holds no private key — only the public one it checks licenses with —
 * so it signs with a key it generates and embeds in the request. Anyone who
 * edits the payload can re-sign it under a fresh key, so this is an integrity
 * check and not an identity: it catches a request that arrived half-mangled, a
 * fingerprint a mail client wrapped, a nonce pasted next to the wrong machine.
 * Who the customer is cannot be settled offline by anything the machine says
 * about itself; that stays the operator's decision, from `licensee` and
 * `product`.
 */

/** Request version prefix. Inside the signed bytes, like the token's. */
export const ACTIVATION_PREFIX = "act1";

/** What a machine says about itself when it asks for a license. */
export interface MachineClaim {
  /**
   * Fresh per request. The license that answers it carries it back as
   * `activation`, which is how an install tells its own license from one issued
   * for the request before it.
   */
  nonce: string;
  /**
   * The machine to bind to — bindMachine's input, not its output. The binding is
   * keyed by the license id, and the issuer has not chosen one yet.
   */
  fingerprint: string;
  /** Unix seconds, so an issuer can refuse a request that has been in a drawer for a month. */
  requestedAt: number;
  /** Who the customer says they are. A label for the operator, never an authorization. */
  licensee?: string;
  /** Which product, for an issuer that signs for several. */
  product?: string;
  /** base64url SPKI of the key the request is signed with — see the note above on what it proves. */
  key: string;
}

/** A request this release cannot read. `reason` is there because the UIs differ. */
export class ActivationError extends Error {
  override readonly name = "ActivationError";
  constructor(
    readonly reason: "malformed" | "invalid_claims" | "invalid_signature",
    message: string,
  ) {
    super(message);
  }
}

export interface ActivationRequestInput {
  /** This machine, from defaultFingerprint() or whatever stronger identity the product has. */
  fingerprint: string;
  licensee?: string;
  product?: string;
  /** Unix seconds. Defaults to the wall clock. */
  requestedAt?: number;
  /** Supplied only by tests and by a caller reproducing a request. Default: 16 random bytes. */
  nonce?: string;
  /**
   * PKCS#8 PEM, for an install that keeps one key across requests.
   *
   * The default generates a key, signs, and discards the private half — nothing
   * later proves anything with it. Keep one instead when the issuer records the
   * key it first saw: a renewal signed by the same key is then recognisably the
   * same install asking again, which is more than the fingerprint alone says.
   */
  signingKey?: KeyInput;
}

/** The blob a product emits to ask for a license: `act1.<payload>.<signature>`. */
export function createActivationRequest(input: ActivationRequestInput): string {
  const privateKey =
    input.signingKey === undefined ? generateKeyPairSync("ed25519").privateKey : toPrivateKey(input.signingKey);

  const claim: MachineClaim = {
    nonce: input.nonce ?? randomBytes(16).toString("base64url"),
    fingerprint: input.fingerprint,
    requestedAt: input.requestedAt ?? Math.floor(Date.now() / 1000),
    key: toBase64Url(createPublicKey(privateKey).export({ type: "spki", format: "der" })),
  };
  if (input.licensee !== undefined) claim.licensee = input.licensee;
  if (input.product !== undefined) claim.product = input.product;
  assertMachineClaim(claim);

  const payload = toBase64Url(canonicalJson(claim));
  const signed = `${ACTIVATION_PREFIX}.${payload}`;
  return `${signed}.${toBase64Url(sign(null, Buffer.from(signed), privateKey))}`;
}

/**
 * Read a request, refusing one that does not hold together.
 *
 * The shape is checked before the signature, which is the reverse of a
 * license's order and deliberately so: the verifying key travels in the payload
 * here, so there is nothing to check a signature with until the payload has
 * been read. Nothing rests on the order, because the signature was never an
 * authority over these claims — for a license it is, which is exactly why
 * verify() will not read a claim before checking it.
 */
export function readActivationRequest(request: string): MachineClaim {
  const parts = request.split(".");
  if (parts.length !== 3 || parts[0] !== ACTIVATION_PREFIX) {
    throw new ActivationError(
      "malformed",
      `expected an ${ACTIVATION_PREFIX}.<payload>.<signature> activation request`,
    );
  }
  const [prefix, payload, signature] = parts as [string, string, string];

  let claim: MachineClaim;
  try {
    const parsed: unknown = JSON.parse(fromBase64Url(payload).toString("utf8"));
    assertMachineClaim(parsed);
    claim = parsed;
  } catch (err) {
    if (err instanceof ActivationError) throw err;
    throw new ActivationError("invalid_claims", `not a machine claim: ${(err as Error).message}`);
  }

  if (!signatureOk(claim.key, `${prefix}.${payload}`, signature)) {
    throw new ActivationError("invalid_signature", "the request is not signed by the key it carries");
  }
  return claim;
}

function signatureOk(key: string, signed: string, signature: string): boolean {
  try {
    const publicKey = createPublicKey({ key: fromBase64Url(key), format: "der", type: "spki" });
    return cryptoVerify(null, Buffer.from(signed), publicKey, fromBase64Url(signature));
  } catch {
    // A key that is not an Ed25519 SPKI cannot have signed this, which is the
    // same verdict as a signature that does not match it.
    return false;
  }
}

/**
 * What an issuer decides. The machine binding and the nonce are not among it:
 * both come from the request, and a caller free to pass either could bind a
 * license to a machine that never asked for one, or stamp it with a nonce no
 * install is waiting for — which is the whole of what the exchange establishes.
 */
export type FulfilmentClaims = Omit<LicenseClaims, "machine" | "activation">;

/** Answer a request: the license the issuer signs, bound to the machine that asked. */
export function fulfilActivation(privateKey: KeyInput, request: string, claims: FulfilmentClaims): string {
  const claim = readActivationRequest(request);
  return issue(privateKey, {
    ...claims,
    machine: bindMachine(claims.id, claim.fingerprint),
    activation: claim.nonce,
  });
}

/**
 * Whether a license is the answer to this request.
 *
 * Checked once, when the license is installed, which is why it is not one of
 * verify()'s checks: a license that answered the right request yesterday still
 * does, and asking on every question would mean keeping the request for the
 * life of the install to re-answer something that cannot change. What verify()
 * goes on checking is the binding — that is the claim with teeth, and it is in
 * the token.
 *
 * The nonce is what makes the pairing visible. Two requests from one machine
 * bind identically, so without it a license issued for the earlier request —
 * shorter, fewer features, or simply the one the renewal was meant to replace —
 * installs as though it were the one just asked for.
 */
export function answersRequest(request: string, claims: LicenseClaims): boolean {
  const claim = readActivationRequest(request);
  return claims.activation === claim.nonce && claims.machine === bindMachine(claims.id, claim.fingerprint);
}

/** Runtime shape check for a payload off the wire — the signature does not vouch for it. */
export function assertMachineClaim(value: unknown): asserts value is MachineClaim {
  if (!value || typeof value !== "object") {
    throw new ActivationError("invalid_claims", "a machine claim must be an object");
  }
  const c = value as Record<string, unknown>;

  for (const key of ["nonce", "fingerprint", "key"] as const) {
    if (typeof c[key] !== "string" || c[key] === "") {
      throw new ActivationError("invalid_claims", `${key} must be a non-empty string`);
    }
  }
  if (typeof c.requestedAt !== "number" || !Number.isFinite(c.requestedAt)) {
    throw new ActivationError("invalid_claims", "requestedAt must be a number");
  }
  for (const key of ["licensee", "product"] as const) {
    if (c[key] !== undefined && (typeof c[key] !== "string" || c[key] === "")) {
      throw new ActivationError("invalid_claims", `${key} must be a non-empty string when present`);
    }
  }
}
