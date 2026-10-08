import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
  verify as cryptoVerify,
} from "node:crypto";
import { fromBase64Url } from "./encoding.js";

/** PEM string or an already-built KeyObject. */
export type KeyInput = string | KeyObject;

/**
 * The public keys a product trusts, each under the `kid` its licenses carry.
 *
 * Ship the whole ring for as long as licenses signed by the old key are still
 * in the field; drop that entry to retire the key, and every token naming it
 * stops verifying.
 */
export type KeyRing = Readonly<Record<string, KeyInput>>;

/** What a verifier accepts: one public key, or a ring to choose from by `kid`. */
export type PublicKeyInput = KeyInput | KeyRing;

export function isKeyRing(input: PublicKeyInput): input is KeyRing {
  return typeof input !== "string" && !(input instanceof KeyObject);
}

export interface KeyPairPem {
  /** PKCS#8 PEM. Keep on the issuing server only. */
  privateKey: string;
  /** SPKI PEM. Ship inside the product. */
  publicKey: string;
}

/** A fresh Ed25519 key pair as PEM — one call at setup time, then store them. */
export function generateKeyPair(): KeyPairPem {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return {
    privateKey: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    publicKey: publicKey.export({ type: "spki", format: "pem" }).toString(),
  };
}

export function toPrivateKey(input: KeyInput): KeyObject {
  const key = typeof input === "string" ? parsePem(input, "private") : input;
  assertEd25519(key, "private");
  return key;
}

export function toPublicKey(input: KeyInput): KeyObject {
  const key = typeof input === "string" ? parsePem(input, "public") : input;
  assertEd25519(key, "public");
  return key;
}

function parsePem(pem: string, kind: "private" | "public"): KeyObject {
  try {
    return kind === "private" ? createPrivateKey(pem) : createPublicKey(pem);
  } catch (err) {
    // OpenSSL's "DECODER routines::unsupported" tells the caller nothing.
    throw new TypeError(`could not parse a ${kind} key from the given PEM: ${(err as Error).message}`);
  }
}

function assertEd25519(key: KeyObject, kind: "private" | "public") {
  if (key.type !== kind) throw new TypeError(`expected a ${kind} key, got a ${key.type} key`);
  if (key.asymmetricKeyType !== "ed25519") {
    throw new TypeError(`expected an ed25519 key, got ${key.asymmetricKeyType ?? "unknown"}`);
  }
}

/**
 * The keys that may have signed this payload — a license token's, or a
 * revocation list's. Both name their key the same way, so both choose it here.
 *
 * Choosing by `kid` means reading the payload before the signature is checked,
 * which is why the kid is used for nothing else: it picks a key, and the
 * payload then has to survive that key like any other. Editing the kid changes
 * the signed bytes, so a forged one fails the check it was meant to escape.
 *
 * A kid naming no key in the ring yields no candidate at all rather than
 * falling back to the rest of it. Falling back would make a retired key
 * indistinguishable from a current one, which is the entire point of the ring.
 */
export function selectKeys(input: PublicKeyInput, payload: string): KeyObject[] {
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

/** Whether any of the candidate keys signed these bytes. */
export function signedByAny(keys: readonly KeyObject[], signed: Buffer, signature: Buffer): boolean {
  return keys.some((key) => {
    try {
      return cryptoVerify(null, signed, key, signature);
    } catch {
      // A key the runtime will not use for this signature is simply not the one.
      return false;
    }
  });
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
