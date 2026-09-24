import { createPrivateKey, createPublicKey, generateKeyPairSync, KeyObject } from "node:crypto";

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
