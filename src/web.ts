import {
  assertClaims,
  ClaimsError,
  featureValue,
  hasFeature,
  type FeatureValue,
  type LicenseClaims,
} from "./claims.js";
import {
  checkTime,
  LicenseError,
  TOKEN_PREFIX,
  type VerifyOptions,
  type VerifyResult,
} from "./core.js";
import { ChainedLedger, type ChainedLedgerOptions } from "./ledger.js";

/**
 * The same verifier, on WebCrypto instead of node:crypto — for Electron
 * renderers, dashboards and anywhere else a license has to be checked without
 * a Node API in reach.
 *
 * Nothing here imports node:crypto, node:os or Buffer, so a bundler can take
 * this entry point alone. The checks and their order come from core.ts, shared
 * with the Node build, and tests/vectors.ts holds both to the same verdicts.
 *
 * Everything is async because WebCrypto is: `subtle.verify` returns a promise
 * and there is no synchronous way to reach it. That is the one difference in
 * the API, and it is not one this library can paper over.
 */

export { LicenseError, TOKEN_PREFIX } from "./core.js";
export type { Predecessor, VerifyFailure, VerifyOptions, VerifyResult } from "./core.js";
export { assertClaims, ClaimsError, featureValue, hasFeature } from "./claims.js";
export type { FeatureValue, Features, LicenseClaims } from "./claims.js";
export { MonotonicClock } from "./clock.js";
export type { ClockObservation, MonotonicClockOptions } from "./clock.js";
export type { ClockStore } from "./stores.js";
export { CLOCK_STORAGE_KEY, LocalStorageStore, LocalStorageLedgerStore, USAGE_STORAGE_KEY } from "./localstorage.js";
export type {
  LocalStorageLedgerStoreOptions,
  LocalStorageStoreOptions,
  WebStorage,
} from "./localstorage.js";
export { parseLedger, serializeLedger, UsageLedgerError, UsageLimitError, USAGE_LEDGER_VERSION } from "./ledger.js";
export type { Ledger, LedgerStore, UsageEntry } from "./ledger.js";

/**
 * An SPKI PEM, or a CryptoKey already imported by the caller.
 *
 * There is no cache behind this: the guard re-verifies on every question, and
 * a hidden map of imported keys would be state this library does not need.
 * Import once yourself and hand over the CryptoKey when a render loop makes
 * the parse worth skipping.
 */
export type WebKeyInput = string | CryptoKey;

/** The public keys a product trusts, each under the `kid` its licenses carry. */
export type WebKeyRing = Readonly<Record<string, WebKeyInput>>;

export type WebPublicKeyInput = WebKeyInput | WebKeyRing;

const ED25519 = { name: "Ed25519" } as const;
const encoder = new TextEncoder();

/**
 * A browser without `crypto.subtle` is not a browser missing a polyfill — it
 * is a page served over http://, where WebCrypto is withheld. Say so, because
 * "cannot read properties of undefined" sends people looking in the wrong place.
 */
function subtle(): typeof globalThis.crypto.subtle {
  const available = globalThis.crypto?.subtle;
  if (!available) {
    throw new Error("crypto.subtle is unavailable: WebCrypto needs a secure context (https:// or localhost)");
  }
  return available;
}

/** Parse an SPKI PEM into a CryptoKey. A CryptoKey passes straight through. */
export async function importPublicKey(key: WebKeyInput): Promise<CryptoKey> {
  if (typeof key !== "string") return key;
  const der = fromBase64Url(key.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""));
  if (der === null) throw new TypeError("could not parse a public key from the given PEM: not base64");
  try {
    return await subtle().importKey("spki", der, ED25519, false, ["verify"]);
  } catch (err) {
    throw new TypeError(`could not parse a public key from the given PEM: ${(err as Error).message}`);
  }
}

/**
 * Bind a license to one machine — byte-for-byte what the Node build produces
 * for the same inputs, so a token issued on the server checks out here.
 *
 * There is no defaultFingerprint() in this build. A browser has nothing stable
 * to offer that is not either useless (a user agent string) or a tracking id,
 * and guessing badly would lock out a customer who changed a font setting.
 * Supply the fingerprint: in Electron, the one the main process already has.
 */
export async function bindMachine(licenseId: string, fingerprint: string): Promise<string> {
  const key = await subtle().importKey("raw", encoder.encode(licenseId), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  return toBase64Url(new Uint8Array(await subtle().sign("HMAC", key, encoder.encode(fingerprint))));
}

/**
 * Check a token. Same checks in the same order as the Node build: signature
 * before anything else, so nothing below ever reasons about claims an attacker
 * wrote. Choosing the key by `kid` is not one of the checks — see selectKeys.
 */
export async function verify(
  publicKey: WebPublicKeyInput,
  token: string,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== TOKEN_PREFIX) return { ok: false, reason: "malformed" };
  const [prefix, payload, signature] = parts as [string, string, string];

  const signedBytes = encoder.encode(`${prefix}.${payload}`);
  const signatureBytes = fromBase64Url(signature);
  const candidates = await selectKeys(publicKey, payload);
  if (signatureBytes === null || !(await anyKeyVerifies(candidates, signedBytes, signatureBytes))) {
    return { ok: false, reason: "invalid_signature" };
  }

  let claims: LicenseClaims;
  try {
    const bytes = fromBase64Url(payload);
    // The signature already passed, so this only trips on a payload that was
    // signed but is not a license — the same case Node reports as invalid_claims.
    if (bytes === null) throw new SyntaxError("payload is not base64url");
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    assertClaims(parsed);
    claims = parsed;
  } catch (err) {
    if (err instanceof ClaimsError || err instanceof SyntaxError) {
      return { ok: false, reason: "invalid_claims" };
    }
    throw err;
  }

  const timing = checkTime(claims, {
    now: options.now?.() ?? Math.floor(Date.now() / 1000),
    clock: options.clock,
    skewSeconds: options.skewSeconds,
    graceSeconds: options.graceSeconds,
  });
  if (!timing.ok) return { ok: false, reason: timing.reason, claims };

  if (claims.machine !== undefined) {
    const fingerprint = options.machineFingerprint;
    if (!fingerprint || (await bindMachine(claims.id, fingerprint)) !== claims.machine) {
      return { ok: false, reason: "machine_mismatch", claims };
    }
  }

  return timing.status === undefined ? { ok: true, claims } : { ok: true, claims, status: timing.status };
}

/** Same as verify(), for callers who prefer exceptions. */
export async function verifyOrThrow(
  publicKey: WebPublicKeyInput,
  token: string,
  options?: VerifyOptions,
): Promise<LicenseClaims> {
  const result = await verify(publicKey, token, options);
  if (!result.ok) throw new LicenseError(result.reason, result.claims);
  return result.claims;
}

export interface LicenseGuardOptions extends VerifyOptions {
  publicKey: WebPublicKeyInput;
  token: string;
}

/**
 * The browser twin of the Node guard: one object that answers "may I?", with
 * every answer a promise. Each question re-verifies — a signature check and a
 * few comparisons, cheap enough that caching would only give a stale answer
 * somewhere to outlive an expiry.
 */
export class LicenseGuard {
  constructor(private readonly options: LicenseGuardOptions) {}

  check(): Promise<VerifyResult> {
    const { publicKey, token, ...rest } = this.options;
    return verify(publicKey, token, rest);
  }

  /** Claims if the license is currently valid, else null. */
  async claims(): Promise<LicenseClaims | null> {
    const result = await this.check();
    return result.ok ? result.claims : null;
  }

  /** True when the license is past expiresAt and alive only on grace — warn, do not block. */
  async inGrace(): Promise<boolean> {
    const result = await this.check();
    return result.ok && result.status === "expired_in_grace";
  }

  async hasFeature(feature: string): Promise<boolean> {
    const claims = await this.claims();
    return claims === null ? false : hasFeature(claims.features, feature);
  }

  /** Throws LicenseError with the precise reason: invalid license vs. missing feature. */
  async assertFeature(feature: string): Promise<LicenseClaims> {
    const result = await this.check();
    if (!result.ok) throw new LicenseError(result.reason, result.claims);
    if (!hasFeature(result.claims.features, feature)) {
      throw new LicenseError("invalid_claims", result.claims);
    }
    return result.claims;
  }

  /**
   * What the license attaches to a feature — a tier name, a count, a switch —
   * or null when it names none (or the license is invalid). Not narrowed by a
   * type parameter, for the reason the Node guard gives.
   */
  async value(feature: string): Promise<FeatureValue | null> {
    const claims = await this.claims();
    return claims === null ? null : featureValue(claims.features, feature);
  }

  /** The cap for `key`, or null when the license sets none (or is invalid). */
  async limit(key: string): Promise<number | null> {
    return (await this.claims())?.limits?.[key] ?? null;
  }

  /** True when `used` is under the cap. A license with no cap for `key` allows everything. */
  async withinLimit(key: string, used: number): Promise<boolean> {
    const cap = await this.limit(key);
    return cap === null ? (await this.claims()) !== null : used < cap;
  }
}

export type UsageLedgerOptions = Omit<ChainedLedgerOptions, "mac">;

/**
 * The browser twin of the Node usage ledger, over `LocalStorageLedgerStore` or
 * anything else that keeps a string.
 *
 * It was async in both builds already: a ledger has to be persisted before the
 * consumption it records is counted, and storage is awaited wherever it lives.
 * The chain's HMAC is this build's `bindMachine`, which produces the same bytes
 * the Node one does, so a ledger an Electron main process wrote verifies in the
 * renderer and the other way round.
 */
export class UsageLedger extends ChainedLedger {
  constructor(options: UsageLedgerOptions) {
    super({ ...options, mac: bindMachine });
  }
}

/**
 * The keys that may have signed this token.
 *
 * Choosing by `kid` means reading the payload before the signature is checked,
 * which is why the kid is used for nothing else. A kid naming no key in the
 * ring yields no candidate rather than falling back to the rest of it, because
 * falling back would make a retired key indistinguishable from a current one.
 */
async function selectKeys(input: WebPublicKeyInput, payload: string): Promise<CryptoKey[]> {
  if (!isKeyRing(input)) return [await importPublicKey(input)];

  const kid = peekKid(payload);
  if (kid === undefined) {
    // Issued before rotation, so it names no key. Every key in the ring is one
    // the caller trusts, so try them all.
    return Promise.all(Object.values(input).map(importPublicKey));
  }
  const named = input[kid];
  return named === undefined ? [] : [await importPublicKey(named)];
}

function isKeyRing(input: WebPublicKeyInput): input is WebKeyRing {
  return typeof input !== "string" && !(input instanceof CryptoKey);
}

/**
 * The kid from an unverified payload — for key selection and nothing else, so
 * anything unreadable is simply "no kid" rather than an error of its own.
 */
function peekKid(payload: string): string | undefined {
  const bytes = fromBase64Url(payload);
  if (bytes === null) return undefined;
  try {
    const parsed: unknown = JSON.parse(new TextDecoder().decode(bytes));
    const kid = (parsed as Record<string, unknown>)?.kid;
    return typeof kid === "string" && kid !== "" ? kid : undefined;
  } catch {
    return undefined;
  }
}

async function anyKeyVerifies(
  keys: CryptoKey[],
  signed: Uint8Array<ArrayBuffer>,
  signature: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
  for (const key of keys) {
    try {
      if (await subtle().verify(ED25519, key, signature, signed)) return true;
    } catch {
      // A key the runtime will not use for this signature is simply not the one.
    }
  }
  return false;
}

/** base64url without padding, on atob/btoa — Buffer does not exist here. */
function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** null rather than a throw: every caller here treats bad input as a verdict, not an error. */
function fromBase64Url(text: string): Uint8Array<ArrayBuffer> | null {
  const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
  let binary: string;
  try {
    binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  } catch {
    return null;
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
