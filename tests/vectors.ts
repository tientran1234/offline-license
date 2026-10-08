import { readFileSync } from "node:fs";
import type { Predecessor, RevocationList, VerifyOptions, VerifyResult } from "../src/index.js";

/**
 * The vectors in `vectors/`, loaded.
 *
 * One table of tokens and the verdict each must produce. The Node build and the
 * browser build are separate implementations over different crypto APIs, so
 * "they agree" is not something the type system can say; both run this table
 * instead, and a verdict that changes on one platform and not the other fails
 * here, whichever platform moved.
 *
 * The table used to be built in TypeScript at import time, over keys generated
 * per run. That proved the two builds agreed with each other and nothing more:
 * the tokens existed for a few milliseconds inside one test process, so an
 * implementation in another language had nothing to check itself against, and a
 * change to `issue` moved the fixtures and the expectations together. Now the
 * tokens are bytes on disk, signed by keys that are also on disk, shipped in
 * the package — see vectors/README.md. This module only reads them.
 */

/** Where the fixtures live. Published, so the paths are part of the contract. */
export const vectorsDir = new URL("../vectors/", import.meta.url);

export function readFixture(name: string): string {
  return readFileSync(new URL(name, vectorsDir), "utf8");
}

/** One entry of `vectors/keys.json`. */
export interface VectorKeyPair {
  /** SPKI PEM, as a verifier takes it. */
  publicKey: string;
  /**
   * The 32 raw Ed25519 bytes, base64url.
   *
   * The same key as `publicKey`, for the implementations whose crypto library
   * wants the key and not a certificate wrapper around it. Parsing SPKI DER to
   * find a 32-byte tail is work this file can do once.
   */
  publicKeyRaw: string;
  /** PKCS#8 PEM. A test key — see the note in the file. */
  privateKey: string;
}

export interface KeyFile {
  version: number;
  note: string;
  keys: Readonly<Record<string, VectorKeyPair>>;
}

/** A key by the name `vectors/keys.json` gives it, or a ring of them by `kid`. */
export type KeyRef = string | Readonly<Record<string, string>>;

/** verify()'s options as JSON can carry them: `now` is a number, not a function. */
export interface VectorOptions {
  now: number;
  skewSeconds?: number;
  graceSeconds?: number;
  machineFingerprint?: string;
  previous?: Predecessor;
  /** The issuer's list, already read — what readRevocationList() hands back. */
  revocations?: RevocationList;
}

export interface VectorEntry {
  name: string;
  publicKey: KeyRef;
  token: string;
  options: VectorOptions;
  expected: VerifyResult;
}

export interface VectorFile {
  version: number;
  /** The token prefix every vector here carries, so a reader can assert it. */
  tokenPrefix: string;
  /** The machine the bound vectors are issued for — bindMachine's input. */
  fingerprint: string;
  vectors: readonly VectorEntry[];
}

export const keyFile = JSON.parse(readFixture("keys.json")) as KeyFile;
export const vectorFile = loadVectorFile();

/**
 * The vectors as checked in, or an empty set when the file is not there.
 *
 * Absent is not a state the suite tolerates — `vectors.test.ts` fails on it in
 * several places at once. But it has to be *loadable*, because the command that
 * re-cuts the file runs through that same suite, and a loader that threw on the
 * way in could never create what it was complaining about.
 */
function loadVectorFile(): VectorFile {
  try {
    return JSON.parse(readFixture("vectors.json")) as VectorFile;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
    return { version: 0, tokenPrefix: "", fingerprint: "", vectors: [] };
  }
}

/** The fixture keys, by name. Both builds and the generator read these. */
export const fixtureKeys = keyFile.keys;

export const FINGERPRINT = vectorFile.fingerprint;

/** A vector with the key names resolved and `now` made callable. */
export interface Vector {
  name: string;
  /** A PEM public key, or a ring of them — both builds accept both. */
  publicKey: string | Readonly<Record<string, string>>;
  token: string;
  options: VerifyOptions;
  expected: VerifyResult;
}

/**
 * A fixture key by name.
 *
 * A ring naming a key the file does not hold would otherwise read as a retired
 * key and pass the vector that expects exactly that, so a missing name is an
 * error here rather than an undefined further down.
 */
export function fixtureKey(name: string): VectorKeyPair {
  const pair = fixtureKeys[name];
  if (pair === undefined) throw new Error(`vectors/keys.json holds no key named ${JSON.stringify(name)}`);
  return pair;
}

export const vectors: readonly Vector[] = vectorFile.vectors.map((entry) => ({
  name: entry.name,
  publicKey: resolveKey(entry.publicKey),
  token: entry.token,
  options: toVerifyOptions(entry.options),
  expected: entry.expected,
}));

function resolveKey(ref: KeyRef): Vector["publicKey"] {
  if (typeof ref === "string") return publicKey(ref);
  return Object.fromEntries(Object.entries(ref).map(([kid, name]) => [kid, publicKey(name)]));
}

function publicKey(name: string): string {
  return fixtureKey(name).publicKey;
}

function toVerifyOptions(options: VectorOptions): VerifyOptions {
  const resolved: VerifyOptions = { now: () => options.now };
  if (options.skewSeconds !== undefined) resolved.skewSeconds = options.skewSeconds;
  if (options.graceSeconds !== undefined) resolved.graceSeconds = options.graceSeconds;
  if (options.machineFingerprint !== undefined) resolved.machineFingerprint = options.machineFingerprint;
  if (options.previous !== undefined) resolved.previous = options.previous;
  if (options.revocations !== undefined) resolved.revocations = options.revocations;
  return resolved;
}
