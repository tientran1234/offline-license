import { createPrivateKey, sign } from "node:crypto";
import {
  bindMachine,
  createActivationRequest,
  fulfilActivation,
  issue,
  type VerifyOptions,
  type VerifyResult,
} from "../src/index.js";
import { at, claims, keys, otherKeys, NOW } from "./helpers.js";

/**
 * One table of tokens and the verdict each must produce.
 *
 * The Node build and the browser build are separate implementations over
 * different crypto APIs, so "they agree" is not something the type system can
 * say. Both run this table instead: a verdict that changes on one platform and
 * not the other fails here, whichever platform moved.
 */
export interface Vector {
  name: string;
  /** A PEM public key, or a ring of them — both builds accept both. */
  publicKey: string | Readonly<Record<string, string>>;
  token: string;
  options: VerifyOptions;
  expected: VerifyResult;
}

export const FINGERPRINT = "0f3c-vector-machine";
const OTHER_FINGERPRINT = "9a11-someone-elses-box";

const ring = { "2025": otherKeys.publicKey, "2026": keys.publicKey };

const DAY = 86_400;
const expiring = claims({ expiresAt: NOW - DAY });
const bound = claims({ machine: bindMachine(claims().id, FINGERPRINT) });
const future = claims({ notBefore: NOW + DAY, expiresAt: NOW + 30 * DAY });
const rotated = claims({ kid: "2026" });
const valued = claims({ features: { sso: true, seats: 25, tier: "pro", beta: false } });

/** A real exchange, with the nonce pinned so the token is reproducible. */
const ACTIVATION_NONCE = "mUoBrUO3tdZr2W7N";
const activationRequest = createActivationRequest({
  fingerprint: FINGERPRINT,
  nonce: ACTIVATION_NONCE,
  requestedAt: NOW - 3600,
});
const activated = claims({ machine: bindMachine(claims().id, FINGERPRINT), activation: ACTIVATION_NONCE });

/** The license an install is holding when a renewal arrives: expired yesterday. */
const PREVIOUS = { id: "lic_vector_0", expiresAt: NOW - DAY };
const renewed = claims({ renews: PREVIOUS.id });
const laterTerm = claims({ renews: PREVIOUS.id, notBefore: NOW + 30 * DAY, expiresAt: NOW + 395 * DAY });
const skipping = claims({ renews: "lic_vector_skipped" });

/** Signed by the real key, but the payload is not a license. */
function signedNonsense(): string {
  const payload = Buffer.from(JSON.stringify({ id: "x" })).toString("base64url");
  const signature = sign(null, Buffer.from(`lic1.${payload}`), createPrivateKey(keys.privateKey));
  return `lic1.${payload}.${signature.toString("base64url")}`;
}

function flipPayload(token: string): string {
  const [prefix, payload, signature] = token.split(".") as [string, string, string];
  return `${prefix}.${payload.slice(0, -1)}${payload.endsWith("A") ? "B" : "A"}.${signature}`;
}

export const vectors: readonly Vector[] = [
  {
    name: "a current license",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, claims()),
    options: { now: at(NOW) },
    expected: { ok: true, claims: claims() },
  },
  {
    name: "expired yesterday, inside a week of grace",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, expiring),
    options: { now: at(NOW), graceSeconds: 7 * DAY },
    expected: { ok: true, claims: expiring, status: "expired_in_grace" },
  },
  {
    name: "expired yesterday, past a one-hour grace",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, expiring),
    options: { now: at(NOW), graceSeconds: 3600 },
    expected: { ok: false, reason: "expired", claims: expiring },
  },
  {
    name: "expired yesterday, no grace asked for",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, expiring),
    options: { now: at(NOW) },
    expected: { ok: false, reason: "expired", claims: expiring },
  },
  {
    name: "expired thirty seconds ago, inside the default skew",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, claims({ expiresAt: NOW - 30 })),
    options: { now: at(NOW) },
    expected: { ok: true, claims: claims({ expiresAt: NOW - 30 }) },
  },
  {
    name: "not valid until tomorrow",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, future),
    options: { now: at(NOW) },
    expected: { ok: false, reason: "not_yet_valid", claims: future },
  },
  {
    name: "signed by a key the verifier does not hold",
    publicKey: keys.publicKey,
    token: issue(otherKeys.privateKey, claims()),
    options: { now: at(NOW) },
    expected: { ok: false, reason: "invalid_signature" },
  },
  {
    name: "one character of the payload changed",
    publicKey: keys.publicKey,
    token: flipPayload(issue(keys.privateKey, claims())),
    options: { now: at(NOW) },
    expected: { ok: false, reason: "invalid_signature" },
  },
  {
    name: "a lic2 token offered to a lic1 verifier",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, claims()).replace(/^lic1/, "lic2"),
    options: { now: at(NOW) },
    expected: { ok: false, reason: "malformed" },
  },
  {
    name: "not a token at all",
    publicKey: keys.publicKey,
    token: "just-garbage",
    options: { now: at(NOW) },
    expected: { ok: false, reason: "malformed" },
  },
  {
    name: "an empty string",
    publicKey: keys.publicKey,
    token: "",
    options: { now: at(NOW) },
    expected: { ok: false, reason: "malformed" },
  },
  {
    name: "a good signature over something that is not a license",
    publicKey: keys.publicKey,
    token: signedNonsense(),
    options: { now: at(NOW) },
    expected: { ok: false, reason: "invalid_claims" },
  },
  {
    name: "machine-bound, on the machine it was issued for",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, bound),
    options: { now: at(NOW), machineFingerprint: FINGERPRINT },
    expected: { ok: true, claims: bound },
  },
  {
    name: "machine-bound, copied to another box",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, bound),
    options: { now: at(NOW), machineFingerprint: OTHER_FINGERPRINT },
    expected: { ok: false, reason: "machine_mismatch", claims: bound },
  },
  {
    name: "machine-bound, with no fingerprint offered",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, bound),
    options: { now: at(NOW) },
    expected: { ok: false, reason: "machine_mismatch", claims: bound },
  },
  {
    name: "features as a record of values rather than a list of names",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, valued),
    options: { now: at(NOW) },
    expected: { ok: true, claims: valued },
  },
  {
    // The web build never makes a request — the exchange happens where the
    // install does — but it has to verify the license one produced.
    name: "a license issued in answer to an activation request",
    publicKey: keys.publicKey,
    token: fulfilActivation(keys.privateKey, activationRequest, claims()),
    options: { now: at(NOW), machineFingerprint: FINGERPRINT },
    expected: { ok: true, claims: activated },
  },
  {
    name: "a license issued in answer to an activation request, on another machine",
    publicKey: keys.publicKey,
    token: fulfilActivation(keys.privateKey, activationRequest, claims()),
    options: { now: at(NOW), machineFingerprint: OTHER_FINGERPRINT },
    expected: { ok: false, reason: "machine_mismatch", claims: activated },
  },
  {
    name: "a renewal of the license the box is holding",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, renewed),
    options: { now: at(NOW), previous: PREVIOUS },
    expected: { ok: true, claims: renewed },
  },
  {
    name: "a renewal that skips a generation",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, skipping),
    options: { now: at(NOW), previous: PREVIOUS },
    expected: { ok: false, reason: "renewal_gap", claims: skipping },
  },
  {
    name: "a renewal dated from the next term, while the one it replaces is in grace",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, laterTerm),
    options: { now: at(NOW), graceSeconds: 7 * DAY, previous: PREVIOUS },
    expected: { ok: true, claims: laterTerm, status: "expired_in_grace" },
  },
  {
    name: "the same renewal once that grace has run out",
    publicKey: keys.publicKey,
    token: issue(keys.privateKey, laterTerm),
    options: { now: at(NOW + 8 * DAY), graceSeconds: 7 * DAY, previous: PREVIOUS },
    expected: { ok: false, reason: "not_yet_valid", claims: laterTerm },
  },
  {
    name: "a ring, and a kid naming the key that signed",
    publicKey: ring,
    token: issue(keys.privateKey, rotated),
    options: { now: at(NOW) },
    expected: { ok: true, claims: rotated },
  },
  {
    name: "a ring, and a kid naming a retired key",
    publicKey: ring,
    token: issue(keys.privateKey, claims({ kid: "2019" })),
    options: { now: at(NOW) },
    expected: { ok: false, reason: "invalid_signature" },
  },
  {
    name: "a ring, and a token issued before rotation",
    publicKey: ring,
    token: issue(keys.privateKey, claims()),
    options: { now: at(NOW) },
    expected: { ok: true, claims: claims() },
  },
];
