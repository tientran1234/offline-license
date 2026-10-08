import { writeFileSync } from "node:fs";
import { createPrivateKey, sign } from "node:crypto";
import {
  bindMachine,
  createActivationRequest,
  fulfilActivation,
  issue,
  type LicenseClaims,
  type RevocationList,
} from "../src/index.js";
import { canonicalJson } from "../src/encoding.js";
import { fixtureKey, vectorsDir, type VectorEntry, type VectorFile } from "./vectors.js";

/**
 * How `vectors/vectors.json` is produced.
 *
 * The file is checked in and the suite reads it from disk, so this generator is
 * not what proves the tokens verify — it is what proves the checked-in bytes
 * are still the bytes this release signs. `vectors.test.ts` regenerates and
 * compares; `pnpm vectors` regenerates and writes.
 *
 * Nothing here comes from `helpers.ts`, deliberately. A published fixture set
 * is a contract with implementations that cannot see this repository, and it
 * should not move because a helper every other test shares picked up a field.
 */

const NOW = 1_800_000_000; // a fixed "now", unix seconds
const DAY = 86_400;

/** The machine the bound vectors are issued for, and one that is not it. */
const FINGERPRINT = "0f3c-vector-machine";
const OTHER_FINGERPRINT = "9a11-someone-elses-box";

const signingKey = fixtureKey("signing").privateKey;
const otherKey = fixtureKey("other").privateKey;

/** The keys a rotating verifier holds, by the `kid` each answers to. */
const ring = { "2025": "other", "2026": "signing" };

function claims(over: Partial<LicenseClaims> = {}): LicenseClaims {
  return {
    id: "lic_test_1",
    licensee: "Acme Ltd",
    features: ["export", "sso"],
    limits: { seats: 10 },
    issuedAt: NOW - 3600,
    expiresAt: NOW + 30 * DAY,
    ...over,
  };
}

const expiring = claims({ expiresAt: NOW - DAY });
const bound = claims({ machine: bindMachine(claims().id, FINGERPRINT) });
const future = claims({ notBefore: NOW + DAY, expiresAt: NOW + 30 * DAY });
const rotated = claims({ kid: "2026" });
const valued = claims({ features: { sso: true, seats: 25, tier: "pro", beta: false } });

/**
 * A real exchange, with the nonce pinned so the token is reproducible.
 *
 * The request's own signing key is pinned too. The license does not depend on
 * it — only the fingerprint and the nonce cross over — but a generator that
 * minted a key per run would be reproducible by accident rather than by
 * construction.
 */
const ACTIVATION_NONCE = "mUoBrUO3tdZr2W7N";
const activationRequest = createActivationRequest({
  fingerprint: FINGERPRINT,
  nonce: ACTIVATION_NONCE,
  requestedAt: NOW - 3600,
  signingKey: otherKey,
});
const activated = claims({ machine: bindMachine(claims().id, FINGERPRINT), activation: ACTIVATION_NONCE });

/** The license an install is holding when a renewal arrives: expired yesterday. */
const PREVIOUS = { id: "lic_vector_0", expiresAt: NOW - DAY };
const renewed = claims({ renews: PREVIOUS.id });
const laterTerm = claims({ renews: PREVIOUS.id, notBefore: NOW + 30 * DAY, expiresAt: NOW + 395 * DAY });
const skipping = claims({ renews: "lic_vector_skipped" });

/**
 * The lists a verifier is handed, as readRevocationList() would hand them over.
 *
 * The signed `rev1` blob is not in the set — see vectors/README.md. What a
 * verifier has to agree on is the verdict a list produces, and the list that
 * produces it is plain claims by the time the check sees them.
 */
const REVOKED = { id: "lic_test_1", revokedAt: NOW - DAY, reason: "chargeback" };
const currentList: RevocationList = { issuedAt: NOW - DAY, revoked: [REVOKED] };
const staleList: RevocationList = {
  issuedAt: NOW - 90 * DAY,
  expiresAt: NOW - DAY,
  revoked: [{ id: "lic_vector_other", revokedAt: NOW - 60 * DAY }],
};
const pendingList: RevocationList = {
  issuedAt: NOW,
  revoked: [{ id: "lic_test_1", revokedAt: NOW + DAY }],
};

/** Signed by the real key, but the payload is not a license. */
function signedNonsense(): string {
  const payload = Buffer.from(JSON.stringify({ id: "x" })).toString("base64url");
  const signature = sign(null, Buffer.from(`lic1.${payload}`), createPrivateKey(signingKey));
  return `lic1.${payload}.${signature.toString("base64url")}`;
}

function flipPayload(token: string): string {
  const [prefix, payload, signature] = token.split(".") as [string, string, string];
  return `${prefix}.${payload.slice(0, -1)}${payload.endsWith("A") ? "B" : "A"}.${signature}`;
}

const table: readonly VectorEntry[] = [
  {
    name: "a current license",
    publicKey: "signing",
    token: issue(signingKey, claims()),
    options: { now: NOW },
    expected: { ok: true, claims: claims() },
  },
  {
    name: "expired yesterday, inside a week of grace",
    publicKey: "signing",
    token: issue(signingKey, expiring),
    options: { now: NOW, graceSeconds: 7 * DAY },
    expected: { ok: true, claims: expiring, status: "expired_in_grace" },
  },
  {
    name: "expired yesterday, past a one-hour grace",
    publicKey: "signing",
    token: issue(signingKey, expiring),
    options: { now: NOW, graceSeconds: 3600 },
    expected: { ok: false, reason: "expired", claims: expiring },
  },
  {
    name: "expired yesterday, no grace asked for",
    publicKey: "signing",
    token: issue(signingKey, expiring),
    options: { now: NOW },
    expected: { ok: false, reason: "expired", claims: expiring },
  },
  {
    name: "expired thirty seconds ago, inside the default skew",
    publicKey: "signing",
    token: issue(signingKey, claims({ expiresAt: NOW - 30 })),
    options: { now: NOW },
    expected: { ok: true, claims: claims({ expiresAt: NOW - 30 }) },
  },
  {
    name: "not valid until tomorrow",
    publicKey: "signing",
    token: issue(signingKey, future),
    options: { now: NOW },
    expected: { ok: false, reason: "not_yet_valid", claims: future },
  },
  {
    name: "signed by a key the verifier does not hold",
    publicKey: "signing",
    token: issue(otherKey, claims()),
    options: { now: NOW },
    expected: { ok: false, reason: "invalid_signature" },
  },
  {
    name: "one character of the payload changed",
    publicKey: "signing",
    token: flipPayload(issue(signingKey, claims())),
    options: { now: NOW },
    expected: { ok: false, reason: "invalid_signature" },
  },
  {
    name: "a lic2 token offered to a lic1 verifier",
    publicKey: "signing",
    token: issue(signingKey, claims()).replace(/^lic1/, "lic2"),
    options: { now: NOW },
    expected: { ok: false, reason: "malformed" },
  },
  {
    name: "not a token at all",
    publicKey: "signing",
    token: "just-garbage",
    options: { now: NOW },
    expected: { ok: false, reason: "malformed" },
  },
  {
    name: "an empty string",
    publicKey: "signing",
    token: "",
    options: { now: NOW },
    expected: { ok: false, reason: "malformed" },
  },
  {
    name: "a good signature over something that is not a license",
    publicKey: "signing",
    token: signedNonsense(),
    options: { now: NOW },
    expected: { ok: false, reason: "invalid_claims" },
  },
  {
    name: "machine-bound, on the machine it was issued for",
    publicKey: "signing",
    token: issue(signingKey, bound),
    options: { now: NOW, machineFingerprint: FINGERPRINT },
    expected: { ok: true, claims: bound },
  },
  {
    name: "machine-bound, copied to another box",
    publicKey: "signing",
    token: issue(signingKey, bound),
    options: { now: NOW, machineFingerprint: OTHER_FINGERPRINT },
    expected: { ok: false, reason: "machine_mismatch", claims: bound },
  },
  {
    name: "machine-bound, with no fingerprint offered",
    publicKey: "signing",
    token: issue(signingKey, bound),
    options: { now: NOW },
    expected: { ok: false, reason: "machine_mismatch", claims: bound },
  },
  {
    name: "features as a record of values rather than a list of names",
    publicKey: "signing",
    token: issue(signingKey, valued),
    options: { now: NOW },
    expected: { ok: true, claims: valued },
  },
  {
    // The web build never makes a request — the exchange happens where the
    // install does — but it has to verify the license one produced.
    name: "a license issued in answer to an activation request",
    publicKey: "signing",
    token: fulfilActivation(signingKey, activationRequest, claims()),
    options: { now: NOW, machineFingerprint: FINGERPRINT },
    expected: { ok: true, claims: activated },
  },
  {
    name: "a license issued in answer to an activation request, on another machine",
    publicKey: "signing",
    token: fulfilActivation(signingKey, activationRequest, claims()),
    options: { now: NOW, machineFingerprint: OTHER_FINGERPRINT },
    expected: { ok: false, reason: "machine_mismatch", claims: activated },
  },
  {
    name: "a renewal of the license the box is holding",
    publicKey: "signing",
    token: issue(signingKey, renewed),
    options: { now: NOW, previous: PREVIOUS },
    expected: { ok: true, claims: renewed },
  },
  {
    name: "a renewal that skips a generation",
    publicKey: "signing",
    token: issue(signingKey, skipping),
    options: { now: NOW, previous: PREVIOUS },
    expected: { ok: false, reason: "renewal_gap", claims: skipping },
  },
  {
    name: "a renewal dated from the next term, while the one it replaces is in grace",
    publicKey: "signing",
    token: issue(signingKey, laterTerm),
    options: { now: NOW, graceSeconds: 7 * DAY, previous: PREVIOUS },
    expected: { ok: true, claims: laterTerm, status: "expired_in_grace" },
  },
  {
    name: "the same renewal once that grace has run out",
    publicKey: "signing",
    token: issue(signingKey, laterTerm),
    options: { now: NOW + 8 * DAY, graceSeconds: 7 * DAY, previous: PREVIOUS },
    expected: { ok: false, reason: "not_yet_valid", claims: laterTerm },
  },
  {
    name: "a license the issuer's revocation list names",
    publicKey: "signing",
    token: issue(signingKey, claims()),
    options: { now: NOW, revocations: currentList },
    expected: { ok: false, reason: "revoked", claims: claims() },
  },
  {
    name: "a license the revocation list does not name",
    publicKey: "signing",
    token: issue(signingKey, claims({ id: "lic_vector_elsewhere" })),
    options: { now: NOW, revocations: currentList },
    expected: { ok: true, claims: claims({ id: "lic_vector_elsewhere" }) },
  },
  {
    name: "a revocation list whose own date has passed",
    publicKey: "signing",
    token: issue(signingKey, claims()),
    options: { now: NOW, revocations: staleList },
    expected: { ok: false, reason: "revocation_stale", claims: claims() },
  },
  {
    name: "a revocation dated tomorrow, which has not taken effect",
    publicKey: "signing",
    token: issue(signingKey, claims()),
    options: { now: NOW, revocations: pendingList },
    expected: { ok: true, claims: claims() },
  },
  {
    name: "a ring, and a kid naming the key that signed",
    publicKey: ring,
    token: issue(signingKey, rotated),
    options: { now: NOW },
    expected: { ok: true, claims: rotated },
  },
  {
    name: "a ring, and a kid naming a retired key",
    publicKey: ring,
    token: issue(signingKey, claims({ kid: "2019" })),
    options: { now: NOW },
    expected: { ok: false, reason: "invalid_signature" },
  },
  {
    name: "a ring, and a token issued before rotation",
    publicKey: ring,
    token: issue(signingKey, claims()),
    options: { now: NOW },
    expected: { ok: true, claims: claims() },
  },
];

export function buildVectorFile(): VectorFile {
  return {
    version: 1,
    tokenPrefix: "lic1",
    fingerprint: FINGERPRINT,
    // Sorted keys inside each entry, like the payloads: the file is read as a
    // diff by whoever regenerates it, and as bytes by an implementation
    // comparing its own. The entry's own fields stay in the order above.
    vectors: table.map((entry) => ({
      name: entry.name,
      publicKey: canonical(entry.publicKey),
      token: entry.token,
      options: canonical(entry.options),
      expected: canonical(entry.expected),
    })),
  };
}

function canonical<T>(value: T): T {
  return JSON.parse(canonicalJson(value)) as T;
}

/** What `vectors/vectors.json` holds, to the byte. */
export function serializeVectorFile(file: VectorFile): string {
  return `${JSON.stringify(file, null, 2)}\n`;
}

export function writeVectorFile(): void {
  writeFileSync(new URL("vectors.json", vectorsDir), serializeVectorFile(buildVectorFile()));
}
