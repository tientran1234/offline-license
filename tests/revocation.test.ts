import { describe, expect, it } from "vitest";
import {
  issue,
  issueRevocationList,
  LicenseGuard,
  readRevocationList,
  REVOCATION_PREFIX,
  RevocationError,
  verify,
  type Predecessor,
  type RevocationEntry,
  type RevocationList,
} from "../src/index.js";
import { at, claims, keys, NOW, otherKeys } from "./helpers.js";

const DAY = 86_400;

const entry = (over: Partial<RevocationEntry> = {}): RevocationEntry => ({
  id: "lic_test_1",
  revokedAt: NOW - DAY,
  ...over,
});

const list = (over = {}) => issueRevocationList(keys.privateKey, { issuedAt: NOW, revoked: [entry()], ...over });

/** Edit one character of a signed list's payload, leaving the signature alone. */
function flipPayload(signed: string): string {
  const [prefix, payload, signature] = signed.split(".") as [string, string, string];
  return `${prefix}.${payload.slice(0, -1)}${payload.endsWith("A") ? "B" : "A"}.${signature}`;
}

describe("the revocation list", () => {
  it("round-trips what the issuer put in it", () => {
    expect(readRevocationList(keys.publicKey, list())).toEqual({ issuedAt: NOW, revoked: [entry()] });
  });

  it("carries an expiry and a reason when the issuer sets them", () => {
    const signed = list({ expiresAt: NOW + 30 * DAY, revoked: [entry({ reason: "chargeback" })] });
    expect(readRevocationList(keys.publicKey, signed)).toEqual({
      issuedAt: NOW,
      expiresAt: NOW + 30 * DAY,
      revoked: [entry({ reason: "chargeback" })],
    });
  });

  it("is reproducible: the same entries from the same key are the same bytes", () => {
    // Canonical JSON and deterministic Ed25519, as for a token. A list an
    // operator re-cuts to confirm what they published must not drift.
    expect(list()).toBe(list());
    expect(list()).toMatch(new RegExp(`^${REVOCATION_PREFIX}\\.[\\w-]+\\.[\\w-]+$`));
  });

  it("refuses a list signed by a key the verifier does not hold", () => {
    const signed = issueRevocationList(otherKeys.privateKey, { issuedAt: NOW, revoked: [entry()] });
    expect(() => readRevocationList(keys.publicKey, signed)).toThrow(
      expect.objectContaining({ name: "RevocationError", reason: "invalid_signature" }),
    );
  });

  it("refuses a list whose entries were edited after signing", () => {
    // The whole point of signing it: an install that could be handed an edited
    // list could be handed one with its own id quietly taken off.
    expect(() => readRevocationList(keys.publicKey, flipPayload(list()))).toThrow(
      expect.objectContaining({ reason: "invalid_signature" }),
    );
  });

  it("refuses a blob that is not a list at all", () => {
    for (const blob of ["", "garbage", "rev1.only-two", list().replace(/^rev1/, "rev2")]) {
      expect(() => readRevocationList(keys.publicKey, blob)).toThrow(
        expect.objectContaining({ reason: "malformed" }),
      );
    }
  });

  it("refuses entries it cannot read, rather than skipping them", () => {
    // Dropping the entry it cannot parse would be the attacker's preferred
    // outcome, so an unreadable list revokes nothing only by throwing.
    for (const revoked of [[{ revokedAt: NOW }], [{ id: "lic_1" }], [{ id: "", revokedAt: NOW }], ["lic_1"]]) {
      expect(() =>
        readRevocationList(keys.publicKey, issueRevocationList(keys.privateKey, { revoked } as never)),
      ).toThrow(RevocationError);
    }
  });

  it("picks the signing key out of a ring by the list's kid", () => {
    const ring = { "2025": otherKeys.publicKey, "2026": keys.publicKey };
    const signed = list({ kid: "2026" });
    expect(readRevocationList(ring, signed)).toMatchObject({ kid: "2026" });
    // A kid naming a key the ring no longer holds is not a list to act on, the
    // same way a token naming one is not a license.
    expect(() => readRevocationList(ring, list({ kid: "2019" }))).toThrow(
      expect.objectContaining({ reason: "invalid_signature" }),
    );
  });
});

/** The list as a verifier takes it: already read, already proved to be the issuer's. */
const read = (over = {}): RevocationList => readRevocationList(keys.publicKey, list(over));

const token = (over = {}) => issue(keys.privateKey, claims(over));

const check = (options = {}) => verify(keys.publicKey, token(), { now: at(NOW), ...options });

describe("checking a license against a revocation list", () => {
  it("refuses a license the list names", () => {
    // The claims come back, as they do on expiry, so a screen can say which
    // license was withdrawn rather than only that something was.
    expect(check({ revocations: read() })).toEqual({ ok: false, reason: "revoked", claims: claims() });
  });

  it("accepts a license the list does not name", () => {
    const others = read({ revoked: [entry({ id: "lic_someone_else" })] });
    expect(check({ revocations: others })).toEqual({ ok: true, claims: claims() });
  });

  it("checks nothing when no list is supplied", () => {
    // Every install verified this way before lists existed, and a product that
    // never adopts them must keep verifying exactly as it did.
    expect(check()).toEqual({ ok: true, claims: claims() });
  });

  it("treats a revocation dated in the future as a notice, until the date passes", () => {
    const pending = read({ revoked: [entry({ revokedAt: NOW + DAY })] });
    expect(check({ revocations: pending })).toEqual({ ok: true, claims: claims() });
    // No slack on the date, unlike expiry: it bites the second the issuer said.
    expect(verify(keys.publicKey, token(), { now: at(NOW + DAY), revocations: pending })).toMatchObject({
      ok: false,
      reason: "revoked",
    });
  });

  it("bites the moment the issuer dated it, taking no slack from --skew", () => {
    // A list published to take effect now has to work now. Reading it the way
    // expiry is read would leave a withdrawn license honoured for another skew.
    const immediate = read({ revoked: [entry({ revokedAt: NOW })] });
    expect(check({ revocations: immediate })).toMatchObject({ ok: false, reason: "revoked" });
    expect(check({ revocations: immediate, skewSeconds: 3600 })).toMatchObject({ ok: false, reason: "revoked" });
  });

  it("refuses every license once the list itself has expired", () => {
    // A revoked install can stop collecting lists; a list that is believed
    // forever is advisory, so an install told to check revocation fails closed
    // on evidence older than the issuer vouched for.
    const stale = read({ expiresAt: NOW - DAY, revoked: [entry({ id: "lic_someone_else" })] });
    expect(check({ revocations: stale })).toEqual({
      ok: false,
      reason: "revocation_stale",
      claims: claims(),
    });
  });

  it("keeps believing a list the issuer gave no expiry", () => {
    const perpetual = read({ revoked: [entry({ id: "lic_someone_else" })] });
    const longTerm = token({ expiresAt: NOW + 600 * DAY });
    expect(verify(keys.publicKey, longTerm, { now: at(NOW + 500 * DAY), revocations: perpetual })).toMatchObject({
      ok: true,
    });
  });

  it("says revoked rather than stale when the stale list names the license", () => {
    const stale = read({ expiresAt: NOW - DAY });
    expect(check({ revocations: stale })).toMatchObject({ ok: false, reason: "revoked" });
  });

  it("runs before the clock and the chain, because a withdrawn license is withdrawn either way", () => {
    const expired = claims({ expiresAt: NOW - 30 * DAY });
    expect(
      verify(keys.publicKey, issue(keys.privateKey, expired), { now: at(NOW), revocations: read() }),
    ).toMatchObject({ ok: false, reason: "revoked" });

    const previous: Predecessor = { id: "lic_test_0", expiresAt: NOW - DAY };
    const skipping = claims({ renews: "lic_test_skipped" });
    expect(
      verify(keys.publicKey, issue(keys.privateKey, skipping), { now: at(NOW), previous, revocations: read() }),
    ).toMatchObject({ ok: false, reason: "revoked" });
  });

  it("stops the guard answering questions, and reports the reason to onCheck", () => {
    const seen: string[] = [];
    const guard = new LicenseGuard({
      publicKey: keys.publicKey,
      token: token(),
      now: at(NOW),
      revocations: read(),
      onCheck: (result) => void seen.push(result.ok ? "ok" : result.reason),
    });
    expect(guard.hasFeature("export")).toBe(false);
    expect(guard.claims()).toBeNull();
    expect(() => guard.assertFeature("export")).toThrow(expect.objectContaining({ reason: "revoked" }));
    expect(new Set(seen)).toEqual(new Set(["revoked"]));
  });
});
