import { describe, expect, it } from "vitest";
import {
  issueRevocationList,
  readRevocationList,
  REVOCATION_PREFIX,
  RevocationError,
  type RevocationEntry,
} from "../src/index.js";
import { keys, NOW, otherKeys } from "./helpers.js";

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
