import { describe, expect, it } from "vitest";
import { generateKeyPair, issue, LicenseGuard, verify, type KeyRing } from "../src/index.js";
import { at, claims, keys, otherKeys, NOW } from "./helpers.js";

// "old" is the key being rotated out, "new" the one taking over.
const old = keys;
const fresh = otherKeys;

const ring: KeyRing = { old: old.publicKey, new: fresh.publicKey };

const signed = (pair: typeof keys, kid: string | undefined, over = {}) =>
  issue(pair.privateKey, claims(kid === undefined ? over : { kid, ...over }));

const check = (trusted: Parameters<typeof verify>[0], token: string, now = NOW) =>
  verify(trusted, token, { now: at(now) });

describe("a key ring, selected by kid", () => {
  it("verifies each key's own licenses while both are trusted", () => {
    expect(check(ring, signed(old, "old")).ok).toBe(true);
    expect(check(ring, signed(fresh, "new")).ok).toBe(true);
  });

  it("rejects a kid that names no key in the ring", () => {
    expect(check(ring, signed(fresh, "next"))).toEqual({ ok: false, reason: "invalid_signature" });
  });

  it("never falls back to the rest of the ring when the kid is unknown", () => {
    // The signature here is real and one of the ring's keys would accept it.
    // Only the kid is wrong, and that alone must be fatal: a ring that tries
    // every key on a miss cannot retire one.
    const token = signed(fresh, "typo");
    expect(check({ new: fresh.publicKey }, token)).toEqual({ ok: false, reason: "invalid_signature" });
    expect(check({ new: fresh.publicKey }, signed(fresh, "new")).ok).toBe(true);
  });

  it("retires a key by dropping it from the ring", () => {
    const token = signed(old, "old");
    expect(check(ring, token).ok).toBe(true);
    expect(check({ new: fresh.publicKey }, token)).toEqual({ ok: false, reason: "invalid_signature" });
  });

  it("rejects a kid pointing at a key that did not sign the token", () => {
    // Mislabelled rather than forged: the kid selects `old`, which never saw
    // these bytes. Rewriting the kid to "new" is no way out — the kid is inside
    // the signature, so the edit invalidates it.
    expect(check(ring, signed(fresh, "old"))).toEqual({ ok: false, reason: "invalid_signature" });
  });

  it("accepts a token issued before rotation, which names no key at all", () => {
    // Every key in the ring is one the caller trusts, so a kid-less token is
    // tried against each. This is what makes the overlap period work.
    expect(check(ring, signed(old, undefined)).ok).toBe(true);
    expect(check(ring, signed(fresh, undefined)).ok).toBe(true);
  });

  it("rejects a kid-less token signed by a key the ring never held", () => {
    const stranger = generateKeyPair();
    expect(check(ring, issue(stranger.privateKey, claims()))).toEqual({
      ok: false,
      reason: "invalid_signature",
    });
  });

  it("trusts nothing when the ring is empty", () => {
    expect(check({}, signed(old, "old"))).toEqual({ ok: false, reason: "invalid_signature" });
    expect(check({}, signed(old, undefined))).toEqual({ ok: false, reason: "invalid_signature" });
  });

  it("keeps the checks in order: the key is chosen, then the claims are judged", () => {
    const stale = signed(old, "old", { expiresAt: NOW - 86_400 });
    const result = check(ring, stale);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("expired");
      expect(result.claims?.kid).toBe("old");
    }
  });

  it("treats an unreadable payload as no kid rather than crashing", () => {
    const junk = Buffer.from("not json at all").toString("base64url");
    expect(check(ring, `lic1.${junk}.${junk}`)).toEqual({ ok: false, reason: "invalid_signature" });
  });
});

describe("a single key, unchanged by rotation", () => {
  it("still verifies a token that carries a kid", () => {
    expect(check(old.publicKey, signed(old, "old")).ok).toBe(true);
  });

  it("still rejects one signed by anybody else, kid or no kid", () => {
    expect(check(old.publicKey, signed(fresh, "old"))).toEqual({ ok: false, reason: "invalid_signature" });
    expect(check(old.publicKey, signed(fresh, undefined))).toEqual({ ok: false, reason: "invalid_signature" });
  });
});

describe("LicenseGuard", () => {
  it("takes a ring wherever it takes a key", () => {
    const guard = new LicenseGuard({ publicKey: ring, token: signed(fresh, "new"), now: at(NOW) });
    expect(guard.hasFeature("sso")).toBe(true);

    const retired = new LicenseGuard({ publicKey: { new: fresh.publicKey }, token: signed(old, "old"), now: at(NOW) });
    expect(retired.claims()).toBeNull();
    expect(retired.hasFeature("sso")).toBe(false);
  });
});
