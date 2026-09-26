import { describe, expect, it } from "vitest";
import { createPrivateKey, sign } from "node:crypto";
import { bindMachine, issue, verify, verifyOrThrow, LicenseError } from "../src/index.js";
import { at, claims, keys, otherKeys, NOW } from "./helpers.js";

const token = () => issue(keys.privateKey, claims());
const check = (t: string, now = NOW) => verify(keys.publicKey, t, { now: at(now) });

describe("signature", () => {
  it("fails when a single payload character changes", () => {
    const [p, payload, s] = token().split(".") as [string, string, string];
    const flipped = payload.slice(0, -1) + (payload.endsWith("A") ? "B" : "A");
    expect(check(`${p}.${flipped}.${s}`)).toEqual({ ok: false, reason: "invalid_signature" });
  });

  it("fails under a different public key", () => {
    expect(verify(otherKeys.publicKey, token(), { now: at(NOW) })).toEqual({
      ok: false,
      reason: "invalid_signature",
    });
  });

  it("fails when someone upgrades features by re-encoding the payload", () => {
    const [p, , s] = token().split(".") as [string, string, string];
    const richer = Buffer.from(JSON.stringify(claims({ features: ["everything"] }))).toString("base64url");
    expect(check(`${p}.${richer}.${s}`).ok).toBe(false);
  });

  it("treats a wrong prefix or wrong part count as malformed, before touching crypto", () => {
    const [, payload, s] = token().split(".") as [string, string, string];
    expect(check(`lic9.${payload}.${s}`)).toEqual({ ok: false, reason: "malformed" });
    expect(check("just-garbage")).toEqual({ ok: false, reason: "malformed" });
    expect(check("")).toEqual({ ok: false, reason: "malformed" });
  });

  it("reports a valid signature over invalid claims as invalid_claims", () => {
    // Properly signed by the real key, but the payload is not a license —
    // e.g. an older issuer version with a different schema.
    const bad = Buffer.from(JSON.stringify({ id: "x" })).toString("base64url");
    const sig = sign(null, Buffer.from(`lic1.${bad}`), createPrivateKey(keys.privateKey)).toString("base64url");
    expect(check(`lic1.${bad}.${sig}`)).toEqual({ ok: false, reason: "invalid_claims" });
  });
});

describe("time", () => {
  it("is valid inside the window", () => {
    expect(check(token(), NOW).ok).toBe(true);
  });

  it("expires, with claims still returned so the UI can say which license", () => {
    const r = check(token(), NOW + 31 * 86_400);
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.reason).toBe("expired");
      expect(r.claims?.id).toBe("lic_test_1");
    }
  });

  it("honours notBefore", () => {
    const t = issue(keys.privateKey, claims({ notBefore: NOW + 3600 }));
    expect(check(t, NOW)).toMatchObject({ ok: false, reason: "not_yet_valid" });
    expect(check(t, NOW + 3600).ok).toBe(true);
  });

  it("allows clock skew up to the configured slack, not beyond", () => {
    const expiresAt = NOW;
    const t = issue(keys.privateKey, claims({ expiresAt }));
    expect(verify(keys.publicKey, t, { now: at(expiresAt + 30), skewSeconds: 60 }).ok).toBe(true);
    expect(verify(keys.publicKey, t, { now: at(expiresAt + 61), skewSeconds: 60 }).ok).toBe(false);
  });

  it("never expires when expiresAt is absent", () => {
    const { expiresAt: _dropped, ...noExpiry } = claims();
    const t = issue(keys.privateKey, noExpiry);
    expect(check(t, NOW + 100 * 365 * 86_400).ok).toBe(true);
  });
});

describe("grace period", () => {
  const expiresAt = NOW;
  const WEEK = 7 * 86_400;
  const graceToken = (over = {}) => issue(keys.privateKey, claims({ expiresAt, ...over }));
  const graced = (now: number, graceSeconds = WEEK) =>
    verify(keys.publicKey, graceToken(), { now: at(now), skewSeconds: 0, graceSeconds });

  it("keeps a just-expired license valid, and marks it so the UI can warn", () => {
    expect(graced(expiresAt + 86_400)).toEqual({
      ok: true,
      claims: claims({ expiresAt }),
      status: "expired_in_grace",
    });
  });

  it("marks nothing while the license is simply valid", () => {
    expect(graced(expiresAt - 1)).toEqual({ ok: true, claims: claims({ expiresAt }) });
  });

  it("expires for real once the window closes — grace that never ends is no expiry", () => {
    expect(graced(expiresAt + WEEK)).toMatchObject({ ok: false, reason: "expired" });
    expect(graced(expiresAt + WEEK).claims?.id).toBe("lic_test_1");
  });

  it("is off unless asked for", () => {
    expect(graced(expiresAt + 1, 0)).toMatchObject({ ok: false, reason: "expired" });
    expect(verify(keys.publicKey, graceToken(), { now: at(expiresAt + 1), skewSeconds: 0 })).toMatchObject({
      ok: false,
      reason: "expired",
    });
  });

  it("measures from expiresAt, with the skew still on top of it", () => {
    const t = graceToken();
    const inGrace = verify(keys.publicKey, t, { now: at(expiresAt + 3600 + 30), skewSeconds: 60, graceSeconds: 3600 });
    expect(inGrace).toMatchObject({ ok: true, status: "expired_in_grace" });
    const past = verify(keys.publicKey, t, { now: at(expiresAt + 3600 + 61), skewSeconds: 60, graceSeconds: 3600 });
    expect(past).toMatchObject({ ok: false, reason: "expired" });
  });

  it("does not paper over a different failure inside the window", () => {
    const t = graceToken({ machine: bindMachine("lic_test_1", "fp-of-this-box") });
    const result = verify(keys.publicKey, t, {
      now: at(expiresAt + 86_400),
      graceSeconds: WEEK,
      machineFingerprint: "fp-of-another-box",
    });
    expect(result).toMatchObject({ ok: false, reason: "machine_mismatch" });
  });
});

describe("machine binding", () => {
  const fingerprint = "fp-of-this-box";
  const bound = () => issue(keys.privateKey, claims({ machine: bindMachine("lic_test_1", fingerprint) }));

  it("accepts the bound machine and rejects any other", () => {
    expect(verify(keys.publicKey, bound(), { now: at(NOW), machineFingerprint: fingerprint }).ok).toBe(true);
    expect(verify(keys.publicKey, bound(), { now: at(NOW), machineFingerprint: "another" })).toMatchObject({
      ok: false,
      reason: "machine_mismatch",
    });
  });

  it("rejects a bound license when the caller supplies no fingerprint at all", () => {
    expect(verify(keys.publicKey, bound(), { now: at(NOW) })).toMatchObject({ reason: "machine_mismatch" });
  });

  it("binds the same machine differently under different license ids", () => {
    expect(bindMachine("lic_a", fingerprint)).not.toBe(bindMachine("lic_b", fingerprint));
  });

  it("does not put the fingerprint itself in the token", () => {
    expect(bound()).not.toContain(Buffer.from(fingerprint).toString("base64url"));
  });
});

describe("verifyOrThrow", () => {
  it("throws a LicenseError carrying the reason", () => {
    expect(() => verifyOrThrow(keys.publicKey, token(), { now: at(NOW + 40 * 86_400) })).toThrow(LicenseError);
    try {
      verifyOrThrow(otherKeys.publicKey, token(), { now: at(NOW) });
    } catch (err) {
      expect((err as LicenseError).reason).toBe("invalid_signature");
    }
  });
});
