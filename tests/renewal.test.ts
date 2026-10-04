import { describe, expect, it } from "vitest";
import { issue, LicenseGuard, verify, type Predecessor } from "../src/index.js";
import { at, claims, keys, NOW } from "./helpers.js";

const DAY = 86_400;
const GRACE = 7 * DAY;

/** The license the install is holding: a term that ran out yesterday. */
const previous: Predecessor = { id: "lic_test_0", expiresAt: NOW - DAY };

const renewal = (over = {}) => claims({ renews: previous.id, ...over });

/** A renewal whose own term starts a month out, so nothing but grace carries it. */
const notStarted = () => renewal({ notBefore: NOW + 30 * DAY, expiresAt: NOW + 395 * DAY });

const check = (over = {}, options = {}) =>
  verify(keys.publicKey, issue(keys.privateKey, renewal(over)), { now: at(NOW), ...options });

describe("the renewal chain", () => {
  it("accepts a renewal that names the license being replaced", () => {
    expect(check({}, { previous })).toEqual({ ok: true, claims: renewal() });
  });

  it("refuses a renewal that skips a generation", () => {
    const skipping = renewal({ renews: "lic_test_skipped" });
    const result = verify(keys.publicKey, issue(keys.privateKey, skipping), { now: at(NOW), previous });
    // The claims come back, as they do on expiry, so a screen can say which
    // license was offered and which one the box actually holds.
    expect(result).toEqual({ ok: false, reason: "renewal_gap", claims: skipping });
  });

  it("accepts a renewal whose term has not begun while the license it replaces is in grace", () => {
    const token = issue(keys.privateKey, notStarted());
    expect(verify(keys.publicKey, token, { now: at(NOW), graceSeconds: GRACE, previous })).toEqual({
      ok: true,
      claims: notStarted(),
      // Still a warning, not silence: the entitlement in force is the old
      // license's grace, and the UI has to keep saying a renewal is overdue.
      status: "expired_in_grace",
    });
  });

  it("stops accepting it once the predecessor's grace has run out", () => {
    const token = issue(keys.privateKey, notStarted());
    expect(verify(keys.publicKey, token, { now: at(NOW + 8 * DAY), graceSeconds: GRACE, previous })).toEqual({
      ok: false,
      reason: "not_yet_valid",
      claims: notStarted(),
    });
  });

  it("inherits nothing from a predecessor that has not expired, or from a grace nobody asked for", () => {
    const token = issue(keys.privateKey, notStarted());
    const live: Predecessor = { id: previous.id, expiresAt: NOW + DAY };
    expect(verify(keys.publicKey, token, { now: at(NOW), graceSeconds: GRACE, previous: live })).toMatchObject({
      ok: false,
      reason: "not_yet_valid",
    });
    expect(verify(keys.publicKey, token, { now: at(NOW), previous })).toMatchObject({
      ok: false,
      reason: "not_yet_valid",
    });
  });

  it("inherits nothing from a predecessor that never expires", () => {
    const token = issue(keys.privateKey, notStarted());
    const perpetual: Predecessor = { id: previous.id };
    expect(
      verify(keys.publicKey, token, { now: at(NOW), graceSeconds: GRACE, previous: perpetual }),
    ).toMatchObject({ ok: false, reason: "not_yet_valid" });
  });

  it("leaves a token carrying no renews exactly as it was", () => {
    expect(verify(keys.publicKey, issue(keys.privateKey, claims()), { now: at(NOW), previous })).toEqual({
      ok: true,
      claims: claims(),
    });
  });

  it("checks nothing when the product offers no predecessor", () => {
    expect(check({}, {})).toEqual({ ok: true, claims: renewal() });
    expect(check({ renews: "lic_test_skipped" }, {})).toEqual({
      ok: true,
      claims: renewal({ renews: "lic_test_skipped" }),
    });
  });

  it("reports the gap rather than the timing, so the operator hears the useful half", () => {
    const wrongChain = { ...notStarted(), renews: "lic_test_skipped" };
    expect(verify(keys.publicKey, issue(keys.privateKey, wrongChain), { now: at(NOW), previous })).toMatchObject({
      ok: false,
      reason: "renewal_gap",
    });
  });

  it("still refuses a license that is not valid here, late or not", () => {
    const bound = { ...notStarted(), machine: "not-this-box" };
    expect(
      verify(keys.publicKey, issue(keys.privateKey, bound), { now: at(NOW), graceSeconds: GRACE, previous }),
    ).toMatchObject({ ok: false, reason: "machine_mismatch" });
  });

  it("refuses to sign a license that renews itself", () => {
    expect(() => issue(keys.privateKey, claims({ renews: claims().id }))).toThrow(
      /renews must name another license/,
    );
  });

  it("answers through the guard, which carries the predecessor like any other option", () => {
    const guard = new LicenseGuard({
      publicKey: keys.publicKey,
      token: issue(keys.privateKey, notStarted()),
      now: at(NOW),
      graceSeconds: GRACE,
      previous,
    });
    expect(guard.hasFeature("sso")).toBe(true);
    expect(guard.inGrace()).toBe(true);

    const stale = new LicenseGuard({
      publicKey: keys.publicKey,
      token: issue(keys.privateKey, renewal({ renews: "lic_test_skipped" })),
      now: at(NOW),
      previous,
    });
    expect(stale.claims()).toBeNull();
    expect(stale.hasFeature("sso")).toBe(false);
  });
});
