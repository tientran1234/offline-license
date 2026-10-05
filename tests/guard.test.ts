import { describe, expect, it } from "vitest";
import { CheckLog, issue, LicenseError, LicenseGuard, MemoryCheckLogStore, type VerifyResult } from "../src/index.js";
import { at, claims, keys, NOW } from "./helpers.js";

const guard = (over = {}, now = NOW) =>
  new LicenseGuard({ publicKey: keys.publicKey, token: issue(keys.privateKey, claims(over)), now: at(now) });

describe("LicenseGuard", () => {
  it("answers feature questions", () => {
    const g = guard();
    expect(g.hasFeature("sso")).toBe(true);
    expect(g.hasFeature("billing")).toBe(false);
  });

  it("says no to everything once the license is invalid — no feature leaks through", () => {
    const g = guard({}, NOW + 40 * 86_400); // expired
    expect(g.hasFeature("sso")).toBe(false);
    expect(g.claims()).toBeNull();
    expect(g.limit("seats")).toBeNull();
    expect(g.withinLimit("seats", 0)).toBe(false);
  });

  it("assertFeature distinguishes a bad license from a missing feature", () => {
    expect(() => guard({}, NOW + 40 * 86_400).assertFeature("sso")).toThrow(
      expect.objectContaining({ reason: "expired" }),
    );
    expect(() => guard().assertFeature("billing")).toThrow(
      expect.objectContaining({ reason: "invalid_claims" }),
    );
    expect(guard().assertFeature("sso").licensee).toBe("Acme Ltd");
  });

  it("reads a valued feature, and separates a withheld one from an absent one", () => {
    const g = guard({ features: { sso: true, seats: 25, tier: "pro", beta: false } });
    expect(g.value("seats")).toBe(25);
    expect(g.value("tier")).toBe("pro");
    expect(g.value("sso")).toBe(true);
    expect(g.value("beta")).toBe(false); // withheld
    expect(g.value("billing")).toBeNull(); // never mentioned
    expect(g.hasFeature("sso")).toBe(true);
    expect(g.hasFeature("beta")).toBe(false);
    expect(() => g.assertFeature("beta")).toThrow(expect.objectContaining({ reason: "invalid_claims" }));
  });

  it("values an array feature at true, and says nothing about a license it rejects", () => {
    expect(guard().value("sso")).toBe(true);
    expect(guard().value("billing")).toBeNull();
    expect(guard({}, NOW + 40 * 86_400).value("sso")).toBeNull();
  });

  it("enforces numeric limits, and treats an unset limit as unlimited", () => {
    const g = guard({ limits: { seats: 10 } });
    expect(g.limit("seats")).toBe(10);
    expect(g.withinLimit("seats", 9)).toBe(true);
    expect(g.withinLimit("seats", 10)).toBe(false);
    expect(g.withinLimit("projects", 1_000_000)).toBe(true);
  });

  it("keeps answering inside a grace window, and admits it is on grace", () => {
    const g = new LicenseGuard({
      publicKey: keys.publicKey,
      token: issue(keys.privateKey, claims()),
      now: at(NOW + 31 * 86_400), // a day past expiresAt
      graceSeconds: 7 * 86_400,
    });
    expect(g.inGrace()).toBe(true);
    expect(g.hasFeature("sso")).toBe(true); // warn, do not block
    expect(g.withinLimit("seats", 9)).toBe(true);
    expect(guard().inGrace()).toBe(false);
  });

  it("reports every verdict it reaches to onCheck", () => {
    const seen: VerifyResult[] = [];
    const g = new LicenseGuard({
      publicKey: keys.publicKey,
      token: issue(keys.privateKey, claims()),
      now: at(NOW),
      onCheck: (result) => seen.push(result),
    });
    g.hasFeature("sso");
    g.assertFeature("sso");
    expect(seen).toEqual([
      { ok: true, claims: claims() },
      { ok: true, claims: claims() },
    ]);

    const rejected = new LicenseGuard({
      publicKey: keys.publicKey,
      token: issue(keys.privateKey, claims()),
      now: at(NOW + 40 * 86_400),
      onCheck: (result) => seen.push(result),
    });
    expect(rejected.hasFeature("sso")).toBe(false);
    expect(seen.at(-1)).toEqual({ ok: false, reason: "expired", claims: claims() });
  });

  it("cannot be made to reject a valid license by a listener that throws", () => {
    // An observer watches the check; it does not take part in it. A log whose
    // disk has filled up must not be able to lock a paying customer out.
    const g = new LicenseGuard({
      publicKey: keys.publicKey,
      token: issue(keys.privateKey, claims()),
      now: at(NOW),
      onCheck: () => {
        throw new Error("the admin log is on a full disk");
      },
    });
    expect(g.hasFeature("sso")).toBe(true);
    expect(g.check()).toEqual({ ok: true, claims: claims() });
  });

  it("fills a CheckLog an admin page can read", async () => {
    const store = new MemoryCheckLogStore();
    const log = new CheckLog({ store, now: at(NOW) });
    await log.load();
    new LicenseGuard({
      publicKey: keys.publicKey,
      token: issue(keys.privateKey, claims()),
      now: at(NOW),
      onCheck: log.record, // a property, so it needs no wrapper to keep its `this`
    }).hasFeature("sso");
    expect(log.lastVerifiedAt).toBe(NOW);
    expect(log.failures).toEqual([]);

    const machineBound = new LicenseGuard({
      publicKey: keys.publicKey,
      token: issue(keys.privateKey, claims({ machine: "not-this-box" })),
      now: at(NOW),
      onCheck: log.record,
    });
    machineBound.hasFeature("sso");
    machineBound.hasFeature("export");
    expect(log.failures).toEqual([
      { reason: "machine_mismatch", firstAt: NOW, at: NOW, count: 2, license: "lic_test_1" },
    ]);
    expect(log.lastVerifiedAt).toBe(NOW); // still what it was: a failure is not a verification
  });

  it("throws LicenseError instances, not plain errors", () => {
    try {
      guard({}, NOW + 40 * 86_400).assertFeature("sso");
    } catch (err) {
      expect(err).toBeInstanceOf(LicenseError);
    }
  });
});
