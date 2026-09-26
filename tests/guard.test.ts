import { describe, expect, it } from "vitest";
import { issue, LicenseError, LicenseGuard } from "../src/index.js";
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

  it("throws LicenseError instances, not plain errors", () => {
    try {
      guard({}, NOW + 40 * 86_400).assertFeature("sso");
    } catch (err) {
      expect(err).toBeInstanceOf(LicenseError);
    }
  });
});
