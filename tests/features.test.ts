import { describe, expect, it } from "vitest";
import { ClaimsError, assertClaims, featureValue, hasFeature, issue, verify } from "../src/index.js";
import { at, claims, keys, NOW } from "./helpers.js";

const VALUED = { sso: true, seats: 25, tier: "pro", beta: false } as const;

describe("the two forms of features", () => {
  it("verifies a record of valued features, and hands it back as it was signed", () => {
    const valued = claims({ features: VALUED });
    expect(verify(keys.publicKey, issue(keys.privateKey, valued), { now: at(NOW) })).toEqual({
      ok: true,
      claims: valued,
    });
  });

  it("still verifies the array form, so a token issued before this existed is unaffected", () => {
    expect(verify(keys.publicKey, issue(keys.privateKey, claims()), { now: at(NOW) })).toEqual({
      ok: true,
      claims: claims(),
    });
  });

  it("refuses a features record holding anything but a boolean, a number or a string", () => {
    for (const features of [{ sso: null }, { sso: { nested: true } }, { sso: [1] }, "sso", 7] as never[]) {
      expect(() => assertClaims(claims({ features }))).toThrow(ClaimsError);
    }
    expect(() => assertClaims(claims({ features: { sso: true, seats: 0, tier: "" } }))).not.toThrow();
  });
});

describe("reading a feature out of either form", () => {
  it("gives an array entry the value true, because presence is all it says", () => {
    expect(featureValue(["export", "sso"], "sso")).toBe(true);
    expect(featureValue(["export", "sso"], "billing")).toBeNull();
    expect(hasFeature(["export", "sso"], "sso")).toBe(true);
    expect(hasFeature(["export", "sso"], "billing")).toBe(false);
  });

  it("gives a record entry the value the license signed", () => {
    expect(featureValue(VALUED, "seats")).toBe(25);
    expect(featureValue(VALUED, "tier")).toBe("pro");
    expect(featureValue(VALUED, "sso")).toBe(true);
    expect(featureValue(VALUED, "billing")).toBeNull();
  });

  it("treats an explicit false as the feature being withheld, and zero as a value", () => {
    expect(hasFeature(VALUED, "beta")).toBe(false);
    expect(featureValue(VALUED, "beta")).toBe(false); // withheld, not absent
    expect(hasFeature({ seats: 0, tier: "" }, "seats")).toBe(true);
    expect(featureValue({ seats: 0 }, "seats")).toBe(0);
  });
});
