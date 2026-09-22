import { describe, expect, it } from "vitest";
import { assertClaims, ClaimsError, issue, verify, TOKEN_PREFIX } from "../src/index.js";
import { at, claims, keys, NOW } from "./helpers.js";

describe("issue → verify", () => {
  it("round-trips claims exactly", () => {
    const token = issue(keys.privateKey, claims());
    const result = verify(keys.publicKey, token, { now: at(NOW) });
    expect(result).toEqual({ ok: true, claims: claims() });
  });

  it("produces the documented shape: lic1.<payload>.<signature>", () => {
    const token = issue(keys.privateKey, claims());
    const parts = token.split(".");
    expect(parts).toHaveLength(3);
    expect(parts[0]).toBe(TOKEN_PREFIX);
    expect(token).not.toMatch(/[+/=]/); // base64url, no padding
  });

  it("is deterministic regardless of key order in the input", () => {
    const a = issue(keys.privateKey, claims());
    const shuffled = Object.fromEntries(Object.entries(claims()).reverse()) as ReturnType<typeof claims>;
    const b = issue(keys.privateKey, shuffled);
    expect(a).toBe(b);
  });

  it("refuses to issue nonsense rather than sign it", () => {
    expect(() => issue(keys.privateKey, claims({ features: ["a", 1 as never] }))).toThrow(ClaimsError);
    expect(() => issue(keys.privateKey, claims({ id: "" }))).toThrow(ClaimsError);
    expect(() => issue(keys.privateKey, claims({ expiresAt: NOW, notBefore: NOW + 1 }))).toThrow(ClaimsError);
  });

  it("rejects a public key where a private one is expected", () => {
    expect(() => issue(keys.publicKey, claims())).toThrow(/private key/);
  });

  it("assertClaims narrows unknown input", () => {
    const input: unknown = claims();
    assertClaims(input);
    expect(input.licensee).toBe("Acme Ltd");
    expect(() => assertClaims({ id: "x" })).toThrow(ClaimsError);
  });
});
