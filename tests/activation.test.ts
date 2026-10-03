import { describe, expect, it } from "vitest";
import { createPrivateKey, sign } from "node:crypto";
import {
  ActivationError,
  createActivationRequest,
  generateKeyPair,
  readActivationRequest,
  type MachineClaim,
} from "../src/index.js";
import { NOW } from "./helpers.js";

const FINGERPRINT = "7b2e-air-gapped-box";

const request = (over: Partial<Parameters<typeof createActivationRequest>[0]> = {}) =>
  createActivationRequest({ fingerprint: FINGERPRINT, requestedAt: NOW, ...over });

/**
 * Re-encode an edited claim under the signature the original came with.
 *
 * Keys are sorted the way the payload's were, so passing no edit reproduces the
 * token byte for byte — which the first test below asserts. Without that, every
 * rejection here could be the re-encoding rather than the edit.
 */
function reclaim(token: string, over: Partial<MachineClaim>): string {
  const [prefix, payload, signature] = token.split(".") as [string, string, string];
  const claim = JSON.parse(Buffer.from(payload, "base64url").toString("utf8")) as MachineClaim;
  const edited = { ...claim, ...over } as Record<string, unknown>;
  const sorted = Object.fromEntries(Object.keys(edited).sort().map((k) => [k, edited[k]]));
  return `${prefix}.${Buffer.from(JSON.stringify(sorted)).toString("base64url")}.${signature}`;
}

describe("the machine claim a product emits", () => {
  it("carries the fingerprint, the nonce and the labels the operator reads", () => {
    const claim = readActivationRequest(request({ licensee: "Acme Ltd", product: "acme-cad" }));

    expect(claim.fingerprint).toBe(FINGERPRINT);
    expect(claim.requestedAt).toBe(NOW);
    expect(claim.licensee).toBe("Acme Ltd");
    expect(claim.product).toBe("acme-cad");
    expect(claim.nonce).not.toBe("");
  });

  it("gives every request its own nonce, so two installs never ask the same thing", () => {
    const nonces = new Set([request(), request(), request()].map((r) => readActivationRequest(r).nonce));
    expect(nonces.size).toBe(3);
  });

  it("omits the labels it was not given rather than writing them empty", () => {
    const claim = readActivationRequest(request());
    expect("licensee" in claim).toBe(false);
    expect("product" in claim).toBe(false);
  });

  it("signs with a key the caller keeps, for an install the issuer can recognise again", () => {
    const install = generateKeyPair();
    const first = readActivationRequest(request({ signingKey: install.privateKey }));
    const second = readActivationRequest(request({ signingKey: install.privateKey, nonce: "n2" }));

    expect(second.key).toBe(first.key);
    expect(readActivationRequest(request()).key).not.toBe(first.key);
  });

  it("refuses a fingerprint the claim does not actually state", () => {
    expect(() => createActivationRequest({ fingerprint: "" })).toThrow(ActivationError);
  });
});

describe("a request that does not hold together", () => {
  const reason = (fn: () => unknown) => {
    try {
      fn();
    } catch (err) {
      return (err as ActivationError).reason;
    }
    return "accepted";
  };

  it("survives being taken apart and put back together unedited", () => {
    const original = request();
    expect(reclaim(original, {})).toBe(original);
  });

  it("is malformed when it is not three parts under the act1 prefix", () => {
    expect(reason(() => readActivationRequest("not-a-request"))).toBe("malformed");
    expect(reason(() => readActivationRequest(request().split(".").slice(0, 2).join(".")))).toBe("malformed");
    expect(reason(() => readActivationRequest(request().replace("act1.", "act2.")))).toBe("malformed");
  });

  it("is an invalid signature when the fingerprint was edited in transit", () => {
    // The whole point of signing the claim: an operator cannot sign a license
    // for a machine that never asked, because the edit no longer verifies.
    const edited = reclaim(request(), { fingerprint: "someone-elses-box" });
    expect(reason(() => readActivationRequest(edited))).toBe("invalid_signature");
  });

  it("is an invalid signature when the nonce was swapped for another request's", () => {
    const other = readActivationRequest(request());
    expect(reason(() => readActivationRequest(reclaim(request(), { nonce: other.nonce })))).toBe("invalid_signature");
  });

  it("is an invalid signature when the embedded key was replaced with one that signed nothing", () => {
    // Re-signing under a fresh key is the attack this never claimed to stop;
    // swapping only the key is the accident it does.
    const { publicKey } = generateKeyPair();
    const der = Buffer.from(publicKey.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
    const edited = reclaim(request(), { key: der.toString("base64url") });
    expect(reason(() => readActivationRequest(edited))).toBe("invalid_signature");
  });

  it("is invalid claims when the payload is signed but is not a machine claim", () => {
    const { privateKey, publicKey } = generateKeyPair();
    const der = Buffer.from(publicKey.replace(/-----[^-]+-----/g, "").replace(/\s+/g, ""), "base64");
    const payload = Buffer.from(JSON.stringify({ fingerprint: FINGERPRINT, key: der.toString("base64url") })).toString(
      "base64url",
    );
    const signature = sign(null, Buffer.from(`act1.${payload}`), createPrivateKey(privateKey));

    expect(reason(() => readActivationRequest(`act1.${payload}.${signature.toString("base64url")}`))).toBe(
      "invalid_claims",
    );
  });

  it("is invalid claims when the payload is not JSON at all", () => {
    expect(reason(() => readActivationRequest("act1.bm90LWpzb24.c2ln"))).toBe("invalid_claims");
  });
});
