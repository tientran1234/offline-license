import { describe, expect, it } from "vitest";
import { createPrivateKey, sign } from "node:crypto";
import {
  ActivationError,
  answersRequest,
  assertClaims,
  ClaimsError,
  createActivationRequest,
  fulfilActivation,
  generateKeyPair,
  issue,
  readActivationRequest,
  verify,
  type MachineClaim,
} from "../src/index.js";
import { at, claims, keys, NOW } from "./helpers.js";

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

describe("the license that answers a request", () => {
  const licensed = (req: string) => fulfilActivation(keys.privateKey, req, claims());
  const check = (token: string, fingerprint: string) =>
    verify(keys.publicKey, token, { now: at(NOW), machineFingerprint: fingerprint });

  it("is bound to the machine that asked, and verifies nowhere else", () => {
    const token = licensed(request());

    expect(check(token, FINGERPRINT).ok).toBe(true);
    expect(check(token, "a-different-box")).toEqual({
      ok: false,
      reason: "machine_mismatch",
      claims: expect.objectContaining({ id: claims().id }),
    });
    // No fingerprint at all is the copied-license case, and fails the same way.
    expect(verify(keys.publicKey, token, { now: at(NOW) }).ok).toBe(false);
  });

  it("carries the nonce of the request it answers", () => {
    const req = request();
    const result = check(licensed(req), FINGERPRINT);

    expect(result.ok).toBe(true);
    expect(result.ok && result.claims.activation).toBe(readActivationRequest(req).nonce);
    expect(answersRequest(req, result.ok ? result.claims : claims())).toBe(true);
  });

  it("keeps everything else the issuer chose", () => {
    const token = fulfilActivation(keys.privateKey, request(), claims({ features: { sso: true, tier: "pro" } }));
    const result = check(token, FINGERPRINT);

    expect(result.ok && result.claims.features).toEqual({ sso: true, tier: "pro" });
    expect(result.ok && result.claims.limits).toEqual({ seats: 10 });
  });

  it("is not an answer to a request it was not issued for", () => {
    // Both requests name the same machine, so the binding alone cannot tell them
    // apart: the nonce is what stops the license meant for the earlier request —
    // shorter, or the one a renewal replaces — installing as the one just asked for.
    const first = request();
    const second = request();
    const token = licensed(first);
    const installed = verify(keys.publicKey, token, { now: at(NOW), machineFingerprint: FINGERPRINT });

    expect(installed.ok).toBe(true);
    expect(installed.ok && answersRequest(first, installed.claims)).toBe(true);
    expect(installed.ok && answersRequest(second, installed.claims)).toBe(false);
  });

  it("is not an answer when it is bound to another machine", () => {
    const req = request();
    const sameNonce = request({ nonce: readActivationRequest(req).nonce, fingerprint: "other-box" });
    const elsewhere = fulfilActivation(keys.privateKey, sameNonce, claims());
    const result = verify(keys.publicKey, elsewhere, { now: at(NOW), machineFingerprint: "other-box" });

    expect(result.ok).toBe(true);
    expect(result.ok && answersRequest(req, result.claims)).toBe(false);
  });

  it("is not an answer when it came from no request at all", () => {
    const plain = issue(keys.privateKey, claims());
    expect(answersRequest(request(), claims())).toBe(false);
    expect(verify(keys.publicKey, plain, { now: at(NOW) }).ok).toBe(true);
  });

  it("is refused outright when the request does not hold together", () => {
    const edited = reclaim(request(), { fingerprint: "someone-elses-box" });
    expect(() => fulfilActivation(keys.privateKey, edited, claims())).toThrow(ActivationError);
  });

  it("will not take a nonce that is not a string, whoever wrote it", () => {
    expect(() => assertClaims({ ...claims(), activation: 7 })).toThrow(ClaimsError);
  });
});
