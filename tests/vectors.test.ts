import { describe, expect, it } from "vitest";
import { createPrivateKey, createPublicKey } from "node:crypto";
import { readFileSync } from "node:fs";
import { bindMachine, TOKEN_PREFIX, verify } from "../src/index.js";
import { VERIFY_FAILURES } from "../src/core.js";
import { buildVectorFile, serializeVectorFile, writeVectorFile } from "./build-vectors.js";
import { fixtureKeys, keyFile, readFixture, vectorFile, vectors } from "./vectors.js";

describe("the shared vectors, on Node", () => {
  for (const vector of vectors) {
    it(vector.name, () => {
      expect(verify(vector.publicKey, vector.token, vector.options)).toEqual(vector.expected);
    });
  }
});

/**
 * The set is published for implementations that cannot run any of this — a
 * verifier in Go, Rust or Python proving it agrees with ours. So these are
 * checks on the files themselves: that the bytes are current, that they ship,
 * and that everything a reader needs to reproduce them is in there with them.
 */
describe("the published fixture set", () => {
  it("holds the tokens this release signs, to the byte", () => {
    // `pnpm vectors` runs this file with the write enabled, so regenerating is
    // the same command that checks. Ed25519 is deterministic and payloads are
    // canonical JSON, so an unchanged release regenerates byte-for-byte; a diff
    // here means the issuer moved and the published set has to be re-cut.
    if (process.env.UPDATE_VECTORS === "1") writeVectorFile();
    expect(vectorFile.vectors.length, "vectors/vectors.json is missing — run `pnpm vectors`").toBeGreaterThan(0);
    expect(readFixture("vectors.json"), "run `pnpm vectors` to re-cut the set").toBe(
      serializeVectorFile(buildVectorFile()),
    );
  });

  it("ships in the package, or nothing outside this repository can run it", () => {
    const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as {
      files: string[];
    };
    expect(manifest.files).toContain("vectors");
  });

  it("states each public key in raw form as well as PEM, and a private half that matches", () => {
    for (const [name, pair] of Object.entries(fixtureKeys)) {
      // An implementation whose library wants the 32 bytes rather than SPKI
      // takes publicKeyRaw on trust; one that signs takes privateKey the same
      // way. Either being the wrong key reads as our tokens being wrong.
      const spki = createPublicKey(pair.publicKey).export({ type: "spki", format: "der" });
      expect(spki.subarray(12).toString("base64url"), `${name}.publicKeyRaw`).toBe(pair.publicKeyRaw);
      expect(
        createPublicKey(createPrivateKey(pair.privateKey)).export({ type: "spki", format: "pem" }).toString(),
        `${name}.privateKey`,
      ).toBe(pair.publicKey);
    }
  });

  it("publishes the fingerprint the bound vectors are bound to", () => {
    // Machine binding is an HMAC the verifier recomputes from a fingerprint it
    // has locally. A set that did not say which fingerprint went in would leave
    // every bound vector unreproducible.
    const bound = vectors.flatMap((vector) => {
      const claims = vector.expected.claims;
      return claims?.machine === undefined ? [] : [{ name: vector.name, claims }];
    });
    expect(bound.length).toBeGreaterThan(0);
    for (const { name, claims } of bound) {
      expect(claims.machine, name).toBe(bindMachine(claims.id, vectorFile.fingerprint));
    }
  });

  it("carries a vector for every failure a token can produce", () => {
    const covered = vectors.flatMap((vector) => (vector.expected.ok ? [] : [vector.expected.reason]));
    // clock_rollback is the one reason that is not a property of a token: it
    // comes from a high-water mark on the machine doing the checking, so there
    // is nothing to put in a file. Every other reason has to be reachable here,
    // or an implementation can pass the whole set without having implemented it.
    const fromTokens = VERIFY_FAILURES.filter((reason) => reason !== "clock_rollback");
    expect([...new Set(covered)].sort()).toEqual([...fromTokens].sort());
  });

  it("declares the token format the vectors are in", () => {
    expect(vectorFile.tokenPrefix).toBe(TOKEN_PREFIX);
    expect(vectorFile.version).toBe(1);
    expect(keyFile.version).toBe(1);
  });
});
