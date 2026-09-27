import { describe, expect, it } from "vitest";
import { verify } from "../src/index.js";
import { vectors } from "./vectors.js";

describe("the shared vectors, on Node", () => {
  for (const vector of vectors) {
    it(vector.name, () => {
      expect(verify(vector.publicKey, vector.token, vector.options)).toEqual(vector.expected);
    });
  }
});
