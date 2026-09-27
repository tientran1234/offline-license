import { sign } from "node:crypto";
import { assertClaims, type LicenseClaims } from "./claims.js";
import { TOKEN_PREFIX } from "./core.js";
import { canonicalJson, toBase64Url } from "./encoding.js";
import { toPrivateKey, type KeyInput } from "./keys.js";

/**
 * Sign claims into a token: `lic1.<payload>.<signature>`.
 *
 * The signature covers `lic1.<payload>` — prefix included — so a future format
 * cannot be downgraded to this one by editing the prefix.
 */
export function issue(privateKey: KeyInput, claims: LicenseClaims): string {
  assertClaims(claims);
  const key = toPrivateKey(privateKey);
  const payload = toBase64Url(canonicalJson(claims));
  const signed = `${TOKEN_PREFIX}.${payload}`;
  const signature = sign(null, Buffer.from(signed), key);
  return `${signed}.${toBase64Url(signature)}`;
}
