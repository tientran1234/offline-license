import { generateKeyPair, type LicenseClaims } from "../src/index.js";

export const keys = generateKeyPair();
export const otherKeys = generateKeyPair();

export const NOW = 1_800_000_000; // a fixed "now", unix seconds
export const at = (seconds: number) => () => seconds;

export function claims(over: Partial<LicenseClaims> = {}): LicenseClaims {
  return {
    id: "lic_test_1",
    licensee: "Acme Ltd",
    features: ["export", "sso"],
    limits: { seats: 10 },
    issuedAt: NOW - 3600,
    expiresAt: NOW + 30 * 86_400,
    ...over,
  };
}
