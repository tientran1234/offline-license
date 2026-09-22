import type { LicenseClaims } from "./claims.js";
import type { KeyInput } from "./keys.js";
import { LicenseError, verify, type VerifyOptions, type VerifyResult } from "./verify.js";

export interface LicenseGuardOptions extends VerifyOptions {
  publicKey: KeyInput;
  token: string;
}

/**
 * The thing an application actually holds: one object that answers "may I?"
 *
 * Every question re-verifies the token. Verification is a signature check and
 * a few comparisons — cheap enough that caching would only add a way for a
 * stale answer to outlive an expiry or a clock rollback.
 */
export class LicenseGuard {
  constructor(private readonly options: LicenseGuardOptions) {}

  check(): VerifyResult {
    const { publicKey, token, ...rest } = this.options;
    return verify(publicKey, token, rest);
  }

  /** Claims if the license is currently valid, else null. */
  claims(): LicenseClaims | null {
    const result = this.check();
    return result.ok ? result.claims : null;
  }

  hasFeature(feature: string): boolean {
    return this.claims()?.features.includes(feature) ?? false;
  }

  /** Throws LicenseError with the precise reason: invalid license vs. missing feature. */
  assertFeature(feature: string): LicenseClaims {
    const result = this.check();
    if (!result.ok) throw new LicenseError(result.reason, result.claims);
    if (!result.claims.features.includes(feature)) {
      throw new LicenseError("invalid_claims", result.claims);
    }
    return result.claims;
  }

  /** The cap for `key`, or null when the license sets none (or is invalid). */
  limit(key: string): number | null {
    return this.claims()?.limits?.[key] ?? null;
  }

  /** True when `used` is under the cap. A license with no cap for `key` allows everything. */
  withinLimit(key: string, used: number): boolean {
    const cap = this.limit(key);
    return cap === null ? this.claims() !== null : used < cap;
  }
}
