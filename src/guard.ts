import { reportCheck, type CheckListener } from "./audit.js";
import { featureValue, hasFeature, type FeatureValue, type LicenseClaims } from "./claims.js";
import type { PublicKeyInput } from "./keys.js";
import { LicenseError, type VerifyOptions, type VerifyResult } from "./core.js";
import { verify } from "./verify.js";

export interface LicenseGuardOptions extends VerifyOptions {
  publicKey: PublicKeyInput;
  token: string;
  /**
   * Told the verdict of every check this guard makes — `CheckLog.record` is
   * what most products hand over, so an admin page can say when the license
   * last verified and what went wrong before that.
   */
  onCheck?: CheckListener;
}

/**
 * The thing an application actually holds: one object that answers "may I?"
 *
 * Every question re-verifies the token. Verification is a signature check and
 * a few comparisons — cheap enough that caching would only add a way for a
 * stale answer to outlive an expiry or a clock rollback.
 *
 * Which is also why `onCheck` fires more often than a product asks questions:
 * it reports verifications, not questions, and one question may be more than
 * one verification. `CheckLog` is built for that.
 */
export class LicenseGuard {
  constructor(private readonly options: LicenseGuardOptions) {}

  check(): VerifyResult {
    const { publicKey, token, onCheck, ...rest } = this.options;
    const result = verify(publicKey, token, rest);
    // After the verdict, and unable to change it: an observer watches a check,
    // it does not take part in one. See reportCheck.
    reportCheck(onCheck, result);
    return result;
  }

  /** Claims if the license is currently valid, else null. */
  claims(): LicenseClaims | null {
    const result = this.check();
    return result.ok ? result.claims : null;
  }

  /** True when the license is past expiresAt and alive only on grace — warn, do not block. */
  inGrace(): boolean {
    const result = this.check();
    return result.ok && result.status === "expired_in_grace";
  }

  hasFeature(feature: string): boolean {
    const claims = this.claims();
    return claims === null ? false : hasFeature(claims.features, feature);
  }

  /** Throws LicenseError with the precise reason: invalid license vs. missing feature. */
  assertFeature(feature: string): LicenseClaims {
    const result = this.check();
    if (!result.ok) throw new LicenseError(result.reason, result.claims);
    if (!hasFeature(result.claims.features, feature)) {
      throw new LicenseError("invalid_claims", result.claims);
    }
    return result.claims;
  }

  /**
   * What the license attaches to a feature — a tier name, a count, a switch —
   * or null when it names none (or the license is invalid).
   *
   * The union is not narrowed by a type parameter: the claims come off a token,
   * so a caller-supplied shape would be an assertion about the wire that nothing
   * verifies. Narrow it where you read it, next to the check that it is the kind
   * you expected.
   */
  value(feature: string): FeatureValue | null {
    const claims = this.claims();
    return claims === null ? null : featureValue(claims.features, feature);
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
