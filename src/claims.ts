/** Everything a license asserts. Times are unix seconds. */
export interface LicenseClaims {
  /** Unique per license. Also the HMAC key for machine binding. */
  id: string;
  /** Who the license was issued to — shown in UIs, never trusted for auth. */
  licensee: string;
  /** Feature keys the licensee may use. */
  features: readonly string[];
  /** Numeric caps, e.g. { seats: 25, projects: 100 }. */
  limits?: Readonly<Record<string, number>>;
  issuedAt: number;
  expiresAt?: number;
  notBefore?: number;
  /** Output of bindMachine(). Present only for machine-bound licenses. */
  machine?: string;
  /** Names the signing key, so a verifier holding a KeyRing knows which to try. */
  kid?: string;
  metadata?: Readonly<Record<string, string>>;
}

export class ClaimsError extends Error {
  override readonly name = "ClaimsError";
}

/** Runtime shape check for a decoded payload — never trust the wire. */
export function assertClaims(value: unknown): asserts value is LicenseClaims {
  if (!value || typeof value !== "object") throw new ClaimsError("claims must be an object");
  const c = value as Record<string, unknown>;

  requireString(c, "id");
  requireString(c, "licensee");
  requireNumber(c, "issuedAt");
  optionalNumber(c, "expiresAt");
  optionalNumber(c, "notBefore");
  optionalString(c, "machine");
  optionalString(c, "kid");

  if (!Array.isArray(c.features) || !c.features.every((f) => typeof f === "string")) {
    throw new ClaimsError("features must be a string array");
  }
  if (c.limits !== undefined) {
    if (!isRecordOf(c.limits, "number")) throw new ClaimsError("limits must map to numbers");
  }
  if (c.metadata !== undefined) {
    if (!isRecordOf(c.metadata, "string")) throw new ClaimsError("metadata must map to strings");
  }
  const expiresAt = c.expiresAt;
  const notBefore = c.notBefore;
  if (typeof expiresAt === "number" && typeof notBefore === "number" && expiresAt < notBefore) {
    throw new ClaimsError("expiresAt is before notBefore");
  }
}

function requireString(c: Record<string, unknown>, key: string) {
  if (typeof c[key] !== "string" || c[key] === "") throw new ClaimsError(`${key} must be a non-empty string`);
}
function requireNumber(c: Record<string, unknown>, key: string) {
  if (typeof c[key] !== "number" || !Number.isFinite(c[key])) throw new ClaimsError(`${key} must be a number`);
}
function optionalNumber(c: Record<string, unknown>, key: string) {
  if (c[key] !== undefined) requireNumber(c, key);
}
function optionalString(c: Record<string, unknown>, key: string) {
  if (c[key] !== undefined) requireString(c, key);
}
function isRecordOf(value: unknown, type: "number" | "string"): boolean {
  return (
    !!value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.values(value as object).every((v) => typeof v === type)
  );
}
