/** What a valued feature carries: a switch, a count, or a short label. */
export type FeatureValue = boolean | number | string;

/**
 * Either form a license may state its entitlements in.
 *
 * The array came first and is still all most licenses need. The record is for
 * the entitlements that have a value and not only a presence — a tier name, a
 * per-feature count. `["export"]` means exactly `{ export: true }`, so a reader
 * that goes through featureValue never has to know which form it was handed.
 */
export type Features = readonly string[] | Readonly<Record<string, FeatureValue>>;

/** Everything a license asserts. Times are unix seconds. */
export interface LicenseClaims {
  /** Unique per license. Also the HMAC key for machine binding. */
  id: string;
  /** Who the license was issued to — shown in UIs, never trusted for auth. */
  licensee: string;
  /** Feature keys the licensee may use, or a record of them with values. */
  features: Features;
  /** Numeric caps, e.g. { seats: 25, projects: 100 }. */
  limits?: Readonly<Record<string, number>>;
  issuedAt: number;
  expiresAt?: number;
  notBefore?: number;
  /** Output of bindMachine(). Present only for machine-bound licenses. */
  machine?: string;
  /** Names the signing key, so a verifier holding a KeyRing knows which to try. */
  kid?: string;
  /** The nonce of the activation request this license answers. Set by fulfilActivation(). */
  activation?: string;
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
  optionalString(c, "activation");

  if (!isFeatures(c.features)) {
    throw new ClaimsError("features must be a string array, or a record of booleans, numbers and strings");
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

/**
 * The value a license attaches to a feature, or null when it names none.
 *
 * An array entry has no value of its own, so it reads as `true`: the array form
 * is the record form with every value a switch, and a product that never issues
 * a record sees exactly what it saw before.
 */
export function featureValue(features: Features, feature: string): FeatureValue | null {
  if (Array.isArray(features)) return features.includes(feature) ? true : null;
  return (features as Readonly<Record<string, FeatureValue>>)[feature] ?? null;
}

/**
 * Whether the license allows a feature at all.
 *
 * Only an explicit `false` withholds one — that is how an issuer turns a feature
 * off without changing the shape of the record it ships every customer, and
 * reading it as allowed would invert what the license says. A `0` or an empty
 * string is a value to read, not a switch: a feature valued zero is still a
 * feature the license names, and what zero means belongs to the product.
 */
export function hasFeature(features: Features, feature: string): boolean {
  const value = featureValue(features, feature);
  return value !== null && value !== false;
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
function isFeatures(value: unknown): boolean {
  if (Array.isArray(value)) return value.every((f) => typeof f === "string");
  return (
    !!value &&
    typeof value === "object" &&
    Object.values(value as object).every(
      (v) => typeof v === "boolean" || typeof v === "number" || typeof v === "string",
    )
  );
}

function isRecordOf(value: unknown, type: "number" | "string"): boolean {
  return (
    !!value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.values(value as object).every((v) => typeof v === type)
  );
}
