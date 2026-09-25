import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

/** The only envelope version that exists. Bumped when this shape changes. */
export const LICENSE_FILE_VERSION = 1;

/**
 * What a license ships as on disk: the token, plus enough context for whoever
 * opens the file in an editor.
 *
 * Only `token` carries any authority — it is the signed part. `issuer` and
 * `notes` sit outside the signature and anybody holding the file can rewrite
 * them, so they are labels for people, never inputs to a check. Read the claims
 * for anything a decision depends on.
 */
export interface LicenseFile {
  /** Envelope format version. A reader refuses one it does not know. */
  version: number;
  /** The `lic1.…` token, exactly as issue() produced it. */
  token: string;
  /** Who issued the license — for the support desk, not for the verifier. */
  issuer?: string;
  /** Free text for whoever opens the file. */
  notes?: string;
}

/** A license file to write: the version is this library's to stamp, not the caller's. */
export type LicenseFileInput = Omit<LicenseFile, "version">;

/** A file that is not a license envelope this version understands. */
export class LicenseFileError extends Error {
  override readonly name = "LicenseFileError";
}

/**
 * Read an envelope and hand back what it holds.
 *
 * The token is not verified here: the envelope has no key, and "there is no
 * license installed" is a different problem from "this license has expired".
 * For the same reason filesystem errors are left to propagate — an ENOENT
 * means no file, which a caller tests for, while a LicenseFileError means the
 * file is there and unusable, which a caller reports.
 */
export async function readLicenseFile(path: string): Promise<LicenseFile> {
  const text = await readFile(path, "utf8");

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    throw new LicenseFileError(`${path}: not JSON (${(err as Error).message})`);
  }
  return assertEnvelope(parsed, path);
}

/**
 * Write an envelope, replacing any file already there.
 *
 * Atomically, by the same temp-file-then-rename as the clock store: a crash
 * halfway through a plain write leaves a truncated file, which parses as
 * nothing at all, and the product would then refuse to start for a customer
 * whose license was perfectly good.
 */
export async function writeLicenseFile(path: string, file: LicenseFileInput): Promise<void> {
  const envelope = assertEnvelope({ version: LICENSE_FILE_VERSION, ...prune(file) }, path);

  const dir = dirname(path);
  await mkdir(dir, { recursive: true });
  const tmp = join(dir, `.${randomBytes(6).toString("hex")}.tmp`);
  await writeFile(tmp, format(envelope), "utf8");
  await rename(tmp, path);
}

/** Fields in a fixed order, indented, so a license file under review diffs line by line. */
function format(envelope: LicenseFile): string {
  const ordered: Record<string, unknown> = { version: envelope.version, token: envelope.token };
  if (envelope.issuer !== undefined) ordered.issuer = envelope.issuer;
  if (envelope.notes !== undefined) ordered.notes = envelope.notes;
  return `${JSON.stringify(ordered, null, 2)}\n`;
}

/** Drop absent optionals, so `{ issuer: undefined }` writes no issuer rather than a null. */
function prune(file: LicenseFileInput): LicenseFileInput {
  return Object.fromEntries(Object.entries(file).filter(([, v]) => v !== undefined)) as LicenseFileInput;
}

const KNOWN_FIELDS = ["version", "token", "issuer", "notes"];

/** Shape check for an envelope from disk — or from a JavaScript caller, who is equally unchecked. */
function assertEnvelope(value: unknown, path: string): LicenseFile {
  const where = (message: string) => new LicenseFileError(`${path}: ${message}`);
  if (!value || typeof value !== "object" || Array.isArray(value)) throw where("expected a JSON object");
  const e = value as Record<string, unknown>;

  if (e.version !== LICENSE_FILE_VERSION) {
    // Version is the whole point of the envelope: a file from a later release
    // is refused outright rather than read as if its fields still meant this.
    throw where(`unsupported envelope version ${JSON.stringify(e.version)}, expected ${LICENSE_FILE_VERSION}`);
  }
  // Within a version the shape is closed. An unknown field is a typo — `note`
  // for `notes` — and ignoring it would erase it on the next write.
  const stray = Object.keys(e).filter((k) => !KNOWN_FIELDS.includes(k));
  if (stray.length > 0) throw where(`unknown field${stray.length > 1 ? "s" : ""}: ${stray.join(", ")}`);

  if (typeof e.token !== "string" || e.token === "") throw where("token must be a non-empty string");
  for (const key of ["issuer", "notes"] as const) {
    if (e[key] !== undefined && (typeof e[key] !== "string" || e[key] === "")) {
      throw where(`${key} must be a non-empty string when present`);
    }
  }

  const envelope: LicenseFile = { version: LICENSE_FILE_VERSION, token: e.token };
  if (e.issuer !== undefined) envelope.issuer = e.issuer as string;
  if (e.notes !== undefined) envelope.notes = e.notes as string;
  return envelope;
}
