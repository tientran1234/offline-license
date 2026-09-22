import { createHash, createHmac } from "node:crypto";
import os from "node:os";

/**
 * Bind a license to one machine.
 *
 * The stored value is HMAC(fingerprint) keyed by the license id, not the raw
 * fingerprint: the token then reveals nothing about the machine, and the same
 * machine produces a different binding under every license, so one leaked
 * token cannot be matched against another.
 */
export function bindMachine(licenseId: string, fingerprint: string): string {
  return createHmac("sha256", licenseId).update(fingerprint).digest("base64url");
}

/**
 * A reasonable default fingerprint: stable across reboots on the same box,
 * changes on a different one. It is deliberately NOT a strong identity — it
 * exists to stop casual copying of a license file, not to resist someone who
 * edits the binary. Supply your own for anything stricter.
 */
export function defaultFingerprint(): string {
  const cpu = os.cpus()[0]?.model ?? "";
  const parts = [os.hostname(), os.platform(), os.arch(), cpu, String(os.totalmem())];
  return createHash("sha256").update(parts.join("|")).digest("hex");
}
