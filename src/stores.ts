import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

/** Where the monotonic clock keeps its high-water mark between runs. */
export interface ClockStore {
  read(): Promise<number | null>;
  write(seconds: number): Promise<void>;
}

/** For tests and short-lived processes. */
export class MemoryStore implements ClockStore {
  private value: number | null = null;
  async read() {
    return this.value;
  }
  async write(seconds: number) {
    this.value = seconds;
  }
}

/**
 * A single file, replaced atomically: write to a sibling temp file, then
 * rename over the original. A crash mid-write leaves the old value intact
 * rather than a half-written one that parses as 0 — which would silently
 * disable rollback detection.
 */
export class FileStore implements ClockStore {
  constructor(private readonly path: string) {}

  async read(): Promise<number | null> {
    try {
      const text = await readFile(this.path, "utf8");
      const n = Number(text.trim());
      return Number.isFinite(n) ? n : null;
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  async write(seconds: number): Promise<void> {
    const dir = dirname(this.path);
    await mkdir(dir, { recursive: true });
    const tmp = join(dir, `.${randomBytes(6).toString("hex")}.tmp`);
    await writeFile(tmp, String(seconds), "utf8");
    await rename(tmp, this.path);
  }
}
