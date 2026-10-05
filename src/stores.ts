import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";

import type { CheckLogStore } from "./audit.js";
import type { LedgerStore } from "./ledger.js";

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
    await writeAtomic(this.path, String(seconds));
  }
}

/** For tests and processes that are not meant to remember. */
export class MemoryLedgerStore implements LedgerStore {
  private text: string | null = null;
  async read() {
    return this.text;
  }
  async write(text: string) {
    this.text = text;
  }
}

/**
 * A usage ledger in one file, replaced atomically by the same temp-then-rename
 * as the clock's mark.
 *
 * A ledger is read whole and verified link by link, so a half-written one is
 * not a slightly stale count — it is a broken chain, which the product is
 * supposed to treat as tampering. An interrupted write must therefore leave the
 * previous ledger, never a fragment of the new one.
 */
export class FileLedgerStore implements LedgerStore {
  constructor(private readonly path: string) {}

  async read(): Promise<string | null> {
    try {
      return await readFile(this.path, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  async write(text: string): Promise<void> {
    await writeAtomic(this.path, text);
  }
}

/** For tests and processes whose history is not meant to outlive them. */
export class MemoryCheckLogStore implements CheckLogStore {
  private text: string | null = null;
  async read() {
    return this.text;
  }
  async write(text: string) {
    this.text = text;
  }
}

/**
 * A check log in one file, replaced atomically by the same temp-then-rename as
 * the clock's mark and the ledger's entries.
 *
 * The atomicity buys less here, because a torn log is discarded rather than
 * read as tampering — but discarding is the whole loss. A write interrupted at
 * the wrong moment would leave the admin page with no history at all, on the
 * install whose history someone has just gone looking for.
 */
export class FileCheckLogStore implements CheckLogStore {
  constructor(private readonly path: string) {}

  async read(): Promise<string | null> {
    try {
      return await readFile(this.path, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return null;
      throw err;
    }
  }

  async write(text: string): Promise<void> {
    await writeAtomic(this.path, text);
  }
}

/** Write to a sibling temp file, then rename over the target. */
async function writeAtomic(path: string, text: string): Promise<void> {
  const dir = dirname(path);
  await mkdir(dir, { recursive: true });
  const tmp = join(dir, `.${randomBytes(6).toString("hex")}.tmp`);
  await writeFile(tmp, text, "utf8");
  await rename(tmp, path);
}
