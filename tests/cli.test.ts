import { execFile } from "node:child_process";
import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, it } from "vitest";
import { verify } from "../src/index.js";

const root = fileURLToPath(new URL("..", import.meta.url));
const CLI = join(root, "dist", "cli.js");
const TSC = join(root, "node_modules", "typescript", "bin", "tsc");

interface Run {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Spawn the built CLI the way a shell would. Nothing is imported from it: the
 * exit code and the streams *are* the contract, and only a real process has
 * them.
 */
function cli(args: readonly string[], stdin = ""): Promise<Run> {
  return new Promise((resolve, reject) => {
    const child = execFile(process.execPath, [CLI, ...args], { cwd: root }, (err, stdout, stderr) => {
      // A non-zero exit arrives as an error with a numeric code; anything else
      // (the binary missing, say) is a real failure and must not read as one.
      if (err && typeof err.code !== "number") return reject(err);
      resolve({ code: typeof err?.code === "number" ? err.code : 0, stdout, stderr });
    });
    child.stdin?.end(stdin);
  });
}

let keys: { dir: string; private: string; public: string };

beforeAll(async () => {
  // These tests run the compiled binary, so compile it here rather than trust
  // whatever an earlier build left in dist/.
  await new Promise<void>((resolve, reject) => {
    execFile(process.execPath, [TSC, "-p", "tsconfig.build.json"], { cwd: root }, (err, stdout) =>
      err ? reject(new Error(`build failed: ${stdout}`)) : resolve(),
    );
  });

  const dir = await mkdtemp(join(tmpdir(), "offline-license-cli-"));
  const result = await cli(["keygen", "--out", dir]);
  expect(result.code).toBe(0);
  keys = { dir, private: join(dir, "private.pem"), public: join(dir, "public.pem") };
}, 120_000);

const issueArgs = () => ["issue", "--key", keys.private, "--id", "lic_cli", "--licensee", "Acme Ltd"];

const issued = async (...args: string[]) => {
  const result = await cli([...issueArgs(), ...args]);
  expect(result.stderr).toBe("");
  expect(result.code).toBe(0);
  return result.stdout.trim();
};

describe("keygen", () => {
  it("writes a usable pair, with the private key readable only by its owner", async () => {
    const mode = (await stat(keys.private)).mode & 0o777;
    expect(mode).toBe(0o600);
    expect(await readFile(keys.public, "utf8")).toMatch(/^-----BEGIN PUBLIC KEY-----/);

    const token = await issued();
    expect(verify(await readFile(keys.public, "utf8"), token).ok).toBe(true);
  });

  it("prints both PEMs as JSON when no --out is given, so it can be piped", async () => {
    const { code, stdout } = await cli(["keygen"]);
    expect(code).toBe(0);
    const pair = JSON.parse(stdout) as { privateKey: string; publicKey: string };
    expect(pair.privateKey).toMatch(/BEGIN PRIVATE KEY/);
    expect(pair.publicKey).toMatch(/BEGIN PUBLIC KEY/);
  });
});

describe("issue", () => {
  it("signs the claims it was given", async () => {
    const token = await issued("--feature", "export", "--feature", "sso", "--limit", "seats=25", "--meta", "plan=pro");
    const result = verify(await readFile(keys.public, "utf8"), token);
    expect(result).toMatchObject({
      ok: true,
      claims: { id: "lic_cli", licensee: "Acme Ltd", features: ["export", "sso"], limits: { seats: 25 }, metadata: { plan: "pro" } },
    });
  });

  it("turns --expires-in into an absolute expiry, and omits one when asked for neither", async () => {
    const dated = verify(await readFile(keys.public, "utf8"), await issued("--now", "1800000000", "--expires-in", "30d"));
    expect(dated.claims?.expiresAt).toBe(1_800_000_000 + 30 * 86_400);

    const perpetual = verify(await readFile(keys.public, "utf8"), await issued());
    expect(perpetual.claims?.expiresAt).toBeUndefined();
  });

  it("writes the token to --out instead of stdout", async () => {
    const path = join(keys.dir, "license.txt");
    const { stdout } = await cli([...issueArgs(), "--out", path]);
    expect(stdout).toBe("");
    expect((await readFile(path, "utf8")).trim()).toMatch(/^lic1\./);
  });
});

describe("verify", () => {
  it("accepts a token piped in, so `issue | verify` needs no temp file", async () => {
    const { code, stdout } = await cli(["verify", "--key", keys.public], `${await issued()}\n`);
    expect(code).toBe(0);
    expect(stdout).toContain("Acme Ltd (lic_cli)");
  });

  it("exits 1 and names the reason when the license is rejected", async () => {
    const token = await issued();
    const tampered = `${token.slice(0, -2)}${token.endsWith("aa") ? "bb" : "aa"}`;

    const bad = await cli(["verify", "--key", keys.public, "--token", tampered]);
    expect(bad.code).toBe(1);
    expect(bad.stderr).toContain("invalid_signature");

    const expired = await cli([
      "verify", "--key", keys.public, "--now", "2099-01-01T00:00:00Z",
      "--token", await issued("--expires-in", "30d"),
    ]);
    expect(expired.code).toBe(1);
    expect(expired.stderr).toContain("expired");
    // The library hands claims back on expiry so a UI can say which license.
    expect(expired.stderr).toContain("lic_cli");
  });

  it("exits 0 inside --grace and names the status, then 1 once the window closes", async () => {
    const token = await issued("--expires-at", "2030-01-01T00:00:00Z");
    const dayLate = ["verify", "--key", keys.public, "--token", token, "--now", "2030-01-02T00:00:00Z"];

    const grace = await cli([...dayLate, "--grace", String(7 * 86_400)]);
    expect(grace.code).toBe(0);
    expect(grace.stdout).toContain("expired_in_grace: Acme Ltd (lic_cli)");

    const past = await cli([...dayLate, "--grace", "3600"]);
    expect(past.code).toBe(1);
    expect(past.stderr).toContain("expired");
  });

  it("still exits 1 under --json — the machine-readable form reports the same verdict", async () => {
    const { code, stdout } = await cli(["verify", "--key", keys.public, "--token", "not-a-token", "--json"]);
    expect(code).toBe(1);
    expect(JSON.parse(stdout)).toEqual({ ok: false, reason: "malformed" });
  });

  it("picks a key out of several by the token's kid, and drops one to retire it", async () => {
    // A rotation, from the shell: issue under each key, trust both, then trust
    // only the new one and watch the old license stop verifying.
    const second = await mkdtemp(join(tmpdir(), "offline-license-cli-"));
    expect((await cli(["keygen", "--out", second])).code).toBe(0);
    const ring = [`--key`, `old=${keys.public}`, `--key`, `new=${join(second, "public.pem")}`];

    const oldToken = await issued("--kid", "old");
    const underNewKey = await cli([
      "issue", "--key", join(second, "private.pem"), "--id", "lic_cli", "--licensee", "Acme Ltd", "--kid", "new",
    ]);
    expect(underNewKey.code).toBe(0);
    const newToken = underNewKey.stdout.trim();

    expect((await cli(["verify", ...ring, "--token", oldToken])).code).toBe(0);
    expect((await cli(["verify", ...ring, "--token", newToken])).code).toBe(0);

    const retired = await cli(["verify", "--key", `new=${join(second, "public.pem")}`, "--token", oldToken]);
    expect(retired.code).toBe(1);
    expect(retired.stderr).toContain("invalid_signature");
  });

  it("checks a machine binding, and refuses the same token without one", async () => {
    const token = await issued("--this-machine");

    const bound = await cli(["verify", "--key", keys.public, "--token", token, "--this-machine"]);
    expect(bound.code).toBe(0);

    const elsewhere = await cli(["verify", "--key", keys.public, "--token", token]);
    expect(elsewhere.code).toBe(1);
    expect(elsewhere.stderr).toContain("machine_mismatch");
  });
});

describe("usage errors exit 2, never 1", () => {
  // Each case names a fragment of its own message: exiting 2 for some other
  // reason (an unreadable key, say) would otherwise pass for the wrong one.
  it.each([
    ["no command at all", () => [], "keygen"],
    ["an unknown command", () => ["bogus"], "unknown command"],
    ["an unknown flag", () => ["verify", "--key", keys.public, "--nope"], "Unknown option"],
    ["a missing required flag", () => ["issue", "--id", "x", "--licensee", "y"], "--key is required"],
    ["an unreadable key", () => ["verify", "--key", "/nonexistent.pem", "--token", "lic1.a.b"], "ENOENT"],
    ["a malformed --limit", () => [...issueArgs(), "--limit", "seats"], "--limit expects key=value"],
    ["a bare --expires-in", () => [...issueArgs(), "--expires-in", "365"], "expects a duration"],
    ["a nonsense --expires-at", () => [...issueArgs(), "--expires-at", "next tuesday"], "ISO 8601"],
    ["both expiry flags", () => [...issueArgs(), "--expires-in", "1d", "--expires-at", "1800000000"], "mutually exclusive"],
    ["contradictory machine flags", () => [...issueArgs(), "--machine", "fp", "--this-machine"], "mutually exclusive"],
    ["two ways to supply a token", () => ["verify", "--key", keys.public, "--token", "t", "--token-file", "f"], "mutually exclusive"],
    ["an unnamed key among several", () => ["verify", "--key", keys.public, "--key", `new=${keys.public}`, "--token", "t"], "<kid>=<file>"],
  ])("%s", async (_name, args, fragment) => {
    const { code, stderr } = await cli(args());
    expect(code).toBe(2);
    expect(stderr).toContain(fragment);
  });

  it("reports a key that is not an Ed25519 key rather than crashing", async () => {
    const path = join(keys.dir, "junk.pem");
    await writeFile(path, "-----BEGIN PUBLIC KEY-----\nnope\n-----END PUBLIC KEY-----\n");
    const { code, stderr } = await cli(["verify", "--key", path, "--token", "lic1.a.b"]);
    expect(code).toBe(2);
    expect(stderr).toContain("public key");
  });
});

describe("help", () => {
  it("exits 0 and lists the three commands", async () => {
    const { code, stdout } = await cli(["help"]);
    expect(code).toBe(0);
    for (const command of ["keygen", "issue", "verify"]) expect(stdout).toContain(command);
  });

  it("documents one command at a time", async () => {
    const { code, stdout } = await cli(["issue", "--help"]);
    expect(code).toBe(0);
    expect(stdout).toContain("--expires-in");
  });
});
