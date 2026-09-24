#!/usr/bin/env node
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseArgs } from "node:util";
import type { LicenseClaims } from "./claims.js";
import { issue } from "./issue.js";
import { generateKeyPair, type PublicKeyInput } from "./keys.js";
import { bindMachine, defaultFingerprint } from "./machine.js";
import { verify, type VerifyOptions } from "./verify.js";

/**
 * Exit codes are this CLI's real contract: a release script runs `verify` and
 * branches on the status, so "the license is rejected" and "you called me
 * wrong" must never collapse into the same non-zero code.
 */
const OK = 0;
const REJECTED = 1;
const MISUSE = 2;

/** Anything the operator can fix by typing a different command line. */
class UsageError extends Error {
  override readonly name = "UsageError";
}

/** Injected so the entry point owns the process and `run` owns the logic. */
export interface CliIo {
  out(text: string): void;
  err(text: string): void;
  stdin(): Promise<string>;
}

const HELP = {
  root: `offline-license — issue and check offline licenses (Ed25519)

  keygen   [--out <dir>]
  issue    --key <private.pem> --id <id> --licensee <name> [options]
  verify   --key <public.pem> [--token <token> | --token-file <file>]

Exit codes: 0 done / valid, 1 license rejected, 2 bad usage.
Run \`offline-license <command> --help\` for one command's options.
`,
  keygen: `offline-license keygen [--out <dir>]

  --out <dir>   Write private.pem (mode 0600) and public.pem there and print
                the paths. Without it, both PEMs go to stdout as JSON.
`,
  issue: `offline-license issue --key <private.pem> --id <id> --licensee <name> [options]

  --key <file>        PKCS#8 PEM of the issuing private key.
  --id <id>           Unique license id. Also keys the machine binding.
  --licensee <name>   Who it is issued to.
  --feature <name>    Repeatable.
  --limit <key=n>     Repeatable numeric cap, e.g. --limit seats=25.
  --meta <key=value>  Repeatable string metadata.
  --expires-in <dur>  Duration from issuedAt: 365d, 24h, 30m, 900s.
  --expires-at <t>    Unix seconds or an ISO 8601 date. Excludes --expires-in.
  --not-before <t>    Unix seconds or an ISO 8601 date.
  --kid <name>        Name the signing key, so a verifier holding several
                      knows which one to check against.
  --machine <fp>      Bind to the machine with this fingerprint.
  --this-machine      Bind to this machine's defaultFingerprint().
  --now <t>           Override issuedAt. For reproducible tokens.
  --out <file>        Write the token there instead of stdout.
`,
  verify: `offline-license verify --key <public.pem> [--token <token> | --token-file <file>]

  --key <file>        SPKI PEM of the public key. Reads the token from stdin
                      when neither --token nor --token-file is given.
  --key <kid>=<file>  Repeatable. Trust several keys during a rotation and let
                      the token's kid choose between them. Given more than one,
                      every key must be named; a kid naming none is rejected.
  --machine <fp>      Fingerprint to check a machine-bound license against.
  --this-machine      Use this machine's defaultFingerprint().
  --skew <seconds>    Slack on notBefore and expiresAt. Default: 60.
  --now <t>           Unix seconds or an ISO 8601 date. Overrides the clock.
  --json              Print the whole VerifyResult. The exit code is unchanged.

Clock-rollback detection is deliberately absent: the high-water mark only means
something across a process's lifetime, so it belongs to MonotonicClock in a
long-lived product, not to a command that exits.
`,
};

export async function run(argv: readonly string[], io: CliIo): Promise<number> {
  const [command, ...rest] = argv;
  try {
    switch (command) {
      case "keygen":
        return await keygen(rest, io);
      case "issue":
        return await issueCommand(rest, io);
      case "verify":
        return await verifyCommand(rest, io);
      case "help":
      case "--help":
      case "-h":
        io.out(HELP.root);
        return OK;
      case undefined:
        io.err(HELP.root);
        return MISUSE;
      default:
        io.err(`unknown command: ${command}\n\n${HELP.root}`);
        return MISUSE;
    }
  } catch (err) {
    // parseArgs reports an unknown or malformed flag by throwing; that is the
    // same class of mistake as our own UsageError, not a crash.
    const code = (err as NodeJS.ErrnoException).code ?? "";
    if (err instanceof UsageError || code.startsWith("ERR_PARSE_ARGS_")) {
      io.err(`${(err as Error).message}\n`);
      return MISUSE;
    }
    throw err;
  }
}

async function keygen(argv: readonly string[], io: CliIo): Promise<number> {
  const { values } = parseArgs({
    args: [...argv],
    options: { out: { type: "string" }, help: { type: "boolean", short: "h" } },
  });
  if (values.help) {
    io.out(HELP.keygen);
    return OK;
  }

  const pair = generateKeyPair();
  if (values.out === undefined) {
    io.out(`${JSON.stringify(pair, null, 2)}\n`);
    return OK;
  }

  await mkdir(values.out, { recursive: true });
  const privatePath = join(values.out, "private.pem");
  const publicPath = join(values.out, "public.pem");
  await writeFile(privatePath, pair.privateKey, { encoding: "utf8", mode: 0o600 });
  await writeFile(publicPath, pair.publicKey, "utf8");
  // writeFile's mode applies only when it creates the file. Overwriting an
  // existing, laxer one would otherwise leave the private key readable.
  await chmod(privatePath, 0o600);

  io.out(`${privatePath}\n${publicPath}\n`);
  return OK;
}

async function issueCommand(argv: readonly string[], io: CliIo): Promise<number> {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      key: { type: "string" },
      id: { type: "string" },
      licensee: { type: "string" },
      feature: { type: "string", multiple: true },
      limit: { type: "string", multiple: true },
      meta: { type: "string", multiple: true },
      "expires-in": { type: "string" },
      "expires-at": { type: "string" },
      "not-before": { type: "string" },
      kid: { type: "string" },
      machine: { type: "string" },
      "this-machine": { type: "boolean" },
      now: { type: "string" },
      out: { type: "string" },
      help: { type: "boolean", short: "h" },
    },
  });
  if (values.help) {
    io.out(HELP.issue);
    return OK;
  }

  const id = required(values.id, "--id");
  const issuedAt = values.now === undefined ? nowSeconds() : asTime(values.now, "--now");
  const claims: LicenseClaims = {
    id,
    licensee: required(values.licensee, "--licensee"),
    features: values.feature ?? [],
    issuedAt,
  };

  const limits = pairs(values.limit, "--limit", asNumber);
  if (Object.keys(limits).length > 0) claims.limits = limits;
  const metadata = pairs(values.meta, "--meta", (text) => text);
  if (Object.keys(metadata).length > 0) claims.metadata = metadata;

  if (values["expires-at"] !== undefined && values["expires-in"] !== undefined) {
    throw new UsageError("--expires-at and --expires-in are mutually exclusive");
  }
  if (values["expires-at"] !== undefined) {
    claims.expiresAt = asTime(values["expires-at"], "--expires-at");
  } else if (values["expires-in"] !== undefined) {
    claims.expiresAt = issuedAt + asDuration(values["expires-in"], "--expires-in");
  }
  if (values["not-before"] !== undefined) {
    claims.notBefore = asTime(values["not-before"], "--not-before");
  }

  if (values.kid !== undefined) claims.kid = values.kid;

  const fingerprint = machineFingerprint(values.machine, values["this-machine"]);
  if (fingerprint !== undefined) claims.machine = bindMachine(id, fingerprint);

  const privateKey = await readText(required(values.key, "--key"), "--key");
  let token: string;
  try {
    token = issue(privateKey, claims);
  } catch (err) {
    // A rejected key or a claim combination the library refuses to sign is bad
    // input, not a failure — report it as such rather than dumping a stack.
    throw new UsageError((err as Error).message);
  }

  if (values.out === undefined) io.out(`${token}\n`);
  else await writeFile(values.out, `${token}\n`, "utf8");
  return OK;
}

async function verifyCommand(argv: readonly string[], io: CliIo): Promise<number> {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      key: { type: "string", multiple: true },
      token: { type: "string" },
      "token-file": { type: "string" },
      machine: { type: "string" },
      "this-machine": { type: "boolean" },
      skew: { type: "string" },
      now: { type: "string" },
      json: { type: "boolean" },
      help: { type: "boolean", short: "h" },
    },
  });
  if (values.help) {
    io.out(HELP.verify);
    return OK;
  }

  const publicKey = await readKeys(values.key);
  const token = (await readToken(values.token, values["token-file"], io)).trim();

  const options: VerifyOptions = {};
  if (values.now !== undefined) {
    const now = asTime(values.now, "--now");
    options.now = () => now;
  }
  if (values.skew !== undefined) options.skewSeconds = asNumber(values.skew, "--skew");
  const fingerprint = machineFingerprint(values.machine, values["this-machine"]);
  if (fingerprint !== undefined) options.machineFingerprint = fingerprint;

  let result;
  try {
    result = verify(publicKey, token, options);
  } catch (err) {
    throw new UsageError((err as Error).message);
  }

  if (values.json) {
    io.out(`${JSON.stringify(result, null, 2)}\n`);
  } else if (result.ok) {
    io.out(`valid: ${describe(result.claims)}${expiry(result.claims)}\n`);
  } else {
    // The library hands claims back on expiry so a UI can say *which* license;
    // the CLI passes that through for the same reason.
    const which = result.claims ? ` — ${describe(result.claims)}` : "";
    io.err(`invalid: ${result.reason}${which}\n`);
  }
  return result.ok ? OK : REJECTED;
}

const describe = (claims: LicenseClaims) => `${claims.licensee} (${claims.id})`;

const expiry = (claims: LicenseClaims) =>
  claims.expiresAt === undefined ? "" : `, expires ${new Date(claims.expiresAt * 1000).toISOString()}`;

/**
 * One --key is the whole key, exactly as before. Several make a ring, and then
 * each needs the name a token's kid selects it by — an unnamed key in a ring
 * could never be chosen.
 */
async function readKeys(entries: readonly string[] | undefined): Promise<PublicKeyInput> {
  const list = entries ?? [];
  const only = list.length === 1 ? list[0] : undefined;
  if (list.length === 0 || (only !== undefined && only.indexOf("=") <= 0)) {
    return readText(required(only, "--key"), "--key");
  }

  const ring: Record<string, string> = {};
  for (const entry of list) {
    const eq = entry.indexOf("=");
    if (eq <= 0) throw new UsageError(`--key expects <kid>=<file> when several keys are given, got ${entry}`);
    ring[entry.slice(0, eq)] = await readText(entry.slice(eq + 1), "--key");
  }
  return ring;
}

async function readToken(token: string | undefined, file: string | undefined, io: CliIo): Promise<string> {
  if (token !== undefined && file !== undefined) {
    throw new UsageError("--token and --token-file are mutually exclusive");
  }
  if (token !== undefined) return token;
  if (file !== undefined) return readText(file, "--token-file");
  return io.stdin();
}

function machineFingerprint(explicit: string | undefined, thisMachine: boolean | undefined): string | undefined {
  if (explicit !== undefined && thisMachine === true) {
    throw new UsageError("--machine and --this-machine are mutually exclusive");
  }
  return thisMachine === true ? defaultFingerprint() : explicit;
}

function required(value: string | undefined, flag: string): string {
  if (value === undefined || value === "") throw new UsageError(`${flag} is required`);
  return value;
}

async function readText(path: string, flag: string): Promise<string> {
  try {
    return await readFile(path, "utf8");
  } catch (err) {
    throw new UsageError(`${flag}: ${(err as Error).message}`);
  }
}

function pairs<T>(
  entries: readonly string[] | undefined,
  flag: string,
  parseValue: (text: string, flag: string) => T,
): Record<string, T> {
  const out: Record<string, T> = {};
  for (const entry of entries ?? []) {
    const eq = entry.indexOf("=");
    if (eq <= 0) throw new UsageError(`${flag} expects key=value, got ${entry}`);
    out[entry.slice(0, eq)] = parseValue(entry.slice(eq + 1), flag);
  }
  return out;
}

function asNumber(text: string, flag: string): number {
  const n = Number(text);
  if (text.trim() === "" || !Number.isFinite(n)) throw new UsageError(`${flag} expects a number, got ${text}`);
  return n;
}

/** Unix seconds or an ISO 8601 date — whichever the operator has to hand. */
function asTime(text: string, flag: string): number {
  if (/^\d+$/.test(text)) return Number(text);
  const ms = Date.parse(text);
  if (Number.isNaN(ms)) throw new UsageError(`${flag} expects unix seconds or an ISO 8601 date, got ${text}`);
  return Math.floor(ms / 1000);
}

const UNIT_SECONDS = { s: 1, m: 60, h: 3600, d: 86_400 } as const;

/**
 * The unit is required. A bare `365` next to `--expires-in` reads as a year to
 * everyone and means five minutes to the machine, so it is a usage error.
 */
function asDuration(text: string, flag: string): number {
  const match = /^(\d+)([smhd])$/.exec(text);
  if (!match) throw new UsageError(`${flag} expects a duration like 365d, 24h, 30m or 900s, got ${text}`);
  return Number(match[1]) * UNIT_SECONDS[match[2] as keyof typeof UNIT_SECONDS];
}

const nowSeconds = () => Math.floor(Date.now() / 1000);

async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) throw new UsageError("no token: pass --token, --token-file, or pipe one in");
  let text = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) text += chunk;
  return text;
}

// Setting exitCode rather than calling process.exit() lets stdout drain first;
// process.exit() truncates a piped token on some platforms.
process.exitCode = await run(process.argv.slice(2), {
  out: (text) => void process.stdout.write(text),
  err: (text) => void process.stderr.write(text),
  stdin: readStdin,
});
