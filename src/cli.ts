#!/usr/bin/env node
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseArgs } from "node:util";
import {
  createActivationRequest,
  fulfilActivation,
  readActivationRequest,
  type ActivationRequestInput,
  type MachineClaim,
} from "./activation.js";
import type { FeatureValue, Features, LicenseClaims } from "./claims.js";
import type { Predecessor, VerifyOptions } from "./core.js";
import { issue } from "./issue.js";
import { generateKeyPair, type PublicKeyInput } from "./keys.js";
import { bindMachine, defaultFingerprint } from "./machine.js";
import { verify } from "./verify.js";

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
  request  --this-machine | --machine <fingerprint> [options]
  fulfil   --key <private.pem> --id <id> [--request <request>] [options]

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
  --feature <name>    Repeatable. Written <name>=<value> it gives the feature a
                      value — a number, true/false, or a string — instead of
                      only naming it; one of those makes every --feature valued.
  --limit <key=n>     Repeatable numeric cap, e.g. --limit seats=25.
  --meta <key=value>  Repeatable string metadata.
  --expires-in <dur>  Duration from issuedAt: 365d, 24h, 30m, 900s.
  --expires-at <t>    Unix seconds or an ISO 8601 date. Excludes --expires-in.
  --not-before <t>    Unix seconds or an ISO 8601 date.
  --kid <name>        Name the signing key, so a verifier holding several
                      knows which one to check against.
  --renews <id>       Issue this as the renewal of that license, so an install
                      holding it accepts this one and one holding an earlier
                      generation does not.
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
  --grace <seconds>   Keep accepting the license this long past expiresAt,
                      printing expired_in_grace and still exiting 0, so a
                      product can warn about a late renewal. Default: 0.
  --previous <token>  The license being replaced, when what is offered is a
                      renewal. One naming a different license is rejected as
                      renewal_gap, and one whose term has not begun is accepted
                      while this license is inside --grace.
  --previous-file <f> Read that token from a file.
  --now <t>           Unix seconds or an ISO 8601 date. Overrides the clock.
  --json              Print the whole VerifyResult. The exit code is unchanged.

Clock-rollback detection is deliberately absent: the high-water mark only means
something across a process's lifetime, so it belongs to MonotonicClock in a
long-lived product, not to a command that exits.
`,
  request: `offline-license request --this-machine | --machine <fingerprint> [options]

  --this-machine      Ask for a license for this box's defaultFingerprint().
  --machine <fp>      Ask for one for the fingerprint given instead.
  --licensee <name>   Who is asking. A label the issuer's operator reads.
  --product <name>    Which product, for an issuer that signs for several.
  --signing-key <f>   PKCS#8 PEM to sign the request with, for an install that
                      keeps one key across requests. Without it a key is
                      generated for this request and thrown away.
  --now <t>           Override requestedAt. Unix seconds or ISO 8601.
  --out <file>        Write the request there instead of stdout.

Prints an act1.… request to carry to the issuer. Nothing secret is in it: the
fingerprint, a nonce, and the key it is signed with.
`,
  fulfil: `offline-license fulfil --key <private.pem> --id <id> [--request <request>] [options]

  --key <file>        PKCS#8 PEM of the issuing private key.
  --request <req>     The act1.… request. Read from stdin when neither this nor
                      --request-file is given.
  --request-file <f>  Read the request from a file.
  --id <id>           Unique license id. Also keys the machine binding.
  --licensee <name>   Defaults to the licensee the request names.

Everything \`issue\` accepts for features, limits, metadata, expiry, --kid and
--renews works here too. The machine binding is not among them: it comes from the
request, which is the point of asking.

A request that does not hold together exits 2 — it is input an operator can
retype, not a license that was rejected.
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
      case "request":
        return await requestCommand(rest, io);
      case "fulfil":
        return await fulfilCommand(rest, io);
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

/**
 * The flags that describe a license. `issue` and `fulfil` sign the same claims
 * from the same input; they differ only in where the machine binding comes from,
 * so the flags that build the claims are declared once.
 */
const CLAIM_OPTIONS = {
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
  renews: { type: "string" },
  now: { type: "string" },
  out: { type: "string" },
  help: { type: "boolean", short: "h" },
} as const;

/** What claimsFrom reads — the parsed CLAIM_OPTIONS, named so a second command can pass them. */
interface ClaimValues {
  id?: string | undefined;
  feature?: readonly string[] | undefined;
  limit?: readonly string[] | undefined;
  meta?: readonly string[] | undefined;
  "expires-in"?: string | undefined;
  "expires-at"?: string | undefined;
  "not-before"?: string | undefined;
  kid?: string | undefined;
  renews?: string | undefined;
  now?: string | undefined;
}

/** The licensee is a parameter because `fulfil` may take it from the request. */
function claimsFrom(values: ClaimValues, licensee: string): LicenseClaims {
  const issuedAt = values.now === undefined ? nowSeconds() : asTime(values.now, "--now");
  const claims: LicenseClaims = {
    id: required(values.id, "--id"),
    licensee,
    features: features(values.feature),
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
  if (values.renews !== undefined) claims.renews = values.renews;
  return claims;
}

async function issueCommand(argv: readonly string[], io: CliIo): Promise<number> {
  const { values } = parseArgs({
    args: [...argv],
    options: { ...CLAIM_OPTIONS, machine: { type: "string" }, "this-machine": { type: "boolean" } },
  });
  if (values.help) {
    io.out(HELP.issue);
    return OK;
  }

  const claims = claimsFrom(values, required(values.licensee, "--licensee"));
  const fingerprint = machineFingerprint(values.machine, values["this-machine"]);
  if (fingerprint !== undefined) claims.machine = bindMachine(claims.id, fingerprint);

  return await emit(values.key, values.out, io, (privateKey) => issue(privateKey, claims));
}

async function requestCommand(argv: readonly string[], io: CliIo): Promise<number> {
  const { values } = parseArgs({
    args: [...argv],
    options: {
      machine: { type: "string" },
      "this-machine": { type: "boolean" },
      licensee: { type: "string" },
      product: { type: "string" },
      "signing-key": { type: "string" },
      now: { type: "string" },
      out: { type: "string" },
      help: { type: "boolean", short: "h" },
    },
  });
  if (values.help) {
    io.out(HELP.request);
    return OK;
  }

  const fingerprint = machineFingerprint(values.machine, values["this-machine"]);
  if (fingerprint === undefined) {
    // There is no default. A request for a fingerprint nobody chose would come
    // back as a license bound to whichever box happened to run the command.
    throw new UsageError("--this-machine or --machine <fingerprint> is required");
  }

  const input: ActivationRequestInput = { fingerprint };
  if (values.licensee !== undefined) input.licensee = values.licensee;
  if (values.product !== undefined) input.product = values.product;
  if (values.now !== undefined) input.requestedAt = asTime(values.now, "--now");
  if (values["signing-key"] !== undefined) {
    input.signingKey = await readText(values["signing-key"], "--signing-key");
  }

  let request: string;
  try {
    request = createActivationRequest(input);
  } catch (err) {
    throw new UsageError((err as Error).message);
  }
  await write(request, values.out, io);
  return OK;
}

async function fulfilCommand(argv: readonly string[], io: CliIo): Promise<number> {
  const { values } = parseArgs({
    args: [...argv],
    options: { ...CLAIM_OPTIONS, request: { type: "string" }, "request-file": { type: "string" } },
  });
  if (values.help) {
    io.out(HELP.fulfil);
    return OK;
  }

  const request = (await readBlob(values.request, values["request-file"], "--request", io)).trim();
  let claim: MachineClaim;
  try {
    claim = readActivationRequest(request);
  } catch (err) {
    // A request the operator pasted is input they can retype, so it exits 2 and
    // the reason says which of the three ways it failed to hold together.
    throw new UsageError(`--request: ${(err as Error).message}`);
  }

  const licensee = values.licensee ?? claim.licensee;
  if (licensee === undefined) throw new UsageError("--licensee is required: the request does not name one");

  const claims = claimsFrom(values, licensee);
  return await emit(values.key, values.out, io, (privateKey) => fulfilActivation(privateKey, request, claims));
}

/**
 * Read the key, sign, and put the result where the operator asked.
 *
 * A key the library rejects, or a claim combination it refuses to sign, is bad
 * input rather than a failure — report it as such instead of dumping a stack.
 */
async function emit(
  keyFlag: string | undefined,
  out: string | undefined,
  io: CliIo,
  signer: (privateKey: string) => string,
): Promise<number> {
  const privateKey = await readText(required(keyFlag, "--key"), "--key");
  let token: string;
  try {
    token = signer(privateKey);
  } catch (err) {
    throw new UsageError((err as Error).message);
  }
  await write(token, out, io);
  return OK;
}

async function write(text: string, out: string | undefined, io: CliIo): Promise<void> {
  if (out === undefined) io.out(`${text}\n`);
  else await writeFile(out, `${text}\n`, "utf8");
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
      grace: { type: "string" },
      previous: { type: "string" },
      "previous-file": { type: "string" },
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
  const token = (await readBlob(values.token, values["token-file"], "--token", io)).trim();

  const options: VerifyOptions = {};
  if (values.now !== undefined) {
    const now = asTime(values.now, "--now");
    options.now = () => now;
  }
  if (values.skew !== undefined) options.skewSeconds = asNumber(values.skew, "--skew");
  if (values.grace !== undefined) options.graceSeconds = asNumber(values.grace, "--grace");
  const fingerprint = machineFingerprint(values.machine, values["this-machine"]);
  if (fingerprint !== undefined) options.machineFingerprint = fingerprint;
  const previous = await readPrevious(values.previous, values["previous-file"]);
  if (previous !== undefined) options.previous = predecessor(publicKey, previous.trim(), options);

  let result;
  try {
    result = verify(publicKey, token, options);
  } catch (err) {
    throw new UsageError((err as Error).message);
  }

  if (values.json) {
    io.out(`${JSON.stringify(result, null, 2)}\n`);
  } else if (result.ok) {
    // The status leads the line the way the reason does below, so one grep over
    // either stream tells a script which of the three verdicts it got.
    io.out(`${result.status ?? "valid"}: ${describe(result.claims)}${expiry(result.claims)}\n`);
  } else {
    // The library hands claims back on expiry so a UI can say *which* license;
    // the CLI passes that through for the same reason.
    const which = result.claims ? ` — ${describe(result.claims)}` : "";
    io.err(`invalid: ${result.reason}${which}\n`);
  }
  return result.ok ? OK : REJECTED;
}

/**
 * The token of the license being replaced. Stdin is not one of the places it
 * can come from: that is where the token under test arrives, and a command
 * reading two blobs from one pipe would have to split them somewhere.
 */
async function readPrevious(inline: string | undefined, file: string | undefined): Promise<string | undefined> {
  if (inline !== undefined && file !== undefined) {
    throw new UsageError("--previous and --previous-file are mutually exclusive");
  }
  if (inline !== undefined) return inline;
  return file === undefined ? undefined : readText(file, "--previous-file");
}

/**
 * The predecessor, read out of its own token under the same key.
 *
 * The id and the expiry a renewal is judged against are claims, and an unsigned
 * claim decides nothing — a predecessor whose expiry anyone could edit would
 * hand out an unbounded grace window. Being expired is what a predecessor
 * normally is, so only a token that yields no claims at all is bad input.
 */
function predecessor(publicKey: PublicKeyInput, token: string, options: VerifyOptions): Predecessor {
  const result = verify(publicKey, token, options);
  if (result.claims === undefined) {
    throw new UsageError("--previous: not a license signed by this key");
  }
  return result.claims;
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

/**
 * A blob the operator supplies inline, from a file, or on stdin — a token for
 * `verify`, a request for `fulfil`. Stdin is what lets `issue | verify` and
 * `request | fulfil` work without a temp file.
 */
async function readBlob(
  inline: string | undefined,
  file: string | undefined,
  flag: string,
  io: CliIo,
): Promise<string> {
  if (inline !== undefined && file !== undefined) {
    throw new UsageError(`${flag} and ${flag}-file are mutually exclusive`);
  }
  if (inline !== undefined) return inline;
  if (file !== undefined) return readText(file, `${flag}-file`);
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

/**
 * `--feature export` keeps the array form, so a command line that worked before
 * this flag learned values still produces the same token byte for byte. One
 * `--feature seats=25` turns the claim into a record, where a bare name is
 * `true`: a license states its features in one form or the other, not both.
 */
function features(entries: readonly string[] | undefined): Features {
  const list = entries ?? [];
  if (!list.some((entry) => entry.includes("="))) return list;

  const record: Record<string, FeatureValue> = {};
  for (const entry of list) {
    const eq = entry.indexOf("=");
    if (eq < 0) record[entry] = true;
    else if (eq === 0) throw new UsageError(`--feature expects <name> or <name>=<value>, got ${entry}`);
    else record[entry.slice(0, eq)] = asFeatureValue(entry.slice(eq + 1));
  }
  return record;
}

/**
 * A shell has only strings. `true`, `false` and a number read as themselves,
 * because that is what an operator typing them means; anything else stays a
 * string, so a tier called `2xl` is not mangled on its way into the token.
 */
function asFeatureValue(text: string): FeatureValue {
  if (text === "true") return true;
  if (text === "false") return false;
  return /^-?\d+(\.\d+)?$/.test(text) ? Number(text) : text;
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
