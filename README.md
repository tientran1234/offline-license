# offline-license

Software licensing that works with the network cable unplugged.

An issuing server signs a license with an Ed25519 private key. The product ships
with the public key and checks the license locally — features, limits, expiry,
which machine it is bound to, and whether someone has wound the clock back.
No phone-home, no dependencies, ~300 lines.

```ts
import { generateKeyPair, issue, LicenseGuard, bindMachine, defaultFingerprint } from "offline-license";

// Once, on your server. Keep the private key there.
const { privateKey, publicKey } = generateKeyPair();

// Per customer, on your server.
const token = issue(privateKey, {
  id: "lic_7f3a",
  licensee: "Acme Ltd",
  features: ["export", "sso"],
  limits: { seats: 25 },
  issuedAt: now(),
  expiresAt: now() + 365 * 86_400,
  machine: bindMachine("lic_7f3a", customerFingerprint), // optional
});

// In the product. Only the public key ships.
const license = new LicenseGuard({ publicKey, token, machineFingerprint: defaultFingerprint() });

license.hasFeature("sso");          // true
license.withinLimit("seats", 24);   // true
license.assertFeature("billing");   // throws LicenseError { reason: "invalid_claims" }
```

## What it checks, in order

| Check | Failure reason | Why this order |
|---|---|---|
| Shape `lic1.<payload>.<sig>` | `malformed` | Cheapest, and it rejects the most junk |
| Ed25519 signature over `lic1.<payload>` | `invalid_signature` | Nothing below reads a byte an attacker could have written |
| Claims schema | `invalid_claims` | A valid signature over the wrong shape is still not a license |
| Clock has not gone backwards | `clock_rollback` | An expired license becomes "valid" if the clock is set back — check before expiry |
| `notBefore` / `expiresAt` (± skew) | `not_yet_valid` / `expired` | |
| Machine binding | `machine_mismatch` | |

`verify()` returns a discriminated union rather than throwing — `{ ok, reason,
claims }` — because "expired" and "tampered" deserve different UI, and the
claims are handed back on expiry so the screen can say *which* license.
`verifyOrThrow()` exists for callers who prefer exceptions.

## CLI

The same three operations from a shell, on `node:util` `parseArgs` — still no
dependencies.

```bash
offline-license keygen --out ./keys          # private.pem (0600) + public.pem

offline-license issue --key ./keys/private.pem \
  --id lic_7f3a --licensee "Acme Ltd" \
  --feature export --feature sso \
  --limit seats=25 --expires-in 365d         # prints the token

offline-license verify --key ./keys/public.pem --token "$LICENSE"
echo "$LICENSE" | offline-license verify --key ./keys/public.pem --json
```

Exit codes are the contract, because a release script branches on them:

| Code | Meaning |
|---|---|
| 0 | Done, or the license is valid |
| 1 | The license was rejected — the reason goes to stderr |
| 2 | Bad usage: an unknown flag, a missing `--key`, `--expires-in 365` with no unit |

A rejected license and a mistyped flag never share a code. `verify` reads the
token from stdin when given no `--token`, so `issue | verify` needs no temp
file, and `--json` prints the whole `VerifyResult` without changing the code.

`--this-machine` binds to — or checks against — this box's
`defaultFingerprint()`; `--machine <fingerprint>` issues for someone else's.
Clock-rollback detection is deliberately absent: a high-water mark only means
something across a process's lifetime, so it belongs to `MonotonicClock` inside
a long-lived product, not to a command that exits.
`offline-license <command> --help` lists the rest.

## Design decisions

**The version prefix is inside the signature.** The signature covers the bytes
`lic1.<payload>`, not just the payload. A future `lic2` format cannot be
downgraded to `lic1` by editing three characters.

**Machine binding stores an HMAC, not the fingerprint.** `machine` is
`HMAC-SHA256(fingerprint, key = licenseId)`. The token reveals nothing about the
machine, and the same machine binds differently under every license, so one
leaked token cannot be matched against another. The verifier recomputes the HMAC
from the local fingerprint and compares.

**Clock rollback is detected with a high-water mark, checked in memory.**
`MonotonicClock` remembers the latest time it has ever seen. Every observation is
one comparison, no I/O. The mark only moves forward; once a later time has been
seen, an earlier one is a rollback however the clock is set. The mark is
persisted on a throttle (default: once an hour) through an atomic
temp-file-then-rename write, so a crash can never leave a half-written file that
parses as time zero and silently switches the check off. The throttle is the
trade-off: after a crash the mark can be up to one interval stale, which bounds
how far a rollback goes undetected. Tighten it if that matters more than writes.

**Payloads are canonical JSON.** Keys are sorted at every level, so two issuers
given the same claims produce byte-identical tokens. Signatures become
reproducible and license files become diffable.

**The guard re-verifies on every question.** A signature check and a few
comparisons are cheap; caching the answer would only give an expiry or a rollback
somewhere to hide.

**`defaultFingerprint()` is deliberately weak.** Hostname, platform, arch, CPU
model, RAM. It stops a license file being copied to a second box; it does not
stop someone who edits the binary — nothing running on the customer's machine
can. Supply your own fingerprint (TPM, dongle, MDM device id) when the threat
model needs more.

## What it does not do

- **Revocation.** Offline means no list to consult. Use short expiries and
  re-issue; that is the whole trade.
- **Obfuscation.** The public key and this code are visible to whoever has the
  binary. This library makes forging a license impossible; it does not make
  removing the check impossible. Nothing does.
- **Key rotation.** One public key per product build. Rotate by shipping a new
  build that accepts both keys during the overlap.

## Install / develop

```bash
pnpm add offline-license      # Node >= 20, zero runtime dependencies
npx offline-license --help    # the CLI, without installing it

pnpm test                     # 60 tests: round-trip, tampering, time, binding, clock, guard, CLI
pnpm build                    # ESM + .d.ts into dist/
```
