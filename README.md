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
| Renewal chain, when a predecessor is given | `renewal_gap` | A renewal from the wrong generation is the wrong file whatever the clock says |
| Clock has not gone backwards | `clock_rollback` | An expired license becomes "valid" if the clock is set back — check before expiry |
| `notBefore` / `expiresAt` (± skew) | `not_yet_valid` / `expired` | A grace period, when set, only moves where `expired` begins |
| Machine binding | `machine_mismatch` | |

`verify()` returns a discriminated union rather than throwing — `{ ok, reason,
claims }` — because "expired" and "tampered" deserve different UI, and the
claims are handed back on expiry so the screen can say *which* license.
`verifyOrThrow()` exists for callers who prefer exceptions.

## Valued features

Some entitlements have a value and not only a presence: the plan tier a screen
has to name, a count that belongs to one feature. `features` takes a record for
those, alongside the array it always took.

```ts
const token = issue(privateKey, {
  ...claims,
  features: { sso: true, seats: 25, tier: "pro", beta: false },
});

const license = new LicenseGuard({ publicKey, token });

license.value("seats");        // 25
license.value("tier");         // "pro"
license.value("billing");      // null — the license never mentions it
license.hasFeature("sso");     // true
license.hasFeature("beta");    // false
```

`["export", "sso"]` means exactly `{ export: true, sso: true }`, so the two
forms answer the same question and `hasFeature` is unchanged by which one a
license carries. That is also why every token already in the field keeps
verifying: nothing about the array form moved, and an issuer that never writes a
record never sees a difference.

Only an explicit `false` withholds a feature. An issuer shipping one record
shape to every customer needs a way to say no, and reading a present `false` as
allowed would invert what the license says. A `0` or an empty string is a value
to read, not a switch — `hasFeature("seats")` is true when the license names
`seats` at all, and what zero seats means belongs to the product.

`value()` returns `boolean | number | string | null`, and deliberately takes no
type parameter for the caller's feature shape. The claims come off a token, so a
supplied shape would be an assertion about the wire that nothing verifies.
Narrow the union where you read it, next to the check that it is the kind you
expected.

Caps stay in `limits`. A numeric feature is a value the product reads; `limits`
is what `withinLimit` compares usage against, and keeping the two apart is what
lets `withinLimit("seats", used)` mean one thing.

`featureValue` and `hasFeature` are exported for code holding claims from
`verify()` rather than a guard, and both builds go through them, so a verdict
cannot differ between Node and the browser.

From the shell, a `=` gives the value:

```bash
offline-license issue --key ./private.pem --id lic_7f3a --licensee "Acme Ltd" \
  --feature sso --feature seats=25 --feature tier=pro
```

`true`, `false` and a number read as themselves; anything else stays a string,
so a tier called `2xl` survives the trip. With no `=` in any `--feature` the
claim is the array it was before, byte for byte.

## Metered limits

`limits` states a cap; `UsageLedger` is what counts against it. Consumption is
recorded locally, in an append-only ledger whose entries are HMAC-chained with
the license id, so the count cannot be edited down with a text editor.

```ts
import { UsageLedger, FileLedgerStore, verifyOrThrow } from "offline-license";

const claims = verifyOrThrow(publicKey, token);     // the caps come from the license
const usage = new UsageLedger({ store: new FileLedgerStore("/var/lib/acme/usage.json"), claims });

await usage.load();                  // once, at startup — reads and checks every link

usage.used("exports");               // 7
usage.remaining("exports");          // 3
usage.withinLimit("exports", 2);     // true

await usage.record("exports");       // appended and persisted
await usage.record("exports", 5);    // throws UsageLimitError { key, cap, used, requested }
```

Reads are synchronous off the loaded ledger, because "how many left" belongs on
a render path; `load()` has to resolve first, the way the clock's does. Writing
is not, and `record()` re-reads the store before it appends: two windows of the
same app share one file, and appending to a copy loaded minutes ago would drop
whatever the other one recorded since. That is also what makes the cap honest
across windows — the check is against what is stored, not against what this
process loaded.

The arithmetic is `withinLimit`'s, so the guard and the ledger cannot disagree:
consumption may reach a cap and not pass it, a key the license caps nowhere
allows everything, and `remaining` is `null` rather than `0` for such a key —
uncapped is not "nothing left".

```json
{
  "version": 1,
  "license": "lic_7f3a",
  "entries": [
    {"key":"exports","amount":1,"at":1800000000,"mac":"kPx…"},
    {"key":"exports","amount":2,"at":1800003600,"mac":"7Qa…"}
  ]
}
```

Each `mac` is `HMAC-SHA256(previous mac ‖ this entry, key = licenseId)` — the
same primitive and the same key as machine binding, under a `usage.` tag so one
can never be read where the other is expected. Because every link covers the one
before it, an amount that was edited, an entry dropped from the middle, two
reordered, or a `mac` copied from elsewhere in the file all break the chain:
`load()` then throws `UsageLedgerError` with `reason: "broken_chain"` instead of
handing back a total it cannot stand behind. A ledger relabelled to another
license fails too — the id is the key, not just a field — and `reason` is
`"wrong_license"` when the label disagrees, `"malformed"` when the file is
truncated or from a later format, because those three deserve different screens.

**What the chain does not catch is deletion.** Dropping the last few entries, or
the file, leaves a ledger that chains perfectly — it just says less was used.
Nothing stored next to the counter can fix that, which is why a missing ledger is
a first run rather than an error, exactly as a missing clock mark is. `head` is
the hook if you need more: the last mac, one short string standing for the whole
history, which a product that syncs with a server or reads an MDM profile can pin
somewhere the customer does not own and compare on startup.

The browser build has the same ledger over `LocalStorageLedgerStore`, and the
macs are byte-identical, so an Electron app can write it in the main process and
read it in the renderer.

```ts
import { UsageLedger, LocalStorageLedgerStore } from "offline-license/web";

const usage = new UsageLedger({ store: new LocalStorageLedgerStore(), claims });
```

## Offline activation

A machine with no network cannot ask for a license, so the asking becomes two
blobs carried by hand. The product emits a request; the operator takes it to the
issuer by email, USB stick or a line typed over the phone; the issuer signs a
license bound to the machine named in it.

```ts
import { createActivationRequest, defaultFingerprint } from "offline-license";

// On the air-gapped box.
const request = createActivationRequest({
  fingerprint: defaultFingerprint(),
  licensee: "Acme Ltd",
  product: "acme-cad",
});
// act1.eyJmaW5nZXJwcmludCI6… — carry this to the issuer
```

```ts
import { fulfilActivation, readActivationRequest } from "offline-license";

// On the issuing server, with the request in hand.
const claim = readActivationRequest(request);   // ActivationError if it does not hold together
claim.licensee;      // "Acme Ltd" — what the operator decides from
claim.requestedAt;   // and how long it has been sitting in a drawer

const token = fulfilActivation(privateKey, request, {
  id: "lic_7f3a",
  licensee: claim.licensee ?? "Acme Ltd",
  features: ["export", "sso"],
  issuedAt: now(),
  expiresAt: now() + 365 * 86_400,
});
```

`fulfilActivation` sets `machine` from the request's fingerprint and `activation`
from its nonce, and the claims it accepts omit both: a caller free to pass either
could bind a license to a machine that never asked for one, or stamp it with a
nonce no install is waiting for.

Back on the box, `verify` checks the binding as it does for any bound license.
The nonce is checked once, when the license is installed:

```ts
import { answersRequest, verifyOrThrow } from "offline-license";

const claims = verifyOrThrow(publicKey, token, { machineFingerprint: defaultFingerprint() });
answersRequest(request, claims);   // is this the license this box asked for?
```

`answersRequest` is deliberately not one of `verify`'s checks. A license that
answered the right request yesterday still does, so asking on every question
would mean keeping the request for the life of the install to re-answer
something that cannot change. What it catches is the one case the binding
cannot: two requests from the same machine bind identically, so without the
nonce the license issued for the earlier one — shorter, fewer features, or the
one a renewal was meant to replace — installs as the answer to the request just
made.

**The request's signature is an integrity check, not an identity.** The product
holds no private key, only the public one it verifies licenses with, so it signs
with a key it generates and embeds in the request. Anyone who edits the payload
can re-sign it under a fresh key and produce a request that reads perfectly.
What the signature does buy is that a request cannot arrive *partly* mangled,
which is what actually goes wrong when a blob travels by mail client and USB
stick: a fingerprint a client line-wrapped, a nonce pasted next to the wrong
machine, a paste that lost its last line. Each of those is `invalid_signature`
on the operator's desk instead of a license bound to a fingerprint no machine
will ever present.

Who the customer is cannot be settled offline by anything the machine says about
itself. `licensee` and `product` are labels for the operator, who decides, and
there is nothing stronger to be had without a network — claiming otherwise would
only move the trust somewhere less visible.

An install that keeps its key gets one thing more. Pass `signingKey` and the
request is signed by a key that outlives it, so an issuer recording the key it
first saw can tell the same install asking again from a new one. That is more
than the fingerprint says: hardware changes, and the fingerprint moves with it.

From the shell the exchange is two commands, and they pipe:

```bash
# on the air-gapped box
offline-license request --this-machine --licensee "Acme Ltd" --out ./request.act

# on the issuer
offline-license fulfil --key ./private.pem --id lic_7f3a \
  --request-file ./request.act --feature sso --limit seats=25 --expires-in 365d
```

`fulfil` takes everything `issue` does except the machine flags — the binding
comes from the request, which is the point of asking — and `--licensee` defaults
to the one the request names. A request that does not hold together exits 2: it
is input an operator can retype, not a license that was rejected.

The exchange is Node-only. It happens where the install does, in an installer, a
service, or a technician's shell, and the browser build has no fingerprint of
its own to offer. What it produces is an ordinary token, so it verifies in both
builds, and the shared vectors hold one.

## Grace period

`expiresAt` is a cliff, and renewals do not land punctually. `graceSeconds`
keeps a just-expired license working for a configured window and says so, so
the screen can warn instead of the product stopping mid-shift.

```ts
const result = verify(publicKey, token, { graceSeconds: 7 * 86_400 });

result.ok;      // true — everything the license allows still works
result.status;  // "expired_in_grace" — and the UI has something to warn with

new LicenseGuard({ publicKey, token, graceSeconds: 7 * 86_400 }).inGrace();
```

The result is `ok` because anything else would block, which is the whole thing
grace exists to avoid: `hasFeature` and `withinLimit` keep answering and
`status` is all that changes. It is absent while the license is simply valid,
and the window defaults to none, so a caller that never asks for grace sees
what it saw before.

The window ends. Past `expiresAt + graceSeconds` the reason is `expired`, as it
always was — grace with no end is no expiry at all. Only expiry is softened: a
machine mismatch or a rolled-back clock inside the window fails exactly as it
does outside, because being late is not a reason to accept a license that was
never valid here.

From the shell it is `--grace <seconds>`. The exit code stays 0 — the product
should run — and the status leads the line the way a rejection's reason does:

```bash
offline-license verify --key ./public.pem --token "$LICENSE" --grace 604800
# expired_in_grace: Acme Ltd (lic_7f3a), expires 2026-09-01T00:00:00.000Z
```

## Renewal chain

A renewal is an ordinary license with one extra claim: `renews`, the id of the
license it replaces. That link is what lets an install tell the renewal it asked
for from a file handed to it out of order.

```ts
const next = issue(privateKey, {
  id: "lic_2027",
  renews: "lic_2026",            // the license this one replaces
  licensee: "Acme Ltd",
  features: ["export", "sso"],
  issuedAt: now(),
  notBefore: FEBRUARY_FIRST,     // the new term, which may not have started yet
  expiresAt: FEBRUARY_FIRST + 365 * 86_400,
});

// In the product, which is holding the license being replaced.
verify(publicKey, next, { previous: installed, graceSeconds: 7 * 86_400 });
```

`previous` is the claims of the license currently installed — whatever an
earlier `verify` handed back — and supplying it is what turns the chain checks
on. Two things come out of them.

**A renewal that skips a generation is refused**, with reason `renewal_gap`.
Each license is issued to follow one particular predecessor, so a token naming a
different one is either a file held back from an earlier term or a license for
another chain, and without the link either installs as though it were the next
one. The claims come back on the failure, as they do on expiry, so a screen can
say which license was offered and which one the box actually holds.

**A renewal whose term has not begun is accepted while the license it replaces
is in grace**, reported as `expired_in_grace`. Renewals are dated from the start
of the next term and installed whenever the operator gets to them; in between,
the product has already swapped the file and the old license it would otherwise
fall back on is gone. Blocking there would lock out a customer whose entitlement
never lapsed, which is the thing grace exists to avoid.

The window is the predecessor's, so it ends where that one does: past
`expiresAt + graceSeconds` the reason is `not_yet_valid` again, until the new
term genuinely starts. The concession is that the new terms begin up to one
grace window early — the trade for not going dark between terms, bounded by a
window the issuer already chose. Nothing else is softened: a machine mismatch or
a rolled-back clock inside the inherited window fails exactly as it does
outside.

Keep the old license file until the renewal verifies against it. The window a
renewal inherits is the predecessor's grace, which means the predecessor's
claims, and an install that threw them away has nothing to inherit from.

A product that does not renew in chains sees no change. A token carrying no
`renews` is not a renewal — an issuer re-issuing from scratch says so by leaving
it out — and with no `previous` supplied there is nothing to check against, so
`renews` is a field the install may display and nothing more. A license whose
`renews` names itself is `invalid_claims`: a chain of one is a mistake in the
issuer, not an unusual link.

From the shell:

```bash
offline-license issue --key ./private.pem --id lic_2027 --renews lic_2026 \
  --licensee "Acme Ltd" --not-before 2027-02-01 --expires-at 2028-02-01

# $INSTALLED ran out on 1 January and the new term starts on 1 February, so in
# between the renewal verifies on the week of grace the old license still has.
offline-license verify --key ./public.pem --token "$RENEWAL" \
  --previous "$INSTALLED" --grace 604800
# expired_in_grace: Acme Ltd (lic_2027), expires 2028-02-01T00:00:00.000Z
```

`--previous` takes the predecessor's own token and reads the id and the expiry
out of it under the same key. Those two claims decide how long the inherited
window runs, and an expiry anyone could edit with a text editor would be no
window at all.

## Check audit

The product knows why it stopped letting people in; its admin page does not.
`onCheck` is told the verdict of every check the guard makes, and `CheckLog` is
the listener that keeps the little of it a screen can use: when the license last
verified, and what went wrong the last few times it did not.

```ts
import { CheckLog, FileCheckLogStore, LicenseGuard } from "offline-license";

const log = new CheckLog({ store: new FileCheckLogStore("/var/lib/acme/checks.json") });
await log.load();                // once, at startup

const license = new LicenseGuard({ publicKey, token, onCheck: log.record });
license.hasFeature("sso");       // every check reports, here and everywhere else

log.lastVerifiedAt;              // 1800003600 — the whole of "last verified at"
log.lastOk;                      // { at: 1800003600, license: "lic_7f3a" }
log.failures;                    // the last runs, oldest first
```

`record` is a property rather than a method, so it can be handed over as it is
and still find its `this`.

**Successes are one timestamp, not a list.** The guard re-verifies on every
question, so a product asking three of them per render produces successes faster
than any small log could hold, and a ring filled with them would push out the
failures the page exists to show. "When did this last work" has one answer
anyway.

**Failures collapse into runs** for that same reason: an expired license fails
again on every render, and what the page needs is the kinds of failure rather
than the last half-second of one of them. A run carries the reason, when it
started, when it last happened, and how many checks it covers — checks and not
questions, because one `withinLimit()` can verify twice.

```json
{
  "version": 1,
  "lastOk": {"at":1800003600,"license":"lic_7f3a"},
  "failures": [
    {"reason":"machine_mismatch","firstAt":1800000000,"at":1800002400,"count":418,"license":"lic_7f3a"}
  ]
}
```

A run is written the moment it starts. Failures are rare, a crash is exactly
when someone goes looking for this page, and a failure nobody wrote down cannot
be reconstructed afterwards. A repeat, or a success, rides a throttle (default:
60 seconds), because a write per question would put the log on the render path —
with the first check after startup always persisted, or a product that is
started and stopped again would never record that it verified at all.

`load()` has to resolve before the log is read, the way the clock's and the
ledger's do: reading it earlier throws rather than saying "never verified" about
an install that has been verifying for a year. Recording is never refused,
though. The guard holds the listener from its constructor and may answer a
question while the file is still being read, so `load()` merges what it finds
underneath what has already happened instead of replacing it.

**The log is not evidence.** It sits on the customer's disk under no signature,
and chaining it the way the usage ledger is chained would claim a guarantee it
cannot have: a usage count decides what the product allows, while nothing is
ever decided from this file. That is also why a log this release cannot read
whole — a later version, a stray field, a write cut short — is discarded rather
than refused. An unreadable history costs an admin page its history; refusing
would cost a paying customer their product. Whatever a listener throws is
swallowed for the same reason, so a log on a full disk cannot turn a valid
license into an exception.

The browser build has the same log over `LocalStorageCheckLogStore`, under
`offline-license:checks`:

```ts
import { CheckLog, LocalStorageCheckLogStore } from "offline-license/web";

const log = new CheckLog({ store: new LocalStorageCheckLogStore() });
```

There is no CLI surface for it. A log is a history and `verify` exits, which is
the same reason clock-rollback detection belongs to a long-lived product rather
than to a command.

## CLI

The same operations from a shell, on `node:util` `parseArgs` — still no
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

`request` and `fulfil` are the two halves of the activation exchange, above.

`--this-machine` binds to — or checks against — this box's
`defaultFingerprint()`; `--machine <fingerprint>` issues for someone else's.
Clock-rollback detection is deliberately absent: a high-water mark only means
something across a process's lifetime, so it belongs to `MonotonicClock` inside
a long-lived product, not to a command that exits.
`offline-license <command> --help` lists the rest.

## Key rotation

Hand `verify` — or `LicenseGuard` — a ring of public keys instead of one, and
let the `kid` claim say which key signed each license.

```ts
const publicKeys = { "2025": oldPublicKey, "2026": newPublicKey };

const token = issue(newPrivateKey, { ...claims, kid: "2026" });
verify(publicKeys, token);   // checked against "2026", and nothing else
```

Ship both keys for as long as licenses signed by the old one are still in the
field, then drop that entry: every token naming it stops verifying, which is
how a key is retired. A `kid` naming no key in the ring is `invalid_signature`
— the ring never falls back to its other keys, because that would leave a
retired key indistinguishable from a current one. A token issued before
rotation carries no `kid` at all, so it is tried against every key in the ring;
that is what makes the overlap period work.

Choosing a key means reading the `kid` before the signature is checked, so the
`kid` decides nothing else. The token still has to verify under the key it
named, and the `kid` sits inside the signed payload, so editing it only breaks
the signature it was meant to escape.

From the shell, `--key` repeats as `<kid>=<file>`:

```bash
offline-license issue --key ./2026/private.pem --kid 2026 --id lic_7f3a --licensee "Acme Ltd"

offline-license verify --token "$LICENSE" \
  --key 2025=./2025/public.pem --key 2026=./2026/public.pem
```

## License files

A token is a base64 blob. The envelope is what ships to the customer: the token
plus the context whoever opens the file needs.

```ts
import { writeLicenseFile, readLicenseFile } from "offline-license";

await writeLicenseFile("/etc/acme/license.json", {
  token,
  issuer: "Acme Ltd",
  notes: "renewal 2027 — support@acme.example",
});

const file = await readLicenseFile("/etc/acme/license.json");
verify(publicKey, file.token);
```

```json
{
  "version": 1,
  "token": "lic1.eyJmZWF0dXJlcyI6…",
  "issuer": "Acme Ltd",
  "notes": "renewal 2027 — support@acme.example"
}
```

`issuer` and `notes` sit outside the signature, so anyone holding the file can
rewrite them. They are labels for people; every decision still comes from the
claims inside the token. `readLicenseFile` does no verifying — it has no key,
and "no license installed" is a different screen from "this license expired".
A missing file therefore surfaces as an ordinary `ENOENT`, while a file that is
there and unusable is a `LicenseFileError`.

`version` is refused rather than interpreted when it is not the one this
release knows, and within a version the shape is closed: an unknown field is a
typo — `note` for `notes` — and reading past it would erase it on the next
write. Writes replace the file atomically, like the clock store's, because a
truncated envelope parses as nothing and would lock out a customer whose
license was fine.

## Browser build

`offline-license/web` is the same verifier over WebCrypto, for Electron
renderers and dashboards that never see a Node API. The bundle imports nothing
from `node:` — a test walks the import graph to keep it that way.

```ts
import { LicenseGuard, verify } from "offline-license/web";

const result = await verify(publicKeyPem, token);   // the same VerifyResult
const license = new LicenseGuard({ publicKey: publicKeyPem, token });

await license.hasFeature("sso");
```

Everything returns a promise, because `subtle.verify` does and there is no
synchronous way to reach it. That is the whole of the difference: the same
checks in the same order, the same reasons, the same `LicenseError`, key rings
and `kid` selection included. Both builds run one table of tokens and expected
verdicts — the one in `vectors/`, below — so a verdict that moves on one
platform and not the other fails the suite rather than a customer's screen.

`verify` takes an SPKI PEM or a `CryptoKey` you imported yourself with
`importPublicKey`. There is no cache behind the PEM — the guard re-verifies on
every question, and hidden state is worse than a parse — so hand it the
`CryptoKey` when a render loop makes the parse worth skipping.

`bindMachine` is async here and byte-identical to the Node one, so a license
issued against a fingerprint the server computed checks out in the renderer.
There is no `defaultFingerprint()`: a browser has nothing stable to offer that
is not either useless (a user agent string) or a tracking id, and a fingerprint
that moves when someone changes a font setting locks out a paying customer. In
Electron, pass the one the main process already has.

WebCrypto needs a secure context, so a page served over `http://` has no
`crypto.subtle` and the build says so rather than failing with an undefined
property.

Clock rollback is checked here too. `MonotonicClock` is platform-free already;
what it lacked was somewhere to keep its high-water mark between page loads, and
`LocalStorageStore` is that — one number under `offline-license:clock`, or under
a `key` of your own.

```ts
import { LocalStorageStore, MonotonicClock, verify } from "offline-license/web";

const clock = new MonotonicClock({ store: new LocalStorageStore() });
await clock.load();                            // once, at startup

await verify(publicKeyPem, token, { clock });  // clock_rollback when it applies
```

It reads the way `FileStore` does: a missing entry, an empty one, or one that is
not a number all mean "first run" rather than time zero — zero is a mark every
later clock beats, so it would switch the check off without saying so. Nothing
mimics the atomic rename, because `setItem` either replaces a value or leaves it
as it was; there is no torn write to read back.

Two things differ, both because an origin is not a file. A write never lowers
what is stored: every tab holds its own in-memory mark, and one left open since
yesterday would otherwise flush that older mark over a newer one and hand back
the rollback the mark exists to catch. And a browser that refuses to store —
site data blocked, or Safari's private mode — throws rather than quietly doing
nothing, because a product that believes the check is on when it is not is worse
off than one that is told. Pass `storage` (`sessionStorage`, or your own object)
when `localStorage` is not where the mark belongs.

## Test vectors

`vectors/` holds twenty-five tokens, the keys that signed them, and the verdict
each must produce. It ships in the package.

```
vectors/keys.json      two Ed25519 key pairs: SPKI PEM, the raw 32 bytes, PKCS#8 PEM
vectors/vectors.json   name, public key, token, verify options, expected result
vectors/README.md      how to run the set, and what is deliberately not in it
```

It is published because a licensing format with one implementation is a format
with no interoperability story. A verifier in Go or Rust can take these files
and prove it agrees with this one — including the parts that are easy to get
subtly wrong, like a `kid` naming a retired key yielding no candidate instead of
falling back to the ring, or claims coming back alongside an `expired` verdict
but not alongside `invalid_signature`. Every failure reason a token can produce
has a vector; a test fails if one is added without one.

The set is also how the two builds here are held together, which is why it is
files and not a table built at import time. Tokens that existed for a few
milliseconds inside one test process proved the builds agreed with each other
and nothing else: a change to the issuer moved the fixtures and the
expectations in step, and nobody outside the repository had anything to check.
These are bytes, signed by keys that are also bytes.

```bash
pnpm vectors    # re-cut the set after a change to the issuer
```

Payloads are canonical JSON and Ed25519 is deterministic, so an unchanged
release re-cuts byte-for-byte; `pnpm test` compares the checked-in file against
what the current code signs and fails on a diff. The private keys are in there
on purpose — an implementation that issues can reproduce every token exactly —
and they are test keys that sign nothing real.

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

## Install / develop

```bash
pnpm add offline-license      # Node >= 20, zero runtime dependencies
npx offline-license --help    # the CLI, without installing it

pnpm test                     # 284 tests: round-trip, tampering, time, grace, renewals, binding, clock, guard, features, metered limits, offline activation, check audit, rotation, CLI, license files, the web build, the published vectors
pnpm build                    # ESM + .d.ts into dist/
pnpm vectors                  # re-cut vectors/ after a change to the issuer
```
