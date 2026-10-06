# Shared test vectors

Twenty-five tokens, the keys that signed them, and the verdict each one must
produce. They are here so that an implementation this repository has never seen
— a verifier in Go, Rust, Python, anything — can prove it agrees with the
reference one before its users find out that it does not.

The Node build and the browser build in this package both run exactly this set,
from exactly these files. There is no second table that only the reference
implementation sees.

## Running the set

For each entry in `vectors.json`:

1. Resolve `publicKey`. A string names a key in `keys.json`. An object is a key
   ring — kid to key name — and the verifier picks from it by the token's `kid`,
   with a kid naming no entry yielding no candidate rather than falling back to
   the rest of the ring.
2. Verify `token` with `options` applied, treating `options.now` as the current
   time in unix seconds. Anything absent takes the documented default:
   `skewSeconds` 60, `graceSeconds` 0, no machine fingerprint, no predecessor.
3. Compare against `expected`, in full. `ok: true` carries `claims` and, inside
   a grace window, `status: "expired_in_grace"`. `ok: false` carries `reason`,
   and `claims` as well whenever the token got far enough to parse — a verifier
   that returns claims for `invalid_signature`, or withholds them for `expired`,
   does not match.

```json
{
  "name": "a renewal that skips a generation",
  "publicKey": "signing",
  "token": "lic1.eyJleHBpcmVzQXQiOjE...",
  "options": { "now": 1800000000, "previous": { "expiresAt": 1799913600, "id": "lic_vector_0" } },
  "expected": { "claims": { "...": "..." }, "ok": false, "reason": "renewal_gap" }
}
```

`name` is a label for your test output. Match on position or on the whole
entry, never on the name — the wording is not a contract and the set grows.

## The keys

`keys.json` gives each key three ways, all the same key: `publicKey` as SPKI
PEM, `publicKeyRaw` as the 32 raw Ed25519 bytes in base64url for a library that
wants the key without the wrapper, and `privateKey` as PKCS#8 PEM.

The private halves are here on purpose. A verifier only needs the public key,
but an implementation that also *issues* can re-sign these claims and compare
tokens byte-for-byte: payloads are canonical JSON — keys sorted at every level
— and Ed25519 signatures are deterministic, so a correct issuer reproduces
every token here exactly. These are test keys and they sign nothing real. Never
ship one in a product.

## What is not in here

**Clock rollback.** `clock_rollback` is the one verdict that is not a property
of a token: it comes from a high-water mark held on the machine doing the
checking, so there is nothing to put in a file. Implement it from the README and
test it locally.

**Activation requests.** The set carries licenses *issued in answer to* a
request (`activation` and `machine` both set), because that is what a verifier
has to accept. The `act1` request blob itself is not here — it is signed by a
key the install mints and discards, so there is no stable artefact to publish.

**Anything stateful.** Usage ledgers and check logs are files the product
writes, not claims a license makes.

## Regenerating

`pnpm vectors`, from the repository root. It re-cuts the file and the suite
compares the result against what the current release signs, so an unchanged
release produces no diff. A diff means the issuer moved, and a published set
that no longer matches it is worse than none.

`fingerprint` at the top of `vectors.json` is the machine the bound vectors are
bound to. `machine` in the claims is `HMAC-SHA256(fingerprint, key = id)`,
base64url, so the fingerprint has to be published for those vectors to be
reproducible at all.
